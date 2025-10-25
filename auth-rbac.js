// auth-rbac.js
// Role-based access control middleware for Express using Firebase Auth + Firestore.
//
// Exports:
//   - requireAuth(req,res,next)
//   - requireRole(allowedRoles)(req,res,next)
//   - minRole(minRoleName)(req,res,next)         // use minRole('user') for the lowest gate (aka “normal user”)
//   - setUserRole(uid, role)
//   - getUserRole(uid)
//   - ROLE_ORDER
//
// Firestore schema (server-side via Admin SDK):
//   Collection: users
//   Doc ID: <uid>
//   Fields:
//     role: "admin" | "moderator" | "operator" | "user"
//     updatedAt: <number ms since epoch>
//
// Notes:
//   * If no user doc exists or role is missing, user defaults to the lowest level (“user”).
//   * Role values are normalized to lowercase.
//   * For backward compatibility, "operator" is treated the same as "user" (lowest level).
//   * This module depends only on firebase-admin.

'use strict';

const { admin } = require('./firebase-admin'); // ✅ MUST match your firebase-admin.js export
const db = admin.firestore();

/** Display order (for reference only). */
const ROLE_ORDER = ['user', 'operator', 'moderator', 'admin'];

/** Internal comparable levels — "user" and "operator" are equivalent (lowest). */
const ROLE_LEVEL = {
  user: 0,
  operator: 0, // ← compatibility alias for lowest level
  moderator: 1,
  admin: 2,
};

// Small in-memory cache to reduce Firestore reads
const roleCache = new Map(); // key: uid → { role, ts }
const ROLE_TTL_MS = 60 * 1000; // 1 minute

/* -------------------------------- Utilities -------------------------------- */
const now = () => Date.now();

function normalizeRole(value) {
  return String(value || '')
    .trim()
    .toLowerCase();
}

function isAllowedRole(role) {
  return Object.prototype.hasOwnProperty.call(ROLE_LEVEL, role);
}

function getRoleLevel(role) {
  const r = normalizeRole(role);
  return isAllowedRole(r) ? ROLE_LEVEL[r] : ROLE_LEVEL.user;
}

function fromCache(uid) {
  const hit = roleCache.get(uid);
  if (!hit) return null;
  if (now() - hit.ts > ROLE_TTL_MS) {
    roleCache.delete(uid);
    return null;
  }
  return hit.role;
}

function setCache(uid, role) {
  roleCache.set(uid, { role, ts: now() });
}

/** Extract Bearer token from Authorization header or __session cookie. */
function extractIdToken(req) {
  const authHeader = req.headers?.authorization;
  if (authHeader && typeof authHeader === 'string') {
    const m = authHeader.match(/^Bearer\s+(.+)$/i);
    if (m) return m[1];
  }
  // Optional cookie fallback (if you set it on the client)
  if (req.cookies && typeof req.cookies.__session === 'string') {
    return req.cookies.__session;
  }
  return null;
}

/* -------------------------- Auth & Role Middlewares ------------------------- */

/** requireAuth — verifies Firebase ID token; attaches req.user = { uid, email } */
async function requireAuth(req, res, next) {
  try {
    if (req.method === 'OPTIONS') return next(); // allow CORS preflight

    const idToken = extractIdToken(req);
    if (!idToken) {
      return res.status(401).json({ ok: false, error: 'Missing Bearer token' });
    }

    // Verify token with Admin SDK
    const decoded = await admin.auth().verifyIdToken(idToken, true);
    req.user = { uid: decoded.uid, email: decoded.email || null };

    return next();
  } catch (_err) {
    // Avoid leaking details
    return res
      .status(401)
      .json({ ok: false, error: 'Invalid or expired token' });
  }
}

/** getUserRole — reads role from Firestore (cached). Defaults to "user". */
async function getUserRole(uid) {
  if (!uid || typeof uid !== 'string') return 'user';

  const cached = fromCache(uid);
  if (cached) return cached;

  const snap = await db.collection('users').doc(uid).get();
  const roleRaw = snap.exists ? snap.data().role : null;

  // Default to lowest level; accept both "user" and legacy "operator"
  let role = normalizeRole(roleRaw || 'user');
  if (!isAllowedRole(role)) role = 'user';

  setCache(uid, role);
  return role;
}

/** requireRole([...roles]) — only allows if user role is exactly one of the list. */
function requireRole(allowedRoles = []) {
  const allowedList = (
    Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles]
  )
    .filter(Boolean)
    .map(normalizeRole)
    .filter(isAllowedRole);

  return async (req, res, next) => {
    try {
      if (!req.user?.uid) {
        return res.status(401).json({ ok: false, error: 'Unauthenticated' });
      }
      const role = await getUserRole(req.user.uid);
      req.user.role = role;

      if (!allowedList.includes(role)) {
        return res
          .status(403)
          .json({ ok: false, error: 'Forbidden: insufficient role' });
      }
      return next();
    } catch (_err) {
      return res.status(500).json({ ok: false, error: 'Role check failed' });
    }
  };
}

/**
 * minRole('user') → allows user/operator, moderator, admin (>=).
 * minRole('moderator') → allows moderator, admin.
 * minRole('admin') → allows admin only.
 */
function minRole(min) {
  const minNormalized = normalizeRole(min);
  if (!isAllowedRole(minNormalized)) {
    throw new Error(`minRole(): invalid role "${min}"`);
  }
  const minLevel = getRoleLevel(minNormalized);

  return async (req, res, next) => {
    try {
      if (!req.user?.uid) {
        return res.status(401).json({ ok: false, error: 'Unauthenticated' });
      }
      const role = await getUserRole(req.user.uid);
      req.user.role = role;

      const ok = getRoleLevel(role) >= minLevel;
      if (!ok) {
        return res
          .status(403)
          .json({ ok: false, error: 'Forbidden: insufficient role' });
      }
      return next();
    } catch (_err) {
      return res.status(500).json({ ok: false, error: 'Role check failed' });
    }
  };
}

/** setUserRole(uid, role) — assigns new role + timestamp, validates input. */
async function setUserRole(uid, role) {
  const normalized = normalizeRole(role);
  if (!isAllowedRole(normalized)) {
    throw new Error(
      'Invalid role ("admin", "moderator", "operator", or "user")'
    );
  }
  if (!uid || typeof uid !== 'string') {
    throw new Error('Invalid uid');
  }

  await db
    .collection('users')
    .doc(uid)
    .set({ role: normalized, updatedAt: Date.now() }, { merge: true });

  roleCache.delete(uid); // bust cache
  return { uid, role: normalized };
}

/* ---------------------------------- Exports --------------------------------- */
module.exports = {
  requireAuth,
  requireRole,
  minRole, // use as minRole('user') where you want the normal-user gate
  setUserRole,
  getUserRole,
  ROLE_ORDER,
};
