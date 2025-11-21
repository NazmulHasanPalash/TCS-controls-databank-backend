'use strict';

const express = require('express');
const crypto = require('crypto');
const router = express.Router();

/* ========================= RBAC ========================= */
const rbac = require('./auth-rbac');

// Ensure requireAuth exists (your server uses it)
const requireAuth = rbac.requireAuth;

// Prefer requireRole; if missing, fallback to minRole('admin')
const requireRole =
  rbac.requireRole ||
  function fallbackRequireRole(roles) {
    const target = Array.isArray(roles) && roles.length ? roles[0] : 'admin';
    if (typeof rbac.minRole === 'function') return rbac.minRole(target);
    // If neither exists, warn (you should secure in prod)
    return (_req, _res, next) => {
      console.warn(
        '[RBAC WARN] requireRole/minRole not found; route not protected!'
      );
      next();
    };
  };

// Pull helper for role persistence (validates + busts cache)
const { setUserRole } = rbac;

/* ===================== Firebase Admin ==================== */
const { admin } = require('./firebase-admin'); // initialized Admin SDK

const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

/* ===================== Roles ===================== */
// Server truth — includes new roles (associate removed).
const ALLOWED_ROLES = [
  'new_register',
  'user',
  'operator',
  'moderator',
  'admin',

  // New “main” roles
  'sales',
  'production',
  'finance',
  'hr',
  'administrative',

  // New “onboarding” roles
  'new_sales',
  'new_production',
  'new_finance',
  'new_hr',
  'new_administrative',
];

/* -------------------- helpers -------------------- */
function normalizeRole(value) {
  const r = String(value || '')
    .trim()
    .toLowerCase();
  if (!ALLOWED_ROLES.includes(r)) {
    throw new Error(
      'Invalid "role". Expected one of: ' + ALLOWED_ROLES.join(', ')
    );
  }
  return r;
}

function toEmailLower(email) {
  const v = String(email || '').trim();
  if (!v) throw new Error('email is required');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v))
    throw new Error('email is invalid');
  return v.toLowerCase();
}

/**
 * Try to read the current caller's role from req.
 * Works with different shapes: req.user.role, customClaims, req.userRole, etc.
 */
function getCurrentRole(req) {
  if (!req) return null;
  const u = req.user || {};
  const fromUser =
    (u.customClaims && u.customClaims.role) ||
    (u.token && u.token.role) ||
    u.role;
  const fromReq = req.userRole || req.role;

  const val = fromUser || fromReq;
  return val ? String(val).toLowerCase() : null;
}

/**
 * Shape a DocumentSnapshot/QueryDocumentSnapshot into a plain user object.
 */
function shapeUserDoc(snap) {
  if (!snap) return null;
  if (
    Object.prototype.hasOwnProperty.call(snap, 'exists') &&
    snap.exists === false
  ) {
    return null;
  }

  const data = snap.data() || {};
  return {
    id: snap.id, // uid
    email: data.email || '',
    emailLower: data.emailLower || '',
    name: data.name || '',
    // Default to "new_register" if role missing (for fresh logins without a role set yet)
    role: String(data.role || 'new_register').toLowerCase(),
    updatedAt: data.updatedAt || null, // Firestore Timestamp or ms
  };
}

/* ================= Additional helpers ================= */
// Resolve uid by email (Auth); returns null if not found
async function resolveUidByEmail(emailLower) {
  try {
    const rec = await admin.auth().getUserByEmail(emailLower);
    return rec.uid;
  } catch (err) {
    if (err && err.code === 'auth/user-not-found') return null;
    throw err;
  }
}

// Delete user in Auth and Firestore (best-effort Firestore)
async function deleteUserByUid(uid) {
  const result = { ok: true, uid, deletedAuth: false, deletedUserDoc: false };

  try {
    await admin.auth().deleteUser(uid);
    result.deletedAuth = true;
  } catch (err) {
    if (!(err && err.code === 'auth/user-not-found')) throw err;
  }

  try {
    await db.collection('users').doc(uid).delete();
    result.deletedUserDoc = true;
  } catch {
    // ignore Firestore delete errors
  }

  return result;
}

/* -------------------- routes -------------------- */

/**
 * GET /api/admin/users
 * Admins & moderators can list users OR look up by exact email.
 *
 * - If query `?email=user@example.com` provided:
 *    returns { ok: true, user: { ... } } with `user` null if not found
 * - Otherwise:
 *    returns { ok: true, items: [ { ... }, ... ] } (limited set)
 */
router.get(
  '/users',
  requireAuth,
  requireRole(['admin', 'moderator']),
  async (req, res) => {
    try {
      const raw = (req.query && req.query.email) || '';
      const emailFilter = String(raw).trim();

      if (emailFilter) {
        const emailLower = toEmailLower(emailFilter);

        // Prefer resolving via Auth to get the UID, then read users/<uid>
        let docSnap = null;
        try {
          const userRecord = await admin.auth().getUserByEmail(emailLower);
          docSnap = await db.collection('users').doc(userRecord.uid).get();
        } catch {
          // If user is not in Auth, fall back to Firestore query by emailLower
          const q = await db
            .collection('users')
            .where('emailLower', '==', emailLower)
            .limit(1)
            .get();
          docSnap = q.empty ? null : q.docs[0];
        }

        const user = docSnap ? shapeUserDoc(docSnap) : null;
        return res.json({ ok: true, user });
      }

      // No filter: return a page of users (adjust limit/order as needed)
      const listSnap = await db.collection('users').limit(200).get();
      const items = listSnap.docs.map(shapeUserDoc).filter(Boolean);
      return res.json({ ok: true, items });
    } catch (e) {
      return res
        .status(400)
        .json({ ok: false, error: e?.message || 'Failed to fetch users' });
    }
  }
);

/* ============== Create/Update role by EMAIL (writes users/<uid>) ============== */

async function upsertRoleHandler(req, res) {
  try {
    if (!req.body || typeof req.body !== 'object') {
      return res
        .status(400)
        .json({ ok: false, error: 'Request body required (JSON)' });
    }

    const emailLower = toEmailLower(req.body?.email);
    const email = String(req.body.email).trim();
    const name = String(req.body?.name || '').trim();
    const role = normalizeRole(req.body?.role);

    // ---- Current caller role checks (admin vs moderator) ----
    const currentRole = getCurrentRole(req) || 'user';
    const isAdmin = currentRole === 'admin';
    const isModerator = currentRole === 'moderator';

    if (!isAdmin && !isModerator) {
      return res.status(403).json({
        ok: false,
        error: 'Only admin or moderator can set roles.',
      });
    }

    // Moderators CANNOT assign the "admin" role
    if (!isAdmin && role === 'admin') {
      return res.status(403).json({
        ok: false,
        error: 'Only an admin can assign the "admin" role.',
      });
    }

    // Resolve UID from Auth; create user if not found
    let uid;
    let resetLink = null;

    try {
      const rec = await admin.auth().getUserByEmail(emailLower);
      uid = rec.uid;
    } catch (err) {
      if (err && err.code === 'auth/user-not-found') {
        // Create with a strong temporary password so the account can sign in
        const tempPassword = crypto.randomUUID() + 'Aa1!';
        const created = await admin.auth().createUser({
          email: emailLower,
          displayName: name || undefined,
          password: tempPassword,
          emailVerified: false,
        });
        uid = created.uid;

        // Generate a password reset link so the user sets their own password
        try {
          resetLink = await admin.auth().generatePasswordResetLink(emailLower);
        } catch (e) {
          console.warn('generatePasswordResetLink failed:', e?.message || e);
        }
      } else {
        throw err;
      }
    }

    // 1) Persist role via RBAC helper (validates + busts cache)
    await setUserRole(uid, role);

    // 2) Mirror role to custom claims (optional but recommended)
    try {
      await admin.auth().setCustomUserClaims(uid, { role });
    } catch (e) {
      // Non-fatal; proceed even if custom claims fails
      console.warn('[RBAC] setCustomUserClaims failed:', e?.message || e);
    }

    // 3) Merge other fields into Firestore user doc
    const ref = db.collection('users').doc(uid);
    await ref.set(
      {
        email,
        emailLower,
        role, // keep role in document for listing UI
        name: name || (FieldValue.delete && FieldValue.delete()) || undefined,
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    // 4) Re-read to return shaped data (ensures we return what was saved)
    const docSnap = await ref.get();
    const user = shapeUserDoc(docSnap);

    const payload = { ok: true, user };
    if (resetLink) payload.resetLink = resetLink; // show in response (email it in production)
    return res.json(payload);
  } catch (e) {
    return res
      .status(400)
      .json({ ok: false, error: e?.message || 'Failed to set role' });
  }
}

// Writes: admin + moderator (but moderator cannot assign admin)
router.post(
  '/users',
  requireAuth,
  requireRole(['admin', 'moderator']),
  upsertRoleHandler
);
router.post(
  '/users/role',
  requireAuth,
  requireRole(['admin', 'moderator']),
  upsertRoleHandler
);

/* ========================= DELETE user ========================= */
/**
 * DELETE /api/admin/users/by-email
 * Body: { email: "user@example.com" }
 * Access: Admin only
 */
router.delete(
  '/users/by-email',
  requireAuth,
  requireRole(['admin']),
  async (req, res) => {
    try {
      const raw = req.body && req.body.email;
      if (!raw)
        return res.status(400).json({ ok: false, error: 'email is required' });

      const emailLower = toEmailLower(raw);

      // Prevent self-delete (avoid locking yourself out)
      const currentUid =
        (req.user && (req.user.uid || req.user.user_id)) || null;

      const targetUid = await resolveUidByEmail(emailLower);
      if (!targetUid) {
        return res
          .status(404)
          .json({ ok: false, error: 'User not found for provided email' });
      }
      if (currentUid && currentUid === targetUid) {
        return res.status(403).json({
          ok: false,
          error: 'Refusing to delete the currently authenticated admin user.',
        });
      }

      const result = await deleteUserByUid(targetUid);
      return res.json(result);
    } catch (err) {
      console.error('❌ Delete by email failed:', err);
      return res
        .status(500)
        .json({ ok: false, error: err.message || 'Delete failed' });
    }
  }
);

/**
 * DELETE /api/admin/users/:uid
 * Access: Admin only
 */
router.delete(
  '/users/:uid',
  requireAuth,
  requireRole(['admin']),
  async (req, res) => {
    const { uid } = req.params;
    if (!uid || typeof uid !== 'string' || uid.trim().length < 1) {
      return res
        .status(400)
        .json({ ok: false, error: 'Invalid or missing uid' });
    }

    // Prevent self-delete
    const currentUid = (req.user && (req.user.uid || req.user.user_id)) || null;
    if (currentUid && currentUid === uid) {
      return res.status(403).json({
        ok: false,
        error: 'Refusing to delete the currently authenticated admin user.',
      });
    }

    try {
      const result = await deleteUserByUid(uid);
      return res.json(result);
    } catch (err) {
      console.error('❌ Delete by uid failed:', err);
      return res
        .status(500)
        .json({ ok: false, error: err.message || 'Delete failed' });
    }
  }
);

module.exports = router;
