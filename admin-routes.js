// admin-routes.js
// Admin endpoints to manage user roles in Firestore BY EMAIL (writes to users/<uid>).
// Requires:
//   - ./firebase-admin  -> exports { admin } (initialized Admin SDK instance)
//   - ./auth-rbac       -> exports { requireAuth, requireRole } OR { requireAuth, minRole }

'use strict';

const express = require('express');
const router = express.Router();

/* ========================= RBAC ========================= */
// Import the whole RBAC module to support both requireRole and minRole.
const rbac = require('./auth-rbac');

// Ensure requireAuth exists (your server uses it)
const requireAuth = rbac.requireAuth;

// Compatibility shim — if requireRole is not exported, map to minRole('admin')
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

/* ===================== Firebase Admin ==================== */
const { admin } = require('./firebase-admin'); // initialized Admin SDK

const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

// Allow "user" as the baseline role (alongside legacy "operator")
const ALLOWED_ROLES = ['admin', 'moderator', 'operator', 'user'];

/* -------------------- helpers -------------------- */
function normalizeRole(value) {
  const r = String(value || '')
    .trim()
    .toLowerCase();
  // Treat legacy "operator" as "user" if you wish to consolidate
  const mapped = r === 'operator' ? 'user' : r;
  if (!ALLOWED_ROLES.includes(mapped)) {
    throw new Error(
      'Invalid "role". Expected one of: admin, moderator, operator, user'
    );
  }
  return mapped;
}

function toEmailLower(email) {
  const v = String(email || '').trim();
  if (!v) throw new Error('email is required');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v))
    throw new Error('email is invalid');
  return v.toLowerCase();
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
    // Default to "user" as the baseline role
    role: String(data.role || 'user').toLowerCase(),
    updatedAt: data.updatedAt || null,
  };
}

/* ================= Additional helpers (NEW) ================= */
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
  const result = {
    ok: true,
    uid,
    deletedAuth: false,
    deletedUserDoc: false,
  };

  try {
    await admin.auth().deleteUser(uid);
    result.deletedAuth = true;
  } catch (err) {
    if (err && err.code !== 'auth/user-not-found') {
      throw err;
    }
  }

  try {
    await db.collection('users').doc(uid).delete();
    result.deletedUserDoc = true;
  } catch (_) {
    // ignore Firestore delete errors
  }

  return result;
}

/* -------------------- routes -------------------- */

/**
 * GET /api/admin/users
 * Signed-in users can list users OR look up by exact email.
 *
 * - If query `?email=user@example.com` provided:
 *    returns { ok: true, user: { ... } } with `user` null if not found
 * - Otherwise:
 *    returns { ok: true, items: [ { ... }, ... ] } (limited set)
 *
 * NOTE:
 * - Your original allowed any signed-in user; kept the same.
 * - If you want ONLY admins to use this route, switch middleware to requireRole(['admin']).
 */
router.get('/users', requireAuth, async (req, res) => {
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
      } catch (_err) {
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
});

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

    // Resolve UID from Auth; create user if not found
    let uid;
    try {
      const rec = await admin.auth().getUserByEmail(emailLower);
      uid = rec.uid;
    } catch (err) {
      if (err && err.code === 'auth/user-not-found') {
        const created = await admin.auth().createUser({ email: emailLower });
        uid = created.uid;
      } else {
        throw err;
      }
    }

    const payload = {
      email,
      emailLower,
      role,
      updatedAt: FieldValue.serverTimestamp(),
      ...(name ? { name } : {}),
    };

    const ref = db.collection('users').doc(uid);
    await ref.set(payload, { merge: true });

    // Re-read to return shaped data
    const docSnap = await ref.get();
    const user = shapeUserDoc(docSnap);

    return res.json({ ok: true, user });
  } catch (e) {
    return res
      .status(400)
      .json({ ok: false, error: e?.message || 'Failed to set role' });
  }
}

// Protect write endpoints — admin only
router.post('/users', requireAuth, requireRole(['admin']), upsertRoleHandler);
router.post(
  '/users/role',
  requireAuth,
  requireRole(['admin']),
  upsertRoleHandler
);

/* ========================= DELETE user (NEW) ========================= */
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
