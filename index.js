'use strict';

/**
 * tcsdatabank-server (Local Disk + MySQL metadata/audit)
 * Public (no-login) endpoints for listing, creating folders/files, uploading,
 * downloading, zipping — and also RENAMING and DELETING (no auth).
 * Admin-only stuff stays under /api/admin via your adminRouter.
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const cookieParser = require('cookie-parser');
const { PassThrough } = require('stream');
const archiver = require('archiver');
const { randomUUID, createHash } = require('crypto');
const mysql = require('mysql2/promise');

// Admin router only (kept behind /api/admin)
const adminRouter = require('./admin-routes');

const app = express();
app.disable('x-powered-by'); // small hardening

/* -------------------- ENV -------------------- */
const {
  // Server
  PORT = 5000,
  CORS_ORIGINS,
  BODY_LIMIT = '2gb',
  FILE_SIZE_LIMIT = '2gb',
  FIELD_SIZE_LIMIT = '512mb',
  FILES_LIMIT = '1000',
  FIELDS_LIMIT = '5000',
  PARTS_LIMIT = '10000',
  // Cookies
  COOKIE_SECRET,

  // Storage (local disk)
  STORAGE_BASE,

  // DB
  DB_HOST,
  DB_PORT,
  DB_NAME,
  DB_USER,
  DB_PASS,
  DB_CONN_LIMIT = '10',
} = process.env;

if (!STORAGE_BASE) {
  console.error('❌ Missing STORAGE_BASE in .env (absolute path required)');
  process.exit(1);
}
if (!DB_HOST || !DB_NAME || !DB_USER || !DB_PASS) {
  console.error('❌ Missing DB_* env vars (DB_HOST/DB_NAME/DB_USER/DB_PASS)');
  process.exit(1);
}

/* -------------------- DB POOL -------------------- */
let DB_POOL;
function getPool() {
  if (!DB_POOL) {
    DB_POOL = mysql.createPool({
      host: DB_HOST,
      port: Number(DB_PORT),
      database: DB_NAME,
      user: DB_USER,
      password: DB_PASS,
      waitForConnections: true,
      connectionLimit: Number(DB_CONN_LIMIT),
      namedPlaceholders: true,
    });
  }
  return DB_POOL;
}

/* -------------------- HELPERS (sizes) -------------------- */
function parseSize(str) {
  if (typeof str === 'number') return str;
  const m = String(str || '')
    .trim()
    .toLowerCase()
    .match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb|tb)?$/);
  if (!m) return 25 * 1024 * 1024;
  const n = parseFloat(m[1]);
  const mul = { b: 1, kb: 1024, mb: 1024 ** 2, gb: 1024 ** 3, tb: 1024 ** 4 }[
    m[2] || 'b'
  ];
  return Math.floor(n * mul);
}

/* -------------------- MIDDLEWARE -------------------- */
app.set('trust proxy', 1);

app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);

app.use(cookieParser(COOKIE_SECRET || undefined));

// Allow very long uploads to run to completion
app.use((req, res, next) => {
  req.setTimeout(0);
  res.setTimeout(0);
  next();
});

// CORS allowlist (strings and /regex/)
const defaultOrigins = [/^http:\/\/localhost:\d+$/];
const parsedOrigins = (
  CORS_ORIGINS
    ? CORS_ORIGINS.split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : []
).map((v) => {
  if (v.startsWith('/') && v.endsWith('/')) {
    try {
      return new RegExp(v.slice(1, -1));
    } catch {
      return v;
    }
  }
  return v;
});
function isAllowedOrigin(origin) {
  if (!origin) return true;
  const allow = parsedOrigins.length ? parsedOrigins : defaultOrigins;
  for (const rule of allow) {
    if (rule instanceof RegExp && rule.test(origin)) return true;
    if (typeof rule === 'string' && rule === origin) return true;
  }
  return false;
}
app.use(
  cors({
    origin: (origin, cb) => {
      if (isAllowedOrigin(origin)) return cb(null, true);
      console.warn('CORS blocked:', origin);
      const err = new Error('CORS: origin not allowed');
      err.statusCode = 403;
      return cb(err);
    },
    credentials: true,
    exposedHeaders: ['Content-Disposition', 'Content-Length', 'X-Filename'],
  })
);

app.use(express.json({ limit: BODY_LIMIT }));
app.use(express.urlencoded({ limit: BODY_LIMIT, extended: true }));

app.use(morgan('dev'));

/* -------------------- MULTER (disk-backed + high limits) -------------------- */
const TMP_DIR =
  process.env.UPLOAD_TMP_DIR || path.join(os.tmpdir(), 'tcsdatabank-upload');
fs.mkdirSync(TMP_DIR, { recursive: true });

const diskStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, TMP_DIR),
  filename: (_req, file, cb) =>
    cb(
      null,
      `${Date.now()}-${Math.round(Math.random() * 1e9)}-${file.originalname}`
    ),
});

const COMMON_LIMITS = {
  fileSize: parseSize(FILE_SIZE_LIMIT),
  fieldSize: parseSize(FIELD_SIZE_LIMIT),
  files: Number(FILES_LIMIT),
  fields: Number(FIELDS_LIMIT),
  parts: Number(PARTS_LIMIT),
};

const uploadSingle = multer({
  storage: diskStorage,
  limits: COMMON_LIMITS,
}).single('file');

const uploadMulti = multer({
  storage: diskStorage,
  limits: COMMON_LIMITS,
}).array('files', COMMON_LIMITS.files);

/* -------------------- STORAGE (LOCAL DISK) HELPERS -------------------- */
const STORAGE_ROOT = path.resolve(STORAGE_BASE);
fs.mkdirSync(STORAGE_ROOT, { recursive: true });

function toVirtual(absPath) {
  const abs = path.resolve(absPath);
  if (!abs.startsWith(STORAGE_ROOT)) {
    throw new Error('Path not under STORAGE_BASE');
  }
  let rel = path.relative(STORAGE_ROOT, abs);
  rel = rel.split(path.sep).join('/'); // normalize
  return '/' + rel.replace(/^\/+/, '');
}

function safeJoinBase(virtualPath) {
  const v = String(virtualPath || '/').replace(/\\/g, '/');
  const clean = v.startsWith('/') ? v.slice(1) : v;
  const abs = path.resolve(STORAGE_ROOT, clean);
  if (!abs.startsWith(STORAGE_ROOT)) throw new Error('Invalid path');
  return abs;
}

function safeFileOrFolderName(raw) {
  const name = String(raw || '')
    .trim()
    .replace(/[\\/:*?"<>|]+/g, '-')
    .replace(/\s+/g, ' ')
    .replace(/^\.+$/, '');
  return name || '';
}

async function listDir(virtualPath) {
  const abs = safeJoinBase(virtualPath);
  const st = await fsp.stat(abs);
  if (!st.isDirectory()) throw new Error('Not a directory');
  const ents = await fsp.readdir(abs, { withFileTypes: true });
  const items = [];
  for (const ent of ents) {
    const child = path.join(abs, ent.name);
    const s = await fsp.stat(child);
    items.push({
      name: ent.name,
      size: s.isFile() ? s.size : null,
      isDirectory: s.isDirectory(),
      modifiedAt: s.mtime,
      rawModifiedAt: s.mtimeMs,
    });
  }
  return { path: toVirtual(abs), items };
}

async function ensureDir(virtualPath) {
  const abs = safeJoinBase(virtualPath);
  await fsp.mkdir(abs, { recursive: true });
  return abs;
}

async function statPathLocal(virtualPath) {
  const abs = safeJoinBase(virtualPath);
  try {
    const st = await fsp.stat(abs);
    return {
      exists: true,
      isDir: st.isDirectory(),
      size: st.isFile() ? st.size : 0,
      abs,
    };
  } catch {
    return { exists: false, isDir: false, size: 0, abs };
  }
}

async function removeRecursive(virtualPath) {
  const info = await statPathLocal(virtualPath);
  if (!info.exists) return { removedFiles: 0, removedDirs: 0, skipped: true };
  let files = 0,
    dirs = 0;

  async function walk(p) {
    const ents = await fsp.readdir(p, { withFileTypes: true }).catch(() => []);
    for (const ent of ents) {
      const child = path.join(p, ent.name);
      if (ent.isDirectory()) {
        await walk(child);
        await fsp.rmdir(child).catch(() => {});
        dirs++;
      } else {
        await fsp.unlink(child).catch(() => {});
        files++;
      }
    }
  }

  if (info.isDir) {
    await walk(info.abs);
    await fsp.rmdir(info.abs).catch(() => {});
    dirs++;
  } else {
    await fsp.unlink(info.abs);
    files++;
  }

  return { removedFiles: files, removedDirs: dirs, skipped: false };
}

async function renamePathLocal(
  fromVirtual,
  toVirtual,
  { overwrite = false } = {}
) {
  const fromAbs = safeJoinBase(fromVirtual);
  const toAbs = safeJoinBase(toVirtual);
  await fsp.mkdir(path.dirname(toAbs), { recursive: true });
  try {
    await fsp.access(toAbs);
    if (!overwrite) throw new Error('Target already exists');
    await removeRecursive(toVirtual);
  } catch {
    /* target missing ok */
  }
  await fsp.rename(fromAbs, toAbs);
  return { fromAbs, toAbs };
}

async function collectFilesRecursiveVirtual(virtualDir) {
  const rootAbs = safeJoinBase(virtualDir);
  const out = [];
  async function walk(abs) {
    const ents = await fsp
      .readdir(abs, { withFileTypes: true })
      .catch(() => []);
    for (const ent of ents) {
      const childAbs = path.join(abs, ent.name);
      if (ent.isDirectory()) await walk(childAbs);
      else out.push(toVirtual(childAbs));
    }
  }
  await walk(rootAbs);
  return out;
}

async function fileSizeOrFolderTotal(virtualPath) {
  const info = await statPathLocal(virtualPath);
  if (!info.exists) throw new Error('Not found');
  if (!info.isDir) {
    const st = await fsp.stat(info.abs);
    return { isDir: false, size: st.size };
  }
  let total = 0;
  async function walk(abs) {
    const ents = await fsp
      .readdir(abs, { withFileTypes: true })
      .catch(() => []);
    for (const ent of ents) {
      const child = path.join(abs, ent.name);
      if (ent.isDirectory()) await walk(child);
      else total += (await fsp.stat(child)).size;
    }
  }
  await walk(info.abs);
  return { isDir: true, size: total };
}

/* -------------------- DB HELPERS (audit + file index) -------------------- */
function pathHash(p) {
  return createHash('sha256')
    .update(String(p || '/'))
    .digest('hex');
}

async function audit({
  userId = null,
  ip,
  action,
  targetPath = '/',
  targetIsDir = false,
  bytes = null,
  status = 'ok',
  errorMsg = null,
  meta = null,
}) {
  const pool = getPool();
  await pool
    .execute(
      `INSERT INTO audit_events
     (user_id, ip, action, target_path, target_is_dir, bytes, status, error_msg, meta_json)
     VALUES (:user_id, INET6_ATON(:ip), :action, :target_path, :target_is_dir, :bytes, :status, :error_msg, :meta_json)`,
      {
        user_id: userId,
        ip: ip || null,
        action,
        target_path: targetPath,
        target_is_dir: targetIsDir ? 1 : 0,
        bytes: bytes == null ? null : Number(bytes),
        status,
        error_msg: errorMsg,
        meta_json: meta ? JSON.stringify(meta) : null,
      }
    )
    .catch(() => {
      // Fallback if INET6_ATON is unavailable
      return pool.execute(
        `INSERT INTO audit_events
       (user_id, ip, action, target_path, target_is_dir, bytes, status, error_msg, meta_json)
       VALUES (:user_id, NULL, :action, :target_path, :target_is_dir, :bytes, :status, :error_msg, :meta_json)`,
        {
          user_id: userId,
          action,
          target_path: targetPath,
          target_is_dir: targetIsDir ? 1 : 0,
          bytes: bytes == null ? null : Number(bytes),
          status,
          error_msg: errorMsg,
          meta_json: meta ? JSON.stringify(meta) : null,
        }
      );
    });
}

async function upsertFileEntry({
  path: vpath,
  isDir,
  sizeBytes = null,
  modifiedAt = null,
}) {
  const pool = getPool();
  await pool.execute(
    `INSERT INTO file_entries (path, path_hash, is_dir, size_bytes, modified_at)
     VALUES (:p, :h, :d, :s, :m)
     ON DUPLICATE KEY UPDATE
       is_dir=VALUES(is_dir),
       size_bytes=VALUES(size_bytes),
       modified_at=VALUES(modified_at),
       updated_at=CURRENT_TIMESTAMP`,
    {
      p: vpath,
      h: pathHash(vpath),
      d: isDir ? 1 : 0,
      s: sizeBytes,
      m: modifiedAt,
    }
  );
}

async function deleteFileEntryByPathPrefix(prefix) {
  const pool = getPool();
  await pool.execute(
    `DELETE FROM file_entries WHERE path_hash = :h OR path = :p`,
    { h: pathHash(prefix), p: prefix }
  );
  await pool.execute(`DELETE FROM file_entries WHERE path LIKE :pref`, {
    pref: prefix.endsWith('/') ? `${prefix}%` : `${prefix}/%`,
  });
}

async function renamePathPrefix(oldPrefix, newPrefix) {
  const pool = getPool();
  await pool.execute(
    `UPDATE file_entries SET path=:np, path_hash=:nh
     WHERE path_hash=:oh`,
    { np: newPrefix, nh: pathHash(newPrefix), oh: pathHash(oldPrefix) }
  );
  const oldLenPlus1 = oldPrefix.length + 1;
  await pool.execute(
    `UPDATE file_entries
       SET path = CONCAT(:np, SUBSTRING(path, :cut)),
           path_hash = SHA2(CONCAT(:np, SUBSTRING(path, :cut)), 256)
     WHERE path LIKE :oldChildren`,
    {
      np: newPrefix,
      cut: oldLenPlus1,
      oldChildren: oldPrefix.endsWith('/') ? `${oldPrefix}%` : `${oldPrefix}/%`,
    }
  );
}

/* -------------------- ROUTES -------------------- */

// Public health
app.get('/api/health', (_req, res) => res.json({ ok: true }));

/* ----- PUBLIC (no auth) ----- */

// List folder
app.get('/api/list', async (req, res) => {
  const folder = (req.query && req.query.path) || '/';
  try {
    const { path: vpath, items } = await listDir(folder);
    res.json({ ok: true, path: vpath, items });
    audit({ ip: req.ip, action: 'list', targetPath: vpath, targetIsDir: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
    audit({
      ip: req.ip,
      action: 'list',
      targetPath: folder,
      targetIsDir: true,
      status: 'error',
      errorMsg: e.message,
    });
  }
});

// Ensure/Create folder
app.post('/api/folder', async (req, res) => {
  const p = (req.body && req.body.path) || '/';
  try {
    const abs = await ensureDir(p);
    await upsertFileEntry({ path: toVirtual(abs), isDir: true });
    res.json({ ok: true, created: p });
    audit({
      ip: req.ip,
      action: 'create_folder',
      targetPath: p,
      targetIsDir: true,
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
    audit({
      ip: req.ip,
      action: 'create_folder',
      targetPath: p,
      targetIsDir: true,
      status: 'error',
      errorMsg: e.message,
    });
  }
});

// Create folder under parent by name
app.post('/api/folder/create', async (req, res) => {
  try {
    const parent = (req.body && req.body.parent) || '/';
    const name = safeFileOrFolderName(req.body && req.body.name);
    if (!name) throw new Error('Invalid "name" for folder.');
    const fullPathV = path.posix.join(parent, name);
    await ensureDir(fullPathV);
    await upsertFileEntry({ path: fullPathV, isDir: true });
    res.json({ ok: true, created: fullPathV, parent, name });
    audit({
      ip: req.ip,
      action: 'create_folder',
      targetPath: fullPathV,
      targetIsDir: true,
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Size (file or folder)
app.get('/api/size', async (req, res) => {
  try {
    const p = (req.query && req.query.path) || '/';
    const r = await fileSizeOrFolderTotal(p);
    res.json({ ok: true, isDirectory: r.isDir, size: r.size });
    audit({
      ip: req.ip,
      action: r.isDir ? 'folder_size' : 'size',
      targetPath: p,
      targetIsDir: r.isDir,
      bytes: r.size,
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Folder total size (alias)
app.get('/api/folder/size', async (req, res) => {
  try {
    const p = (req.query && req.query.path) || '/';
    const r = await fileSizeOrFolderTotal(p);
    res.json({ ok: true, size: r.size });
    audit({
      ip: req.ip,
      action: 'folder_size',
      targetPath: p,
      targetIsDir: true,
      bytes: r.size,
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Create a text file from content
app.post('/api/file', async (req, res) => {
  try {
    const dest = (req.body && req.body.dest) || '/';
    const name = safeFileOrFolderName(req.body && req.body.name);
    if (!name) throw new Error('Invalid "name".');
    const content =
      typeof (req.body && req.body.content) === 'string'
        ? req.body.content
        : '';

    const destAbs = safeJoinBase(dest);
    await fsp.mkdir(destAbs, { recursive: true });
    const fileAbs = path.join(destAbs, name);
    await fsp.writeFile(fileAbs, content, 'utf8');
    const st = await fsp.stat(fileAbs);

    await upsertFileEntry({
      path: toVirtual(fileAbs),
      isDir: false,
      sizeBytes: st.size,
      modifiedAt: st.mtime,
    });

    res.json({
      ok: true,
      created: toVirtual(fileAbs),
      bytes: Buffer.byteLength(content, 'utf8'),
    });
    audit({
      ip: req.ip,
      action: 'write_file',
      targetPath: toVirtual(fileAbs),
      targetIsDir: false,
      bytes: st.size,
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Read a file's content (utf8 or base64)
app.get('/api/file/content', async (req, res) => {
  try {
    if (!req.query || !req.query.path) throw new Error('Missing "path" query');
    const abs = safeJoinBase(req.query.path);
    const enc =
      req.query && req.query.encoding
        ? String(req.query.encoding).toLowerCase()
        : 'utf8';
    const buf = await fsp.readFile(abs);
    const st = await fsp.stat(abs);

    audit({
      ip: req.ip,
      action: 'read_file',
      targetPath: req.query.path,
      targetIsDir: false,
      bytes: st.size,
    });

    if (enc === 'base64') {
      res.json({
        ok: true,
        path: req.query.path,
        size: st.size,
        encoding: 'base64',
        content: buf.toString('base64'),
      });
    } else {
      res.json({
        ok: true,
        path: req.query.path,
        size: st.size,
        encoding: 'utf8',
        content: buf.toString('utf8'),
      });
    }
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

/* -------------------- UPLOADS -------------------- */

// Single file (path in body.path)
app.post('/api/upload', (req, res) => {
  uploadSingle(req, res, async (err) => {
    if (err) return res.status(400).json({ ok: false, error: err.message });
    let tmpPath;
    try {
      if (!req.file)
        throw new Error('No file uploaded. Field name must be "file".');
      tmpPath = req.file.path;
      const targetBase =
        req.body &&
        typeof req.body.path === 'string' &&
        req.body.path.trim().length
          ? req.body.path.trim()
          : '/';

      await ensureDir(targetBase);
      const destAbsDir = safeJoinBase(targetBase);
      const targetAbs = path.join(destAbsDir, req.file.originalname);

      await fsp.rename(tmpPath, targetAbs);
      const st = await fsp.stat(targetAbs);

      await upsertFileEntry({
        path: toVirtual(targetAbs),
        isDir: false,
        sizeBytes: st.size,
        modifiedAt: st.mtime,
      });

      res.json({
        ok: true,
        uploaded: {
          to: toVirtual(targetAbs),
          filename: req.file.originalname,
          bytes: st.size,
        },
      });

      audit({
        ip: req.ip,
        action: 'upload_file',
        targetPath: toVirtual(targetAbs),
        targetIsDir: false,
        bytes: st.size,
        meta: { filename: req.file.originalname },
      });
    } catch (e) {
      res.status(400).json({ ok: false, error: e.message });
    } finally {
      if (tmpPath) await fsp.unlink(tmpPath).catch(() => {});
    }
  });
});

/**
 * Upload an entire folder preserving EVERY subfolder and file.
 */
app.post('/api/upload-folder', (req, res) => {
  uploadMulti(req, res, async (err) => {
    try {
      if (err) {
        console.error('[MULTER ERROR]', {
          code: err.code,
          message: err.message,
          field: err.field,
        });
        throw new Error(err.message || 'Upload failed');
      }

      const files = Array.isArray(req.files) ? req.files : [];
      const hasAnyFiles = files.length > 0;

      // Normalize paths (string | array | missing)
      let relPaths = req.body?.paths ?? req.body?.relativePaths ?? null;

      if (relPaths == null) {
        relPaths = files.map((f) =>
          f.originalname && f.originalname.includes('/')
            ? f.originalname
            : f.webkitRelativePath || f.relativePath || f.originalname
        );
      } else if (typeof relPaths === 'string') {
        relPaths = [relPaths];
      } else if (!Array.isArray(relPaths)) {
        relPaths = files.map((f) => f.webkitRelativePath || f.originalname);
      }

      // Align counts (prevents mismatch)
      if (hasAnyFiles && relPaths.length !== files.length) {
        const aligned = new Array(files.length);
        for (let i = 0; i < files.length; i++) {
          aligned[i] =
            relPaths[i] ??
            files[i].webkitRelativePath ??
            files[i].relativePath ??
            files[i].originalname;
        }
        relPaths = aligned;
      }

      // Optional empty folders
      let rawDirs = req.body?.dirs ?? req.body?.directories ?? [];
      if (typeof rawDirs === 'string') rawDirs = [rawDirs];
      if (!Array.isArray(rawDirs)) rawDirs = [];
      if (!hasAnyFiles && rawDirs.length === 0) {
        throw new Error('No files or directories were provided.');
      }

      const destBase =
        req.body && req.body.dest && String(req.body.dest).trim().length
          ? String(req.body.dest).trim()
          : '/';
      await ensureDir(destBase);

      // Build dir set (parents first)
      const dirSet = new Set();

      // Parents from file paths
      for (let i = 0; i < relPaths.length; i++) {
        const rel = String(relPaths[i] || '')
          .replace(/^[\\/]+/, '')
          .replace(/\\/g, '/');
        const parent = path.posix.dirname(rel);
        if (parent && parent !== '.' && parent !== '/') {
          const parts = parent.split('/').filter(Boolean);
          let accum = '';
          for (const part of parts) {
            accum = accum ? `${accum}/${part}` : part;
            dirSet.add(accum);
          }
        }
      }
      // Explicit empty dirs (+ parents)
      for (const d of rawDirs) {
        const clean = String(d || '')
          .replace(/^[\\/]+/, '')
          .replace(/\\/g, '/');
        if (clean && clean !== '.' && clean !== '/') {
          const parts = clean.split('/').filter(Boolean);
          let accum = '';
          for (const part of parts) {
            accum = accum ? `${accum}/${part}` : part;
            dirSet.add(accum);
          }
        }
      }

      // 1) Create all directories (parents first)
      const createdDirs = [];
      const dirsSorted = Array.from(dirSet).sort((a, b) =>
        a.localeCompare(b, undefined, { sensitivity: 'base' })
      );
      for (const relDir of dirsSorted) {
        const vDir = path.posix.join(destBase, relDir);
        await ensureDir(vDir);
        createdDirs.push(vDir);
        await upsertFileEntry({ path: vDir, isDir: true });
      }

      // 2) Upload files preserving structure
      const uploaded = [];
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        const rel = path.posix.normalize(
          String(relPaths[i] || f.originalname)
            .replace(/^[\\/]+/, '')
            .replace(/\\/g, '/')
        );
        const destVPath = path.posix.join(destBase, rel);
        const destAbs = safeJoinBase(destVPath);
        await fsp.mkdir(path.dirname(destAbs), { recursive: true });
        await fsp.rename(f.path, destAbs);
        const st = await fsp.stat(destAbs);
        uploaded.push({
          to: destVPath,
          filename: f.originalname,
          bytes: st.size,
        });
        await upsertFileEntry({
          path: destVPath,
          isDir: false,
          sizeBytes: st.size,
          modifiedAt: st.mtime,
        });
      }

      console.log('[UPLOAD-FOLDER OK]', {
        base: destBase,
        files: files.length,
        createdDirs: dirSet.size,
      });

      audit({
        ip: req.ip,
        action: 'upload_folder',
        targetPath: destBase,
        targetIsDir: true,
        bytes: uploaded.reduce((a, b) => a + (b.bytes || 0), 0),
        meta: { count: uploaded.length },
      });

      return res.json({
        ok: true,
        base: destBase,
        count: uploaded.length,
        uploaded,
        createdDirs,
      });
    } catch (e) {
      return res
        .status(400)
        .json({ ok: false, error: e?.message || 'Upload failed' });
    } finally {
      // Cleanup tmp files from disk
      await Promise.allSettled(
        (req.files || [])
          .map((f) => f?.path)
          .filter(Boolean)
          .map((p) => fsp.unlink(p).catch(() => {}))
      );
    }
  });
});

/* -------------------- DOWNLOAD -------------------- */
app.get('/api/download', async (req, res) => {
  try {
    const vpath = (req.query && req.query.path) || '/';
    const abs = safeJoinBase(vpath);
    const filename = path.posix.basename(vpath);

    const st = await fsp.stat(abs);
    if (!st.isFile()) throw new Error('Not a file');

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader(
      'Content-Disposition',
      "attachment; filename*=UTF-8''" + encodeURIComponent(filename)
    );
    res.setHeader('X-Filename', filename);
    res.setHeader('Cache-Control', 'no-store');

    audit({
      ip: req.ip,
      action: 'download',
      targetPath: vpath,
      targetIsDir: false,
      bytes: st.size,
    });

    fs.createReadStream(abs)
      .on('error', () => {
        try {
          res.end();
        } catch {}
      })
      .pipe(res);
  } catch (e) {
    if (!res.headersSent) res.status(400).json({ ok: false, error: e.message });
    else {
      try {
        res.end();
      } catch {}
    }
  }
});

/* -------------------- ZIP (one folder) -------------------- */
const pendingZips = new Map();

app.post('/api/zip', async (req, res) => {
  try {
    const body = req.body || {};
    if (!body.path)
      return res.status(400).json({ ok: false, error: 'Missing "path"' });
    const folderVPath = body.path;

    const info = await statPathLocal(folderVPath);
    if (!info.exists || !info.isDir) {
      return res.status(400).json({
        ok: false,
        error: 'Folder not found or is not a directory',
      });
    }

    if (pendingZips.size > 500) {
      return res
        .status(429)
        .json({ ok: false, error: 'Too many pending ZIP jobs' });
    }

    const folderName =
      safeFileOrFolderName(path.posix.basename(folderVPath)) || 'folder';
    const zipName = `${folderName}.zip`;
    const id = randomUUID();
    pendingZips.set(id, {
      folderVPath,
      filename: zipName,
      createdAt: Date.now(),
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true, downloadId: id, filename: zipName });

    audit({
      ip: req.ip,
      action: 'zip_start',
      targetPath: folderVPath,
      targetIsDir: true,
      meta: { downloadId: id, filename: zipName },
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.get('/api/zip/:id', async (req, res) => {
  const job = pendingZips.get(req.params.id);
  if (!job) return res.status(404).end('Not found');

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader(
    'Content-Disposition',
    "attachment; filename*=UTF-8''" + encodeURIComponent(job.filename)
  );
  res.setHeader('X-Filename', job.filename);
  res.setHeader('Cache-Control', 'no-store');

  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.on('warning', (err) => console.warn('archiver warning', err));
  archive.on('error', (err) => {
    console.error('archiver error', err);
    if (!res.headersSent) res.status(500).end('ZIP error');
    else res.end();
  });
  archive.on('end', async () => {
    pendingZips.delete(req.params.id);
    await audit({
      ip: req.ip,
      action: 'zip_complete',
      targetPath: job.folderVPath,
      targetIsDir: true,
      meta: { downloadId: req.params.id },
    });
  });
  archive.pipe(res);

  try {
    const top =
      safeFileOrFolderName(path.posix.basename(job.folderVPath)) || 'folder';
    const children = await collectFilesRecursiveVirtual(job.folderVPath);
    children.sort((a, b) =>
      a.localeCompare(b, undefined, { sensitivity: 'base' })
    );
    for (const v of children) {
      const abs = safeJoinBase(v);
      const rel = v.slice(job.folderVPath.length + 1);
      const nameInZip = path.posix.join(top, rel);
      archive.file(abs, { name: nameInZip });
    }
    archive.finalize();
  } catch (e) {
    try {
      archive.abort();
    } catch {}
    if (!res.headersSent) res.status(500).end('ZIP build error');
  }
});

/* -------------------- ZIP (multi) -------------------- */
const pendingMultiZips = new Map();

function uniqueNameResolver() {
  const used = new Set();
  return (name) => {
    if (!used.has(name)) {
      used.add(name);
      return name;
    }
    const dir = path.posix.dirname(name);
    const base = path.posix.basename(name);
    const ext = path.posix.extname(base);
    const stem = ext ? base.slice(0, -ext.length) : base;
    let i = 1,
      candidate;
    do {
      candidate = (dir === '.' ? '' : dir + '/') + `${stem} (${i})${ext}`;
      i++;
    } while (used.has(candidate));
    used.add(candidate);
    return candidate;
  };
}

app.post('/api/zip-multi', async (req, res) => {
  try {
    const body = req.body || {};
    const rawItems = Array.isArray(body.items) ? body.items : [];
    if (!rawItems.length)
      return res.status(400).json({ ok: false, error: 'No items' });

    const normalized = rawItems.map((it) => ({
      path: String(it?.path || '/'),
      type: String(it?.type || 'file').toLowerCase(),
    }));

    let zipName = safeFileOrFolderName((body.zipName || '').trim());
    if (!zipName) {
      const onlyFolders = normalized.filter((i) =>
        ['folder', 'directory', 'dir'].includes(i.type)
      );
      zipName =
        onlyFolders.length === 1 && normalized.length === 1
          ? `${
              safeFileOrFolderName(path.posix.basename(onlyFolders[0].path)) ||
              'folder'
            }.zip`
          : 'selection.zip';
    }
    if (!zipName.toLowerCase().endsWith('.zip')) zipName += '.zip';

    if (pendingMultiZips.size > 500) {
      return res
        .status(429)
        .json({ ok: false, error: 'Too many pending ZIP jobs' });
    }

    const id = randomUUID();
    pendingMultiZips.set(id, {
      items: normalized,
      filename: zipName,
      createdAt: Date.now(),
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true, downloadId: id, filename: zipName });
    audit({
      ip: req.ip,
      action: 'zip_start',
      targetPath: '(multi)',
      targetIsDir: true,
      meta: { downloadId: id, filename: zipName },
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.get('/api/zip-multi/:id', async (req, res) => {
  const job = pendingMultiZips.get(req.params.id);
  if (!job) return res.status(404).end('Not found');

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader(
    'Content-Disposition',
    "attachment; filename*=UTF-8''" + encodeURIComponent(job.filename)
  );
  res.setHeader('X-Filename', job.filename);
  res.setHeader('Cache-Control', 'no-store');

  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.on('warning', (err) => console.warn('archiver warning', err));
  archive.on('error', (err) => {
    console.error('archiver error', err);
    if (!res.headersSent) res.status(500).end('ZIP error');
    else res.end();
  });
  archive.on('end', () => pendingMultiZips.delete(req.params.id));
  archive.pipe(res);

  try {
    const ensureUnique = uniqueNameResolver();
    const entries = [];
    for (const it of job.items) {
      const isFolder = ['folder', 'directory', 'dir'].includes(it.type);
      if (isFolder) {
        const top =
          safeFileOrFolderName(path.posix.basename(it.path)) || 'folder';
        const children = await collectFilesRecursiveVirtual(it.path);
        children.sort((a, b) =>
          a.localeCompare(b, undefined, { sensitivity: 'base' })
        );
        for (const v of children) {
          const rel = v.slice(it.path.length + 1);
          const desired = path.posix.join(top, rel);
          entries.push({ v, nameInZip: desired });
        }
      } else {
        entries.push({ v: it.path, nameInZip: path.posix.basename(it.path) });
      }
    }
    const fixed = entries.map((e) => ({
      ...e,
      nameInZip: ensureUnique(e.nameInZip),
    }));
    for (const e of fixed) {
      const abs = safeJoinBase(e.v);
      archive.file(abs, { name: e.nameInZip });
    }
    await archive.finalize();
  } catch (e) {
    try {
      archive.abort();
    } catch {}
    if (!res.headersSent) res.status(500).end('ZIP build error');
  }
});

/* -------------------- RENAME & DELETE (PUBLIC) -------------------- */

// FOLDER RENAME (public)
app.put('/api/folder', async (req, res) => {
  try {
    const rawFrom = req.body && req.body.from;
    const rawTo = req.body && req.body.to;
    if (!rawFrom || !rawTo) throw new Error('Provide both "from" and "to".');

    const info = await statPathLocal(rawFrom);
    if (!info.exists || !info.isDir)
      throw new Error('Source folder does not exist.');

    await renamePathLocal(rawFrom, rawTo, {
      overwrite: String(req.body?.overwrite).toLowerCase() === 'true',
    });

    await renamePathPrefix(rawFrom, rawTo);

    res.json({ ok: true, from: rawFrom, to: rawTo });
    audit({
      ip: req.ip,
      action: 'rename_folder',
      targetPath: rawTo,
      targetIsDir: true,
      meta: { from: rawFrom, overwrite: !!req.body?.overwrite },
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || 'Rename failed' });
  }
});

// FILE RENAME (public)
app.post('/api/file/rename', async (req, res) => {
  try {
    const hasFromTo =
      typeof (req.body && req.body.from) === 'string' &&
      typeof (req.body && req.body.to) === 'string';
    const hasFromNew =
      typeof (req.body && req.body.from) === 'string' &&
      typeof (req.body && req.body.newName) === 'string';
    if (!hasFromTo && !hasFromNew)
      throw new Error('Provide {from,to} or {from,newName}.');

    const from = req.body.from;
    let to;
    if (hasFromTo) {
      to = req.body.to;
    } else {
      const dir = path.posix.dirname(from);
      const newName = safeFileOrFolderName(req.body.newName);
      if (!newName) throw new Error('Invalid newName');
      to = path.posix.join(dir, newName);
    }

    const info = await statPathLocal(from);
    if (!info.exists || info.isDir)
      throw new Error('Source file does not exist or is a directory.');

    await renamePathLocal(from, to, {
      overwrite: String(req.body?.overwrite).toLowerCase() === 'true',
    });

    await renamePathPrefix(from, to);

    res.json({ ok: true, from, to });
    audit({
      ip: req.ip,
      action: 'rename_file',
      targetPath: to,
      targetIsDir: false,
      meta: { from, overwrite: !!req.body?.overwrite },
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || 'Rename failed' });
  }
});

// DELETE (file or folder) — public
async function deleteHandler(req, res) {
  try {
    const raw = (req.query && req.query.path) || (req.body && req.body.path);
    if (!raw) throw new Error('Missing "path"');

    const info = await statPathLocal(raw);
    if (!info.exists) throw new Error('Not found');

    const out = await removeRecursive(raw);
    await deleteFileEntryByPathPrefix(raw);

    res.json({ ok: true, path: raw, isDirectory: info.isDir, ...out });
    audit({
      ip: req.ip,
      action: info.isDir ? 'delete_folder' : 'delete_file',
      targetPath: raw,
      targetIsDir: info.isDir,
      meta: { removedFiles: out.removedFiles, removedDirs: out.removedDirs },
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || 'Delete failed' });
  }
}
app.delete('/api/delete', deleteHandler);
app.post('/api/delete', deleteHandler);
app.delete('/api/file', deleteHandler);
app.delete('/api/folder', deleteHandler);

/* -------------------- ADMIN (kept behind your router) -------------------- */
app.use('/api/admin', adminRouter);

/* -------------------- HOUSEKEEPING -------------------- */
const ZIP_TTL_MS = 30 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [id, job] of pendingZips.entries())
    if (now - job.createdAt > ZIP_TTL_MS) pendingZips.delete(id);
  for (const [id, job] of pendingMultiZips.entries())
    if (now - job.createdAt > ZIP_TTL_MS) pendingMultiZips.delete(id);
}, 5 * 60 * 1000);

/* -------------------- BODY PARSE / GENERAL ERROR GUARD -------------------- */
app.use((err, _req, res, next) => {
  if (err?.type === 'entity.parse.failed' || err instanceof SyntaxError) {
    return res.status(400).json({ ok: false, error: 'Invalid JSON body' });
  }
  if (err) {
    const code = err.statusCode || 500;
    return res
      .status(code)
      .json({ ok: false, error: err.message || 'Server error' });
  }
  next();
});

/* -------------------- 404 -------------------- */
app.use((_req, res) => res.status(404).json({ ok: false, error: 'Not found' }));

process.on('unhandledRejection', (r) =>
  console.error('UnhandledRejection:', r)
);
process.on('uncaughtException', (e) => console.error('UncaughtException:', e));

/* -------------------- START -------------------- */
app.listen(Number(PORT), () => {
  console.log(`tcsdatabank-server running on http://localhost:${PORT}`);
});
