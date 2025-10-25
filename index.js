/**
 * tcsdatabank-server (FTP-backed, high limits)
 * Public (no-login) endpoints for listing, creating folders/files, uploading,
 * downloading, zipping — and now also RENAMING and DELETING (no auth).
 * Admin-only stuff stays under /api/admin via your adminRouter.
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const multer = require('multer');
const ftp = require('basic-ftp');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const os = require('os');
const { Readable, PassThrough } = require('stream');
const archiver = require('archiver');
const { randomUUID } = require('crypto');

// Admin router only (kept behind /api/admin)
const adminRouter = require('./admin-routes');

const app = express();
app.disable('x-powered-by'); // small hardening

/* -------------------- ENV -------------------- */
const {
  // FTP
  FTP_HOST,
  FTP_PORT = 21,
  FTP_USER,
  FTP_PASS,
  FTP_SECURE = 'true',
  FTP_SECURE_REJECT_UNAUTHORIZED = 'false',
  FTP_BASE = '/',

  // Server
  PORT = 5000,
  CORS_ORIGINS,
  BODY_LIMIT = '500mb', // for JSON & urlencoded bodies
  FILE_SIZE_LIMIT = '500mb', // per-file limit (multer)
  FIELD_SIZE_LIMIT = '200mb', // per-field size in multipart
  FILES_LIMIT = '50', // max number of files in multipart
  FIELDS_LIMIT = '1000', // max number of non-file fields
  PARTS_LIMIT = '2000', // max number of parts (files+fields)
} = process.env;

if (!FTP_HOST || !FTP_USER || !FTP_PASS) {
  console.error('❌ Missing FTP_HOST/FTP_USER/FTP_PASS in .env');
  process.exit(1);
}

/* -------------------- HELPERS (sizes, paths) -------------------- */
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
// Optional: enable if behind a proxy (nginx/ingress)
app.set('trust proxy', 1);

app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);

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

// Body parsers with huge limits
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

/* -------------------- FTP HELPERS -------------------- */
const FTP_BASE_NORM = path.posix.normalize(FTP_BASE || '/');

function safeJoinBase(userPath) {
  const input =
    typeof userPath === 'string' && userPath.trim() ? userPath.trim() : '/';
  const normalized = path.posix.normalize(input);
  if (normalized.startsWith(FTP_BASE_NORM)) return normalized;
  const joined = path.posix.normalize(
    path.posix.join(FTP_BASE_NORM, normalized.replace(/^\/+/, ''))
  );
  if (!joined.startsWith(FTP_BASE_NORM))
    throw new Error('Invalid path: outside FTP_BASE');
  return joined;
}
function safeJoinUnder(base, rel) {
  const cleaned = String(rel || '')
    .replace(/^[\\/]+/, '')
    .replace(/\\/g, '/');
  const candidate = path.posix.normalize(path.posix.join(base, cleaned));
  if (
    candidate !== base &&
    !candidate.startsWith(base.endsWith('/') ? base : base + '/')
  ) {
    throw new Error('Invalid relative path (outside base)');
  }
  return candidate;
}
function safeFileOrFolderName(raw) {
  const name = String(raw || '')
    .trim()
    .replace(/[\\/:*?"<>|]+/g, '-')
    .replace(/\s+/g, ' ')
    .replace(/^\.+$/, '');
  return name || '';
}

async function getClient() {
  // read from env, default 10 minutes
  const FTP_TIMEOUT_MS = Number(process.env.FTP_TIMEOUT_MS || 600000);
  const client = new ftp.Client(FTP_TIMEOUT_MS);
  client.ftp.verbose = false;
  try {
    await client.access({
      host: FTP_HOST,
      port: Number(FTP_PORT),
      user: FTP_USER,
      password: FTP_PASS,
      secure: String(FTP_SECURE).toLowerCase() === 'true',
      secureOptions:
        String(FTP_SECURE).toLowerCase() === 'true'
          ? {
              rejectUnauthorized:
                String(FTP_SECURE_REJECT_UNAUTHORIZED).toLowerCase() === 'true',
            }
          : undefined,
    });
    await client.cd(FTP_BASE_NORM);
    return client;
  } catch (err) {
    client.close();
    throw err;
  }
}
async function withClient(fn) {
  const client = await getClient();
  try {
    return await fn(client);
  } finally {
    client.close();
  }
}
function mapFtpList(items) {
  return (items || []).map((it) => {
    const isDir =
      typeof it.isDirectory === 'boolean'
        ? it.isDirectory
        : it.type === 2 || it.type === 'd' || it.type === 'directory';
    const modifiedAt = it.modifiedAt || it.date || null;
    return {
      name: it.name,
      size: typeof it.size === 'number' ? it.size : null,
      isDirectory: !!isDir,
      modifiedAt,
      rawModifiedAt: it.rawModifiedAt || null,
    };
  });
}
async function collectFilesRecursive(client, dirPath) {
  const out = [];
  async function walk(p) {
    let list;
    try {
      list = await client.list(p);
    } catch {
      return;
    }
    for (const ent of list) {
      const isDir =
        typeof ent.isDirectory === 'boolean'
          ? ent.isDirectory
          : ent.type === 2 || ent.type === 'd' || ent.type === 'directory';
      const child = path.posix.join(p, ent.name);
      if (isDir) await walk(child);
      else out.push(child);
    }
  }
  await walk(dirPath);
  return out;
}
async function getSizeRecursive(client, p) {
  let listing;
  try {
    listing = await client.list(p);
  } catch {
    return 0;
  }
  let total = 0;
  for (const ent of listing) {
    const isDir =
      typeof ent.isDirectory === 'boolean'
        ? ent.isDirectory
        : ent.type === 2 || ent.type === 'd' || ent.type === 'directory';
    const child = path.posix.join(p, ent.name);
    if (isDir) total += await getSizeRecursive(client, child);
    else if (typeof ent.size === 'number') total += ent.size;
  }
  return total;
}
function uniqueNameResolver() {
  const used = new Set();
  return (fullPathInZip) => {
    if (!used.has(fullPathInZip)) {
      used.add(fullPathInZip);
      return fullPathInZip;
    }
    const dir = path.posix.dirname(fullPathInZip);
    const base = path.posix.basename(fullPathInZip);
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

/* -------- DELETE & RENAME HELPERS (robust) -------- */

async function statPath(client, p) {
  const parent = path.posix.dirname(p);
  const base = path.posix.basename(p);
  let list;
  try {
    list = await client.list(parent);
  } catch {
    return { exists: false, isDir: false, size: 0 };
  }
  const entry = list.find((e) => e.name === base);
  if (!entry) return { exists: false, isDir: false, size: 0 };
  const isDir =
    typeof entry.isDirectory === 'boolean'
      ? entry.isDirectory
      : entry.type === 2 || entry.type === 'd' || entry.type === 'directory';
  return {
    exists: true,
    isDir,
    size: typeof entry.size === 'number' ? entry.size : 0,
  };
}

async function ensureParent(client, p) {
  const parent = path.posix.dirname(p);
  await client.ensureDir(parent);
}

async function removeRecursive(client, p) {
  const info = await statPath(client, p);
  if (!info.exists) return { removedFiles: 0, removedDirs: 0, skipped: true };
  if (!info.isDir) {
    await client.remove(p);
    return { removedFiles: 1, removedDirs: 0, skipped: false };
  }
  let files = 0;
  let dirs = 0;
  let list = [];
  try {
    list = await client.list(p);
  } catch {
    list = [];
  }
  for (const ent of list) {
    const isDir =
      typeof ent.isDirectory === 'boolean'
        ? ent.isDirectory
        : ent.type === 2 || ent.type === 'd' || ent.type === 'directory';
    const child = path.posix.join(p, ent.name);
    if (isDir) {
      const r = await removeRecursive(client, child);
      files += r.removedFiles;
      dirs += r.removedDirs;
    } else {
      await client.remove(child);
      files += 1;
    }
  }
  if (typeof client.removeDir === 'function') await client.removeDir(p);
  else if (typeof client.removeEmptyDir === 'function')
    await client.removeEmptyDir(p);
  else await client.send('RMD ' + p);
  dirs += 1;

  return { removedFiles: files, removedDirs: dirs, skipped: false };
}

async function safeRename(client, from, to, { overwrite = false } = {}) {
  if (from === to) return { ok: true, from, to, noop: true };

  await ensureParent(client, to);

  const toParent = path.posix.dirname(to);
  const toBase = path.posix.basename(to);
  let toExists = false;
  try {
    const parentList = await client.list(toParent);
    toExists = !!parentList.find((e) => e.name === toBase);
  } catch {}
  if (toExists) {
    if (!overwrite) {
      throw new Error(
        'Target already exists. Provide a different "to" path or enable overwrite.'
      );
    }
    await removeRecursive(client, to);
  }

  await client.rename(from, to);
  return { ok: true, from, to, noop: false };
}

/* -------------------- ROUTES -------------------- */

// Public health
app.get('/api/health', (_req, res) => res.json({ ok: true }));

/* ----- PUBLIC (no auth) for ALL non-admin operations, including rename & delete ----- */

// List folder
app.get('/api/list', async (req, res) => {
  try {
    const folder = safeJoinBase((req.query && req.query.path) || '/');
    const items = await withClient(async (client) => {
      await client.cd(folder);
      return mapFtpList(await client.list());
    });
    res.json({ ok: true, path: folder, items });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Ensure/Create folder
app.post('/api/folder', async (req, res) => {
  try {
    const p = safeJoinBase((req.body && req.body.path) || '/');
    await withClient(async (client) => {
      await client.ensureDir(p);
    });
    res.json({ ok: true, created: p });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Create folder under parent by name
app.post('/api/folder/create', async (req, res) => {
  try {
    const parent = safeJoinBase((req.body && req.body.parent) || '/');
    const name = safeFileOrFolderName(req.body && req.body.name);
    if (!name) throw new Error('Invalid "name" for folder.');
    const fullPath = path.posix.join(parent, name);
    await withClient(async (client) => {
      await client.ensureDir(fullPath);
    });
    res.json({ ok: true, created: fullPath, parent, name });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Size (file or folder)
app.get('/api/size', async (req, res) => {
  try {
    const p = safeJoinBase((req.query && req.query.path) || '/');
    const result = await withClient(async (client) => {
      const base = path.posix.dirname(p);
      const name = path.posix.basename(p);
      let list;
      try {
        list = await client.list(base);
      } catch {
        throw new Error('Not found');
      }
      const entry = list.find((e) => e.name === name);
      if (!entry) throw new Error('Not found');
      const isDirectory =
        typeof entry.isDirectory === 'boolean'
          ? entry.isDirectory
          : entry.type === 2 ||
            entry.type === 'd' ||
            entry.type === 'directory';
      if (!isDirectory) {
        return {
          isDir: false,
          size: typeof entry.size === 'number' ? entry.size : null,
        };
      }
      return { isDir: true, size: await getSizeRecursive(client, p) };
    });
    res.json({ ok: true, isDirectory: result.isDir, size: result.size });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Folder total size (alias)
app.get('/api/folder/size', async (req, res) => {
  try {
    const p = safeJoinBase((req.query && req.query.path) || '/');
    const total = await withClient(async (client) =>
      getSizeRecursive(client, p)
    );
    res.json({ ok: true, size: total });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Create a text file from content
app.post('/api/file', async (req, res) => {
  try {
    const dest = safeJoinBase((req.body && req.body.dest) || '/');
    const name = safeFileOrFolderName(req.body && req.body.name);
    if (!name) throw new Error('Invalid "name".');
    const content =
      typeof (req.body && req.body.content) === 'string'
        ? req.body.content
        : '';
    const remotePath = path.posix.join(dest, name);
    await withClient(async (client) => {
      await client.ensureDir(dest);
      await client.uploadFrom(
        Readable.from(Buffer.from(content, 'utf8')),
        remotePath
      );
    });
    res.json({
      ok: true,
      created: remotePath,
      bytes: Buffer.byteLength(content, 'utf8'),
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// Read a file's content (utf8 or base64)
app.get('/api/file/content', async (req, res) => {
  try {
    if (!req.query || !req.query.path) throw new Error('Missing "path" query');
    const remotePath = safeJoinBase(req.query.path);
    const enc =
      req.query && req.query.encoding
        ? String(req.query.encoding).toLowerCase()
        : 'utf8';
    const result = await withClient(async (client) => {
      const chunks = [];
      const pass = new PassThrough();
      pass.on('data', (c) => chunks.push(c));
      await client.downloadTo(pass, remotePath);
      const buf = Buffer.concat(chunks);
      return { data: buf, size: buf.length };
    });
    if (enc === 'base64') {
      res.json({
        ok: true,
        path: remotePath,
        size: result.size,
        encoding: 'base64',
        content: result.data.toString('base64'),
      });
    } else {
      res.json({
        ok: true,
        path: remotePath,
        size: result.size,
        encoding: 'utf8',
        content: result.data.toString('utf8'),
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
      const destDir = safeJoinBase(targetBase);
      const remotePath = path.posix.join(destDir, req.file.originalname);

      await withClient(async (client) => {
        await client.ensureDir(destDir);
        await client.uploadFrom(tmpPath, remotePath);
      });

      res.json({
        ok: true,
        uploaded: {
          to: remotePath,
          filename: req.file.originalname,
          bytes: req.file.size,
        },
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
 * Accepts:
 *  - files (multipart array)
 *  - paths | relativePaths (optional): per-file relative path strings
 *  - dirs | directories (optional): relative directories to create (supports empty folders)
 *  - dest (optional): base destination (defaults '/')
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

      // Optional empty folders (from drag/drop enumeration)
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
      const baseDir = safeJoinBase(destBase);

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

      const uploaded = [];

      await withClient(async (client) => {
        // Ensure base exists
        await client.ensureDir(baseDir);

        // 1) Create all directories (parents first)
        const dirsSorted = Array.from(dirSet).sort((a, b) =>
          a.localeCompare(b, undefined, { sensitivity: 'base' })
        );
        for (const relDir of dirsSorted) {
          const dirAbs = safeJoinUnder(baseDir, relDir);
          await client.ensureDir(dirAbs);
        }

        // 2) Upload files preserving structure
        for (let i = 0; i < files.length; i++) {
          const f = files[i];
          const rel = path.posix.normalize(
            String(relPaths[i] || f.originalname)
              .replace(/^[\\/]+/, '')
              .replace(/\\/g, '/')
          );
          const destPath = safeJoinUnder(baseDir, rel);
          const destDir = path.posix.dirname(destPath);

          await client.ensureDir(destDir);
          await client.uploadFrom(f.path, destPath);

          uploaded.push({
            to: destPath,
            filename: f.originalname,
            bytes: f.size,
          });
        }
      });

      console.log('[UPLOAD-FOLDER OK]', {
        base: baseDir,
        files: files.length,
        createdDirs: dirSet.size,
      });

      return res.json({
        ok: true,
        base: baseDir,
        count: uploaded.length,
        uploaded,
        createdDirs: Array.from(dirSet),
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
          .map((p) => fsp.unlink(p))
      );
    }
  });
});

/* -------------------- DOWNLOAD -------------------- */
app.get('/api/download', async (req, res) => {
  try {
    const remotePath = safeJoinBase((req.query && req.query.path) || '/');
    const filename = path.posix.basename(remotePath);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader(
      'Content-Disposition',
      "attachment; filename*=UTF-8''" + encodeURIComponent(filename)
    );
    res.setHeader('X-Filename', filename);
    res.setHeader('Cache-Control', 'no-store');

    await withClient(async (client) => {
      const pass = new PassThrough();
      pass.on('error', () => {
        try {
          res.end();
        } catch {}
      });
      pass.pipe(res);
      await client.downloadTo(pass, remotePath);
    });
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
    const folderPath = safeJoinBase(body.path);

    const isFolder = await withClient(async (client) => {
      const parent = path.posix.dirname(folderPath);
      const base = path.posix.basename(folderPath);
      const list = await client.list(parent);
      const entry = list.find((e) => e.name === base);
      if (!entry) throw new Error('Folder not found');
      return typeof entry.isDirectory === 'boolean'
        ? entry.isDirectory
        : entry.type === 2 || entry.type === 'd' || entry.type === 'directory';
    });
    if (!isFolder) {
      return res.status(400).json({
        ok: false,
        error: 'Path is a file. Use /api/download for files.',
      });
    }

    if (pendingZips.size > 500) {
      return res
        .status(429)
        .json({ ok: false, error: 'Too many pending ZIP jobs' });
    }

    const folderName =
      safeFileOrFolderName(path.posix.basename(folderPath)) || 'folder';
    const zipName = `${folderName}.zip`;
    const id = randomUUID();
    pendingZips.set(id, {
      folderPath,
      filename: zipName,
      createdAt: Date.now(),
    });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true, downloadId: id, filename: zipName });
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
  archive.on('end', () => pendingZips.delete(req.params.id));
  archive.pipe(res);

  try {
    await withClient(async (client) => {
      const top =
        safeFileOrFolderName(path.posix.basename(job.folderPath)) || 'folder';
      const children = await collectFilesRecursive(client, job.folderPath);
      children.sort((a, b) =>
        a.localeCompare(b, undefined, { sensitivity: 'base' })
      );
      for (const abs of children) {
        const rel = abs.slice(job.folderPath.length + 1);
        const nameInZip = path.posix.join(top, rel);
        const pass = new PassThrough();
        archive.append(pass, { name: nameInZip });
        try {
          await client.downloadTo(pass, abs);
        } catch {
          try {
            pass.end();
          } catch {}
        }
      }
    });
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

app.post('/api/zip-multi', async (req, res) => {
  try {
    const body = req.body || {};
    const rawItems = Array.isArray(body.items) ? body.items : [];
    if (!rawItems.length)
      return res.status(400).json({ ok: false, error: 'No items' });

    const normalized = rawItems.map((it) => ({
      path: safeJoinBase(it && it.path ? it.path : '/'),
      type: (it && it.type ? String(it.type) : 'file').toLowerCase(),
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
    await withClient(async (client) => {
      const ensureUnique = uniqueNameResolver();
      const entries = [];
      for (const it of job.items) {
        const isFolder = ['folder', 'directory', 'dir'].includes(it.type);
        if (isFolder) {
          const top =
            safeFileOrFolderName(path.posix.basename(it.path)) || 'folder';
          const children = await collectFilesRecursive(client, it.path);
          children.sort((a, b) =>
            a.localeCompare(b, undefined, { sensitivity: 'base' })
          );
          for (const abs of children) {
            const rel = abs.slice(it.path.length + 1);
            const desired = path.posix.join(top, rel);
            entries.push({ abs, nameInZip: desired });
          }
        } else {
          entries.push({
            abs: it.path,
            nameInZip: path.posix.basename(it.path),
          });
        }
      }
      const fixed = entries.map((e) => ({
        ...e,
        nameInZip: ensureUnique(e.nameInZip),
      }));
      for (const e of fixed) {
        const pass = new PassThrough();
        archive.append(pass, { name: e.nameInZip });
        try {
          await client.downloadTo(pass, e.abs);
        } catch {
          try {
            pass.end();
          } catch {}
        }
      }
    });
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

    const from = safeJoinBase(rawFrom);
    const to = safeJoinBase(rawTo);

    const result = await withClient(async (client) => {
      const info = await statPath(client, from);
      if (!info.exists || !info.isDir)
        throw new Error('Source folder does not exist.');
      return await safeRename(client, from, to, {
        overwrite: String(req.body?.overwrite).toLowerCase() === 'true',
      });
    });

    res.json({ ok: true, ...result });
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

    const from = safeJoinBase(req.body.from);
    let to;
    if (hasFromTo) {
      to = safeJoinBase(req.body.to);
    } else {
      const dir = path.posix.dirname(from);
      const newName = safeFileOrFolderName(req.body.newName);
      if (!newName) throw new Error('Invalid newName');
      to = safeJoinBase(path.posix.join(dir, newName));
    }

    const result = await withClient(async (client) => {
      const info = await statPath(client, from);
      if (!info.exists || info.isDir)
        throw new Error('Source file does not exist or is a directory.');
      return await safeRename(client, from, to, {
        overwrite: String(req.body?.overwrite).toLowerCase() === 'true',
      });
    });

    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || 'Rename failed' });
  }
});

// DELETE (file or folder) — public
async function deleteHandler(req, res) {
  try {
    const raw = (req.query && req.query.path) || (req.body && req.body.path);
    if (!raw) throw new Error('Missing "path"');
    const p = safeJoinBase(raw);

    const result = await withClient(async (client) => {
      const info = await statPath(client, p);
      if (!info.exists) throw new Error('Not found');
      const out = await removeRecursive(client, p);
      return { isDirectory: info.isDir, ...out };
    });

    res.json({ ok: true, path: p, ...result });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || 'Delete failed' });
  }
}
app.delete('/api/delete', deleteHandler);
app.post('/api/delete', deleteHandler);
app.delete('/api/file', deleteHandler);
app.delete('/api/folder', deleteHandler);

// DELETE multiple — public
app.post('/api/delete-multi', async (req, res) => {
  try {
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    if (!items.length) throw new Error('No items');

    const results = await withClient(async (client) => {
      const out = [];
      for (const it of items) {
        try {
          const p = safeJoinBase(it && it.path ? it.path : '/');
          const info = await statPath(client, p);
          if (!info.exists) {
            out.push({ path: p, ok: false, error: 'Not found' });
            continue;
          }
          const r = await removeRecursive(client, p);
          out.push({ path: p, ok: true, isDirectory: info.isDir, ...r });
        } catch (err) {
          out.push({
            path: it?.path || '',
            ok: false,
            error: err.message || 'Delete failed',
          });
        }
      }
      return out;
    });

    res.json({ ok: true, results });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || 'Delete failed' });
  }
});

/* -------------------- ADMIN (kept behind your router) -------------------- */
app.use('/api/admin', adminRouter);

/* -------------------- HOUSEKEEPING -------------------- */
setInterval(() => {
  const now = Date.now();
  for (const [id, job] of pendingZips.entries())
    if (now - job.createdAt > 30 * 60 * 1000) pendingZips.delete(id);
  for (const [id, job] of pendingMultiZips.entries())
    if (now - job.createdAt > 30 * 60 * 1000) pendingMultiZips.delete(id);
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
