// firebase-admin.js
// Robust initializer for Firebase Admin SDK.
// Credential sources (checked in order):
//  1) GOOGLE_APPLICATION_CREDENTIALS_JSON (full JSON as env string)
//  2) GOOGLE_APPLICATION_CREDENTIALS (path to JSON file)
//  3) ./serviceAccount.json (dev fallback)
//
// Exports:
//   - default export = admin (initialized instance)
//   - { admin, getDb, getAuth }

'use strict';

const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

/* ---------------------------- Helpers ---------------------------- */

function normalizePrivateKey(pk) {
  if (!pk || typeof pk !== 'string') return pk;
  // Convert escaped newlines to actual newlines when coming from env vars
  return pk.includes('\\n') ? pk.replace(/\\n/g, '\n') : pk;
}

function parseCredsFromEnvJson(raw) {
  if (!raw) return null;
  try {
    const obj = JSON.parse(raw);
    if (obj.private_key) obj.private_key = normalizePrivateKey(obj.private_key);
    return obj;
  } catch {
    // If it isn't valid JSON we return null so the next source can be tried.
    return null;
  }
}

function readJsonFile(absPath) {
  const content = fs.readFileSync(absPath, 'utf8');
  const json = JSON.parse(content);
  if (json.private_key)
    json.private_key = normalizePrivateKey(json.private_key);
  return json;
}

function validateServiceAccount(json, sourceLabel) {
  const missing = [];
  if (!json || typeof json !== 'object') missing.push('entire JSON');
  else {
    if (!json.client_email) missing.push('client_email');
    if (!json.private_key) missing.push('private_key');
    if (!json.project_id) missing.push('project_id');
  }
  if (missing.length) {
    throw new Error(
      `Invalid Firebase service account from ${sourceLabel}: missing ${missing.join(
        ', '
      )}`
    );
  }
  // Basic sanity check for key shape
  if (!String(json.private_key).includes('BEGIN PRIVATE KEY')) {
    throw new Error(
      `Service account private_key from ${sourceLabel} looks malformed (newline escaping not fixed?).`
    );
  }
  return json;
}

function loadCredentials() {
  // 1) Full JSON in env var (recommended in hosted/prod)
  const envJson = process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON;
  const parsed = parseCredsFromEnvJson(envJson);
  if (parsed)
    return validateServiceAccount(
      parsed,
      'GOOGLE_APPLICATION_CREDENTIALS_JSON'
    );

  // 2) Path to JSON file via env
  const envPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (envPath) {
    const abs = path.isAbsolute(envPath)
      ? envPath
      : path.join(process.cwd(), envPath);
    if (!fs.existsSync(abs)) {
      throw new Error(
        `GOOGLE_APPLICATION_CREDENTIALS points to a non-existent file: ${abs}`
      );
    }
    const json = readJsonFile(abs);
    return validateServiceAccount(json, `file ${abs}`);
  }

  // 3) Local dev fallback
  const localPath = path.join(process.cwd(), 'serviceAccount.json');
  if (fs.existsSync(localPath)) {
    const json = readJsonFile(localPath);
    return validateServiceAccount(json, `file ${localPath}`);
  }

  throw new Error(
    'No Firebase Admin credentials found. Provide one of:\n' +
      ' - GOOGLE_APPLICATION_CREDENTIALS_JSON (full JSON string)\n' +
      ' - GOOGLE_APPLICATION_CREDENTIALS=/absolute/or/relative/path/to/key.json\n' +
      ' - serviceAccount.json in the project root (dev only)'
  );
}

function initAdmin() {
  if (admin.apps.length) return admin; // already initialized
  const creds = loadCredentials();

  admin.initializeApp({
    credential: admin.credential.cert(creds),
    // Explicit projectId helps in some hosts; falls back to creds.project_id/env
    projectId: creds.project_id || process.env.GOOGLE_CLOUD_PROJECT,
    // Optional:
    // databaseURL: `https://${creds.project_id}.firebaseio.com`,
    // storageBucket: `${creds.project_id}.appspot.com`,
  });

  return admin;
}

/* ---------------------------- Instance ---------------------------- */

const instance = initAdmin();

function getDb() {
  return instance.firestore();
}

function getAuth() {
  return instance.auth();
}

// Convenience
instance.getDb = getDb;
instance.getAuth = getAuth;

/* ---------------------------- Exports ---------------------------- */

module.exports = instance; // default export (CommonJS)
module.exports.admin = instance; // named
module.exports.getDb = getDb; // named
module.exports.getAuth = getAuth; // named
