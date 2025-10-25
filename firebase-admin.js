// firebase-admin.js
// Robust initializer for Firebase Admin SDK.
// Supports credentials from:
//  1) GOOGLE_APPLICATION_CREDENTIALS_JSON (full JSON in env)
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

function parseCredsFromEnvJson(raw) {
  if (!raw) return null;
  try {
    const obj = JSON.parse(raw);
    if (obj.private_key && typeof obj.private_key === 'string') {
      // Convert escaped newlines to real newlines
      obj.private_key = obj.private_key.replace(/\\n/g, '\n');
    }
    return obj;
  } catch {
    return null;
  }
}

function loadCredentials() {
  // 1) Full JSON in env var (recommended for prod)
  const envJson = process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON;
  const parsed = parseCredsFromEnvJson(envJson);
  if (parsed) return parsed;

  // 2) Path to JSON file in env
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
    const json = JSON.parse(fs.readFileSync(abs, 'utf8'));
    if (json.private_key && typeof json.private_key === 'string') {
      json.private_key = json.private_key.replace(/\\n/g, '\n');
    }
    return json;
  }

  // 3) Local dev fallback
  const localPath = path.join(process.cwd(), 'serviceAccount.json');
  if (!fs.existsSync(localPath)) {
    throw new Error(
      'No Firebase Admin credentials found. Provide one of:\n' +
        ' - GOOGLE_APPLICATION_CREDENTIALS_JSON (full JSON)\n' +
        ' - GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json\n' +
        ' - serviceAccount.json in the project root'
    );
  }
  const json = JSON.parse(fs.readFileSync(localPath, 'utf8'));
  if (json.private_key && typeof json.private_key === 'string') {
    json.private_key = json.private_key.replace(/\\n/g, '\n');
  }
  return json;
}

function initAdmin() {
  if (admin.apps.length) return admin; // already initialized

  const creds = loadCredentials();

  admin.initializeApp({
    credential: admin.credential.cert(creds),
    // Optionally add:
    // projectId: creds.project_id,
    // databaseURL: `https://${creds.project_id}.firebaseio.com`,
    // storageBucket: `${creds.project_id}.appspot.com`,
  });

  return admin;
}

const instance = initAdmin();

function getDb() {
  return instance.firestore();
}

function getAuth() {
  return instance.auth();
}

// Convenience methods on the instance (optional)
instance.getDb = getDb;
instance.getAuth = getAuth;

// Default export (CommonJS)
module.exports = instance;

// Named exports (CommonJS)
module.exports.admin = instance;
module.exports.getDb = getDb;
module.exports.getAuth = getAuth;
