'use strict';
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const DB_PATH = process.env.DB_PATH || '/data/filedrop.db';
let db;

function initDb() {
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      original_name TEXT NOT NULL,
      size INTEGER NOT NULL,
      content_type TEXT NOT NULL,
      visibility TEXT NOT NULL DEFAULT 'private',
      expires_at INTEGER,
      owner_issuer TEXT,
      owner_sub TEXT,
      management_token_hash TEXT,
      share_token_hash TEXT NOT NULL,
      uploaded_at INTEGER NOT NULL,
      cleanup_done INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_files_public
      ON files(uploaded_at DESC)
      WHERE visibility = 'public' AND cleanup_done = 0;

    CREATE INDEX IF NOT EXISTS idx_files_share
      ON files(share_token_hash)
      WHERE cleanup_done = 0;

    CREATE INDEX IF NOT EXISTS idx_files_owner
      ON files(owner_issuer, owner_sub, uploaded_at DESC)
      WHERE cleanup_done = 0;

    CREATE INDEX IF NOT EXISTS idx_files_mgmt
      ON files(management_token_hash)
      WHERE cleanup_done = 0;

    CREATE INDEX IF NOT EXISTS idx_files_cleanup
      ON files(expires_at)
      WHERE cleanup_done = 0 AND expires_at IS NOT NULL;
  `);
}

function getSessionSecret() {
  let row = db.prepare('SELECT value FROM config WHERE key = ?').get('session_secret');
  if (!row) {
    const secret = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)').run('session_secret', secret);
    row = { value: secret };
  }
  return row.value;
}

function getDb() {
  return db;
}

module.exports = { initDb, getDb, getSessionSecret };
