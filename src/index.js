'use strict';
const express = require('express');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const path = require('path');
const { rateLimit } = require('express-rate-limit');

const { initDb, getDb, getSessionSecret } = require('./db.js');
const { uploadToS3, downloadFromS3, deleteFromS3 } = require('./s3.js');
const { getOidcDiscovery, validateJwt } = require('./auth.js');

const PORT = parseInt(process.env.PORT || '3000');
const ACCESS_MODE = process.env.ACCESS_MODE || 'upload-authenticated';
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE || String(50 * 1024 * 1024));
const OIDC_CLIENT_ID = process.env.OIDC_CLIENT_ID || '';
const OIDC_ISSUER_URL = process.env.OIDC_ISSUER_URL || '';
const OIDC_CLIENT_ORIGIN = process.env.OIDC_CLIENT_ORIGIN || '';

// MIME types safe for inline preview
const SAFE_INLINE = new Set([
  'image/jpeg','image/png','image/gif','image/webp','image/avif',
  'audio/mpeg','audio/ogg','audio/wav','audio/flac','audio/aac','audio/mp4',
  'video/mp4','video/webm','video/ogg',
  'text/plain',
  'application/pdf',
]);

// Must be served as application/octet-stream download
const FORCE_DOWNLOAD = new Set([
  'text/html','image/svg+xml','application/javascript','text/javascript',
  'application/x-sh','application/xhtml+xml','text/xml','application/xml',
  'application/x-httpd-php','application/x-perl',
]);

function detectMime(buf) {
  if (buf.length < 4) return 'application/octet-stream';
  const b = buf;
  if (b[0]===0xFF && b[1]===0xD8 && b[2]===0xFF) return 'image/jpeg';
  if (b[0]===0x89 && b[1]===0x50 && b[2]===0x4E && b[3]===0x47) return 'image/png';
  if (b[0]===0x47 && b[1]===0x49 && b[2]===0x46) return 'image/gif';
  if (b[0]===0x52 && b[1]===0x49 && b[2]===0x46 && b[3]===0x46 &&
      buf.length >= 12 && b[8]===0x57 && b[9]===0x45 && b[10]===0x42 && b[11]===0x50) return 'image/webp';
  if (b[0]===0x25 && b[1]===0x50 && b[2]===0x44 && b[3]===0x46) return 'application/pdf';
  if (b[0]===0x49 && b[1]===0x44 && b[2]===0x33) return 'audio/mpeg';
  if (b[0]===0xFF && (b[1]===0xFB || b[1]===0xF3 || b[1]===0xF2)) return 'audio/mpeg';
  if (b[0]===0x4F && b[1]===0x67 && b[2]===0x67 && b[3]===0x53) return 'audio/ogg';
  if (b[0]===0x66 && b[1]===0x4C && b[2]===0x61 && b[3]===0x43) return 'audio/flac';
  if (b[0]===0x52 && b[1]===0x49 && b[2]===0x46 && b[3]===0x46 &&
      buf.length >= 12 && b[8]===0x57 && b[9]===0x41 && b[10]===0x56 && b[11]===0x45) return 'audio/wav';
  if (buf.length >= 8 && b[4]===0x66 && b[5]===0x74 && b[6]===0x79 && b[7]===0x70) return 'video/mp4';
  if (b[0]===0x1A && b[1]===0x45 && b[2]===0xDF && b[3]===0xA3) return 'video/webm';
  if (b[0]===0x50 && b[1]===0x4B) return 'application/zip';
  // Detect text types by scanning first 512 bytes
  const head = buf.slice(0, 512).toString('binary').replace(/\0/g, '');
  const headLow = head.trimStart().toLowerCase();
  if (headLow.startsWith('<!doctype html') || headLow.startsWith('<html')) return 'text/html';
  if (headLow.startsWith('<?xml') || headLow.startsWith('<svg')) return 'image/svg+xml';
  // Heuristic: if mostly printable ASCII, call it text/plain
  const printable = (buf.slice(0, 512).toString('binary').match(/[\x09\x0A\x0D\x20-\x7E]/g) || []).length;
  if (printable / Math.min(buf.length, 512) > 0.85) return 'text/plain';
  return 'application/octet-stream';
}

function hash(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function genToken() {
  return crypto.randomBytes(32).toString('hex');
}

function createSession(user, secret) {
  const payload = Buffer.from(JSON.stringify({
    iss: user.iss, sub: user.sub, email: user.email,
    exp: Date.now() + 24 * 60 * 60 * 1000,
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function parseSession(cookie, secret) {
  const [payload, sig] = (cookie || '').split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  if (sig !== expected) return null;
  const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
  if (data.exp < Date.now()) return null;
  return data;
}

function isExpired(file) {
  return file.expires_at && Date.now() > file.expires_at;
}

function checkOwnership(file, req) {
  if (req.user && file.owner_issuer === req.user.iss && file.owner_sub === req.user.sub) return true;
  const mgmt = req.headers['x-management-token'] || req.query.mgmt;
  if (mgmt && file.management_token_hash && hash(mgmt) === file.management_token_hash) return true;
  return false;
}

function canRead(file, req, shareToken) {
  if (file.cleanup_done || isExpired(file)) return false;
  if (checkOwnership(file, req)) return true;
  if (file.visibility === 'public') {
    if (ACCESS_MODE === 'enforced-auth') return !!req.user;
    return true;
  }
  // Private: check share token
  const tok = shareToken || req.query.share;
  if (tok && hash(tok) === file.share_token_hash) {
    if (ACCESS_MODE === 'enforced-auth') return !!req.user;
    return true;
  }
  return false;
}

function canUpload(req) {
  if (ACCESS_MODE === 'anonymous') return true;
  return !!req.user;
}

function canBrowsePublic(req) {
  if (ACCESS_MODE === 'enforced-auth') return !!req.user;
  return true;
}

const app = express();
app.use(cookieParser());
app.use(express.json());
app.set('trust proxy', 1);
app.use(express.static(path.join(__dirname, '..', 'public')));

let SESSION_SECRET;

// Auth middleware
app.use(async (req, res, next) => {
  req.user = null;
  const sess = parseSession(req.cookies?.session, SESSION_SECRET);
  if (sess) { req.user = sess; return next(); }
  const auth = req.headers.authorization;
  if (auth?.startsWith('Bearer ')) {
    try {
      req.user = await validateJwt(auth.slice(7), OIDC_ISSUER_URL, null);
    } catch {}
  }
  next();
});

// Anonymous upload rate limit (10/15min per IP)
const anonLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  skip: (req) => !!req.user,
  standardHeaders: true,
  legacyHeaders: false,
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE, files: 10 },
});

// ── Config ──────────────────────────────────────────────────────────────────
app.get('/api/config', async (req, res) => {
  let discovery = null;
  try { discovery = await getOidcDiscovery(OIDC_ISSUER_URL); } catch {}
  res.json({
    accessMode: ACCESS_MODE,
    oidc: {
      clientId: OIDC_CLIENT_ID,
      issuerUrl: OIDC_ISSUER_URL,
      origin: OIDC_CLIENT_ORIGIN,
      redirectUri: (OIDC_CLIENT_ORIGIN || '') + '/auth/callback',
      authorizationEndpoint: discovery?.authorization_endpoint || null,
      tokenEndpoint: discovery?.token_endpoint || null,
    },
    limits: { maxFileSize: MAX_FILE_SIZE },
    user: req.user ? { sub: req.user.sub, email: req.user.email } : null,
  });
});

// ── Auth ─────────────────────────────────────────────────────────────────────
app.post('/auth/token', async (req, res) => {
  const { code, codeVerifier, redirectUri } = req.body || {};
  if (!code || !codeVerifier || !redirectUri) return res.status(400).json({ error: 'Missing fields' });
  try {
    const discovery = await getOidcDiscovery(OIDC_ISSUER_URL);
    const tokenRes = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: codeVerifier, client_id: OIDC_CLIENT_ID, redirect_uri: redirectUri }),
    });
    if (!tokenRes.ok) {
      const err = await tokenRes.text();
      return res.status(400).json({ error: 'Token exchange failed', detail: err });
    }
    const tokens = await tokenRes.json();
    const user = await validateJwt(tokens.id_token, OIDC_ISSUER_URL, null);
    const cookie = createSession(user, SESSION_SECRET);
    res.cookie('session', cookie, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 86400000, path: '/' });
    res.json({ user: { sub: user.sub, email: user.email } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/auth/logout', (req, res) => {
  res.clearCookie('session', { path: '/' });
  res.json({ ok: true });
});

app.get('/auth/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ sub: req.user.sub, email: req.user.email });
});

// ── Public gallery ──────────────────────────────────────────────────────────
app.get('/api/files', (req, res) => {
  if (!canBrowsePublic(req)) return res.status(401).json({ error: 'Authentication required' });
  const limit = Math.min(parseInt(req.query.limit || '20'), 50);
  const before = req.query.before ? parseInt(req.query.before) : Date.now();
  const db = getDb();
  const rows = db.prepare(`
    SELECT id, original_name, size, content_type, visibility, expires_at, uploaded_at
    FROM files
    WHERE visibility='public' AND cleanup_done=0 AND uploaded_at < ?
      AND (expires_at IS NULL OR expires_at > ?)
    ORDER BY uploaded_at DESC LIMIT ?
  `).all(before, Date.now(), limit + 1);
  const hasMore = rows.length > limit;
  const files = hasMore ? rows.slice(0, limit) : rows;
  res.json({ files, nextCursor: hasMore ? files[files.length - 1].uploaded_at : null });
});

// ── Upload ───────────────────────────────────────────────────────────────────
app.post('/api/files', anonLimiter, upload.array('files', 10), async (req, res) => {
  if (!canUpload(req)) return res.status(401).json({ error: 'Sign in to upload' });
  if (!req.files?.length) return res.status(400).json({ error: 'No files' });

  const db = getDb();
  const now = Date.now();
  const visibility = req.body.visibility === 'public' ? 'public' : 'private';
  const expiresAt = req.body.expiresAt ? parseInt(req.body.expiresAt) : null;
  if (expiresAt && expiresAt <= now) return res.status(400).json({ error: 'Expiry must be in the future' });

  const results = [];
  for (const f of req.files) {
    const contentType = detectMime(f.buffer);
    const id = uuidv4();
    const shareToken = genToken();
    let mgmtToken = null, mgmtHash = null;
    if (!req.user) {
      mgmtToken = genToken();
      mgmtHash = hash(mgmtToken);
    }
    try {
      await uploadToS3(id, f.buffer, contentType);
    } catch (e) {
      return res.status(500).json({ error: 'S3 upload failed: ' + e.message });
    }
    db.prepare(`INSERT INTO files (id,original_name,size,content_type,visibility,expires_at,owner_issuer,owner_sub,management_token_hash,share_token_hash,uploaded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(id, f.originalname, f.size, contentType, visibility, expiresAt, req.user?.iss || null, req.user?.sub || null, mgmtHash, hash(shareToken), now);
    const r = { id, originalName: f.originalname, size: f.size, contentType, visibility, expiresAt, uploadedAt: now, shareUrl: `/share/${shareToken}` };
    if (mgmtToken) {
      r.managementToken = mgmtToken;
      r.managementUrl = `/?mgmt=${mgmtToken}`;
      r.managementWarning = '⚠ Save this token! It is shown only once. Without it you cannot manage this upload.';
    }
    results.push(r);
  }
  res.status(201).json({ files: results });
});

// ── File metadata ─────────────────────────────────────────────────────────────
app.get('/api/files/:id', (req, res) => {
  const db = getDb();
  const file = db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id);
  if (!file || file.cleanup_done) return res.status(404).json({ error: 'Not found' });
  const shareToken = req.query.share;
  if (!canRead(file, req, shareToken)) {
    if (!req.user && ACCESS_MODE !== 'anonymous') return res.status(401).json({ error: 'Authentication required' });
    return res.status(403).json({ error: 'Access denied' });
  }
  const isOwner = checkOwnership(file, req);
  res.json({
    id: file.id, originalName: file.original_name, size: file.size,
    contentType: file.content_type, visibility: file.visibility,
    expiresAt: file.expires_at, uploadedAt: file.uploaded_at,
    isOwner, isExpired: !!isExpired(file),
  });
});

// ── Update file ───────────────────────────────────────────────────────────────
app.put('/api/files/:id', (req, res) => {
  const db = getDb();
  const file = db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id);
  if (!file || file.cleanup_done) return res.status(404).json({ error: 'Not found' });
  if (!checkOwnership(file, req)) return res.status(403).json({ error: 'Access denied' });
  if (isExpired(file)) return res.status(410).json({ error: 'File expired' });
  const { visibility, expiresAt } = req.body;
  const sets = [], vals = [];
  if (visibility === 'public' || visibility === 'private') { sets.push('visibility=?'); vals.push(visibility); }
  if ('expiresAt' in req.body) {
    if (expiresAt !== null && expiresAt <= Date.now()) return res.status(400).json({ error: 'Expiry in past' });
    sets.push('expires_at=?'); vals.push(expiresAt ?? null);
  }
  if (!sets.length) return res.status(400).json({ error: 'Nothing to update' });
  db.prepare(`UPDATE files SET ${sets.join(',')} WHERE id=?`).run(...vals, file.id);
  res.json({ ok: true });
});

// ── Delete file ───────────────────────────────────────────────────────────────
app.delete('/api/files/:id', async (req, res) => {
  const db = getDb();
  const file = db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id);
  if (!file || file.cleanup_done) return res.status(404).json({ error: 'Not found' });
  if (!checkOwnership(file, req)) return res.status(403).json({ error: 'Access denied' });
  try {
    await deleteFromS3(file.id);
    db.prepare('UPDATE files SET cleanup_done=1 WHERE id=?').run(file.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Download/stream content ───────────────────────────────────────────────────
app.get('/api/files/:id/content', async (req, res) => {
  const db = getDb();
  const file = db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id);
  if (!file || file.cleanup_done || isExpired(file)) return res.status(404).json({ error: 'Not found' });
  if (!canRead(file, req, req.query.share)) {
    if (!req.user && ACCESS_MODE !== 'anonymous') return res.status(401).json({ error: 'Authentication required' });
    return res.status(403).json({ error: 'Access denied' });
  }

  const forceDownload = FORCE_DOWNLOAD.has(file.content_type) || !SAFE_INLINE.has(file.content_type);
  const safeType = forceDownload ? 'application/octet-stream' : file.content_type;
  const disp = forceDownload
    ? `attachment; filename*=UTF-8''${encodeURIComponent(file.original_name)}`
    : `inline; filename*=UTF-8''${encodeURIComponent(file.original_name)}`;

  res.setHeader('Content-Type', safeType);
  res.setHeader('Content-Disposition', disp);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'private, no-store');
  res.setHeader('Accept-Ranges', 'bytes');

  const rangeHeader = req.headers.range;
  if (rangeHeader) {
    const [start, end] = parseRange(rangeHeader, file.size);
    if (start > file.size - 1) return res.status(416).end();
    const actualEnd = Math.min(end, file.size - 1);
    res.status(206);
    res.setHeader('Content-Range', `bytes ${start}-${actualEnd}/${file.size}`);
    res.setHeader('Content-Length', actualEnd - start + 1);
  } else {
    res.setHeader('Content-Length', file.size);
  }

  try {
    const stream = await downloadFromS3(file.id, rangeHeader || undefined);
    stream.pipe(res);
    stream.on('error', (e) => { console.error('stream error', e); if (!res.headersSent) res.status(500).end(); });
  } catch (e) {
    console.error('download error', e);
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

function parseRange(header, total) {
  const m = header.match(/bytes=(\d*)-(\d*)/);
  if (!m) return [0, total - 1];
  const start = m[1] ? parseInt(m[1]) : total - parseInt(m[2]);
  const end = m[2] ? parseInt(m[2]) : total - 1;
  return [Math.max(0, start), Math.min(total - 1, end)];
}

// ── Revoke share link ─────────────────────────────────────────────────────────
app.post('/api/files/:id/revoke-link', (req, res) => {
  const db = getDb();
  const file = db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id);
  if (!file || file.cleanup_done) return res.status(404).json({ error: 'Not found' });
  if (!checkOwnership(file, req)) return res.status(403).json({ error: 'Access denied' });
  if (isExpired(file)) return res.status(410).json({ error: 'File expired' });
  const tok = genToken();
  db.prepare('UPDATE files SET share_token_hash=? WHERE id=?').run(hash(tok), file.id);
  res.json({ shareUrl: `/share/${tok}` });
});

// ── My files ──────────────────────────────────────────────────────────────────
app.get('/api/my-files', (req, res) => {
  const mgmt = req.headers['x-management-token'] || req.query.mgmt;
  const db = getDb();
  let rows;
  if (req.user) {
    rows = db.prepare(`SELECT id,original_name,size,content_type,visibility,expires_at,uploaded_at FROM files WHERE owner_issuer=? AND owner_sub=? AND cleanup_done=0 ORDER BY uploaded_at DESC LIMIT 200`).all(req.user.iss, req.user.sub);
  } else if (mgmt) {
    const f = db.prepare('SELECT id,original_name,size,content_type,visibility,expires_at,uploaded_at FROM files WHERE management_token_hash=? AND cleanup_done=0').get(hash(mgmt));
    rows = f ? [f] : [];
  } else {
    return res.status(401).json({ error: 'Authentication required' });
  }
  res.json({ files: rows });
});

// ── Private share redirect ────────────────────────────────────────────────────
app.get('/share/:shareToken', (req, res) => {
  const db = getDb();
  const tok = req.params.shareToken;
  const file = db.prepare('SELECT * FROM files WHERE share_token_hash=? AND cleanup_done=0').get(hash(tok));
  if (!file || isExpired(file)) return res.status(404).send('File not found or expired');
  if (ACCESS_MODE === 'enforced-auth' && !req.user) {
    return res.redirect(302, `/auth/login?next=${encodeURIComponent(req.url)}`);
  }
  res.redirect(302, `/?view=${file.id}&share=${tok}`);
});

// ── Auth redirect entry ───────────────────────────────────────────────────────
app.get('/auth/login', (req, res) => res.redirect('/?login=1' + (req.query.next ? `&next=${encodeURIComponent(req.query.next)}` : '')));
app.get('/auth/callback', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

// ── SPA fallback ──────────────────────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

// ── Cleanup job ───────────────────────────────────────────────────────────────
function runCleanup() {
  const db = getDb();
  try {
    const expired = db.prepare('SELECT id FROM files WHERE cleanup_done=0 AND expires_at IS NOT NULL AND expires_at < ?').all(Date.now());
    for (const { id } of expired) {
      deleteFromS3(id).catch(e => console.error('cleanup S3 delete', id, e));
      db.prepare('UPDATE files SET cleanup_done=1 WHERE id=?').run(id);
    }
  } catch (e) { console.error('cleanup error', e); }
}

// ── Start ─────────────────────────────────────────────────────────────────────
initDb();
SESSION_SECRET = getSessionSecret();
runCleanup();
setInterval(runCleanup, 5 * 60 * 1000);

app.listen(PORT, '0.0.0.0', () => {
  console.log(`FileDrop listening on :${PORT} [mode=${ACCESS_MODE}]`);
});
