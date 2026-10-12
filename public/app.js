'use strict';
/* global fetch, sessionStorage, crypto, TextEncoder, Uint8Array */

let CONFIG = null;
let currentUser = null;
let galleryCursor = null;
let currentMgmtToken = sessionStorage.getItem('mgmtToken') || null;

// ── PKCE helpers ──────────────────────────────────────────────────────────────
function b64url(arr) {
  return btoa(String.fromCharCode(...arr)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
async function generatePKCE() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return { verifier, challenge: b64url(new Uint8Array(digest)) };
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, ms = 3000) {
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), ms);
}

// ── API helpers ───────────────────────────────────────────────────────────────
async function api(method, path, body, headers = {}) {
  const opts = { method, headers: { ...headers } };
  if (body instanceof FormData) {
    opts.body = body;
  } else if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  if (currentMgmtToken) opts.headers['x-management-token'] = currentMgmtToken;
  const res = await fetch(path, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

// ── Formatting ────────────────────────────────────────────────────────────────
function fmtSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n/1048576).toFixed(1) + ' MB';
  return (n/1073741824).toFixed(2) + ' GB';
}
function fmtDate(ms) { return ms ? new Date(ms).toLocaleString() : '—'; }
function typeIcon(ct) {
  if (!ct) return '📄';
  if (ct.startsWith('image/')) return '🖼️';
  if (ct.startsWith('video/')) return '🎬';
  if (ct.startsWith('audio/')) return '🎵';
  if (ct === 'application/pdf') return '📑';
  if (ct === 'text/plain') return '📝';
  if (ct.includes('zip') || ct.includes('archive')) return '📦';
  return '📄';
}

// ── OIDC login ────────────────────────────────────────────────────────────────
async function startLogin() {
  if (!CONFIG?.oidc?.authorizationEndpoint) { toast('OIDC not configured'); return; }
  const { verifier, challenge } = await generatePKCE();
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)));
  sessionStorage.setItem('pkce_verifier', verifier);
  sessionStorage.setItem('pkce_state', state);
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CONFIG.oidc.clientId,
    redirect_uri: CONFIG.oidc.redirectUri,
    scope: 'openid profile email',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
  });
  window.location.href = CONFIG.oidc.authorizationEndpoint + '?' + params;
}

async function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');
  if (!code) return;
  const savedState = sessionStorage.getItem('pkce_state');
  const verifier = sessionStorage.getItem('pkce_verifier');
  sessionStorage.removeItem('pkce_state');
  sessionStorage.removeItem('pkce_verifier');
  if (state !== savedState) { toast('State mismatch — login failed'); return; }
  try {
    const data = await api('POST', '/auth/token', {
      code, codeVerifier: verifier,
      redirectUri: CONFIG.oidc.redirectUri,
    });
    currentUser = data.user;
    toast('Signed in as ' + (currentUser.email || currentUser.sub));
    window.history.replaceState({}, '', '/');
    updateUI();
  } catch (e) {
    toast('Login failed: ' + e.message);
    window.history.replaceState({}, '', '/');
  }
}

async function logout() {
  await api('POST', '/auth/logout');
  currentUser = null;
  updateUI();
  toast('Signed out');
}

// ── Init ──────────────────────────────────────────────────────────────────────
async function init() {
  // Load config
  try {
    CONFIG = await (await fetch('/api/config')).json();
    currentUser = CONFIG.user;
  } catch (e) { console.error('config', e); }

  // Handle mgmt token in URL
  const urlParams = new URLSearchParams(window.location.search);
  const mgmt = urlParams.get('mgmt');
  if (mgmt) {
    currentMgmtToken = mgmt;
    sessionStorage.setItem('mgmtToken', mgmt);
  }

  // Handle OIDC callback
  if (window.location.pathname === '/auth/callback' || urlParams.get('code')) {
    if (CONFIG) await handleCallback();
    return;
  }

  // Handle direct view link (from /share/:token redirect)
  const viewId = urlParams.get('view');
  const shareToken = urlParams.get('share');
  if (viewId) {
    await openFileModal(viewId, shareToken);
    window.history.replaceState({}, '', '/');
  }

  // Handle login request from enforced-auth redirect
  if (urlParams.get('login') === '1') {
    await startLogin();
    return;
  }

  updateUI();
  setMinExpiry();
}

function setMinExpiry() {
  const el = document.getElementById('expiresInput');
  if (el) {
    const now = new Date(Date.now() + 60000);
    el.min = now.toISOString().slice(0, 16);
  }
}

// ── UI update ─────────────────────────────────────────────────────────────────
function updateUI() {
  const mode = CONFIG?.accessMode || 'upload-authenticated';
  const modeLabels = {
    'anonymous': 'Anonymous Mode — anyone can upload',
    'upload-authenticated': 'Upload requires sign-in',
    'enforced-auth': 'Sign-in required to browse',
  };

  document.getElementById('modeBadge').textContent = mode.replace(/-/g, ' ');

  const banner = document.getElementById('modeBanner');
  banner.textContent = modeLabels[mode] || mode;
  banner.style.display = '';

  // Auth area
  const authArea = document.getElementById('authArea');
  if (currentUser) {
    authArea.innerHTML = `<span style="font-size:0.85rem;margin-right:8px">${currentUser.email || currentUser.sub}</span><button class="btn btn-secondary btn-small" onclick="logout()">Sign Out</button>`;
    document.getElementById('myfilesTab').style.display = '';
  } else if (CONFIG?.oidc?.clientId) {
    authArea.innerHTML = `<button class="btn btn-primary btn-small" onclick="startLogin()">Sign In</button>`;
    document.getElementById('myfilesTab').style.display = 'none';
  }

  // Upload gate
  const canUpload = mode === 'anonymous' || currentUser;
  document.getElementById('uploadGate').style.display = canUpload ? 'none' : '';
  document.getElementById('uploadForm').style.display = canUpload ? '' : 'none';
  document.getElementById('uploadTab').style.display = '';

  if (CONFIG?.limits?.maxFileSize) {
    document.getElementById('maxSizeHint').textContent = `Max ${fmtSize(CONFIG.limits.maxFileSize)} per file`;
  }

  // Load gallery or show auth gate
  if (mode === 'enforced-auth' && !currentUser) {
    document.getElementById('galleryGrid').innerHTML = '';
    document.getElementById('galleryEmpty').textContent = 'Sign in to browse files.';
    document.getElementById('galleryEmpty').style.display = '';
  } else {
    loadGallery();
  }

  // If mgmt token from URL, show my files tab
  if (currentMgmtToken && !currentUser) {
    document.getElementById('myfilesTab').style.display = '';
  }
}

// ── Tabs ──────────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('section').forEach(s => s.classList.remove('active'));
    tab.classList.add('active');
    const id = 'tab-' + tab.dataset.tab;
    document.getElementById(id).classList.add('active');
    if (tab.dataset.tab === 'myfiles') loadMyFiles();
  });
});

// ── Gallery ───────────────────────────────────────────────────────────────────
async function loadGallery(cursor = null) {
  try {
    const params = new URLSearchParams({ limit: 20 });
    if (cursor) params.set('before', cursor);
    const data = await api('GET', '/api/files?' + params);
    const grid = document.getElementById('galleryGrid');
    if (!cursor) grid.innerHTML = '';
    if (data.files.length === 0 && !cursor) {
      document.getElementById('galleryEmpty').style.display = '';
    } else {
      document.getElementById('galleryEmpty').style.display = 'none';
      data.files.forEach(f => grid.appendChild(makeFileCard(f)));
    }
    galleryCursor = data.nextCursor;
    document.getElementById('galleryMore').style.display = galleryCursor ? '' : 'none';
  } catch (e) {
    if (e.message.includes('Authentication')) {
      document.getElementById('galleryEmpty').textContent = 'Sign in to view files.';
      document.getElementById('galleryEmpty').style.display = '';
    }
  }
}
function loadMoreGallery() { if (galleryCursor) loadGallery(galleryCursor); }

function makeFileCard(f) {
  const card = document.createElement('div');
  card.className = 'file-card';
  const isImg = f.content_type?.startsWith('image/');
  const thumb = isImg
    ? `<img src="/api/files/${f.id}/content" alt="" loading="lazy" onerror="this.style.display='none'">`
    : `<span>${typeIcon(f.content_type)}</span>`;
  card.innerHTML = `
    <div class="file-thumb">${thumb}</div>
    <div class="file-info">
      <div class="file-name">${escapeHtml(f.original_name)}</div>
      <div class="file-meta">${fmtSize(f.size)} · ${new Date(f.uploaded_at).toLocaleDateString()}</div>
    </div>`;
  card.onclick = () => openFileModal(f.id, null);
  return card;
}

// ── My Files ──────────────────────────────────────────────────────────────────
async function loadMyFiles() {
  const container = document.getElementById('myfilesList');
  container.innerHTML = '<div class="spinner"></div>';
  try {
    const data = await api('GET', '/api/my-files');
    if (!data.files.length) {
      container.innerHTML = '<div class="empty">No uploads yet.</div>';
      return;
    }
    const ul = document.createElement('ul');
    ul.className = 'file-list';
    data.files.forEach(f => {
      const li = document.createElement('li');
      li.className = 'file-row';
      li.innerHTML = `
        <span>${typeIcon(f.content_type)}</span>
        <span class="name">${escapeHtml(f.original_name)}</span>
        <span class="vis-badge vis-${f.visibility}">${f.visibility}</span>
        <span class="meta">${fmtSize(f.size)}</span>
        <span class="meta">${new Date(f.uploaded_at).toLocaleDateString()}</span>`;
      li.onclick = () => openFileModal(f.id, null, true);
      ul.appendChild(li);
    });
    container.innerHTML = '';
    container.appendChild(ul);
  } catch (e) {
    container.innerHTML = `<div class="empty">Error: ${escapeHtml(e.message)}</div>`;
  }
}

// ── Upload ─────────────────────────────────────────────────────────────────────
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag');
  uploadFiles(Array.from(e.dataTransfer.files));
});
fileInput.addEventListener('change', () => { uploadFiles(Array.from(fileInput.files)); fileInput.value = ''; });

async function doUpload() {
  const files = fileInput.files.length ? Array.from(fileInput.files) : null;
  if (!files) { toast('Select files first'); return; }
  uploadFiles(files);
}

async function uploadFiles(files) {
  if (!files.length) return;
  const vis = document.getElementById('visSelect').value;
  const expInput = document.getElementById('expiresInput').value;
  const expiresAt = expInput ? new Date(expInput).getTime() : null;
  const progressList = document.getElementById('progressList');

  const mgmtWarnings = [];
  for (const file of files) {
    const item = document.createElement('div');
    item.className = 'progress-item';
    item.innerHTML = `<span style="flex:0 0 auto;font-size:0.85rem;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(file.name)}</span><div class="progress-bar-wrap"><div class="progress-bar" id="pb-${file.name.replace(/\W/g,'_')}"></div></div><span id="ps-${file.name.replace(/\W/g,'_')}" style="font-size:0.8rem;min-width:40px">0%</span>`;
    progressList.appendChild(item);

    const fd = new FormData();
    fd.append('files', file);
    fd.append('visibility', vis);
    if (expiresAt) fd.append('expiresAt', expiresAt);

    const pbId = 'pb-' + file.name.replace(/\W/g,'_');
    const psId = 'ps-' + file.name.replace(/\W/g,'_');
    const bar = document.getElementById(pbId);
    const status = document.getElementById(psId);

    try {
      // Use XHR for progress
      const result = await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/files');
        if (currentMgmtToken) xhr.setRequestHeader('x-management-token', currentMgmtToken);
        xhr.upload.onprogress = e => {
          if (e.lengthComputable) {
            const pct = Math.round(e.loaded / e.total * 100);
            if (bar) bar.style.width = pct + '%';
            if (status) status.textContent = pct + '%';
          }
        };
        xhr.onload = () => {
          if (xhr.status === 201) resolve(JSON.parse(xhr.responseText));
          else reject(new Error(JSON.parse(xhr.responseText).error || xhr.statusText));
        };
        xhr.onerror = () => reject(new Error('Network error'));
        xhr.send(fd);
      });

      if (bar) bar.style.width = '100%';
      if (status) status.textContent = '✓';

      // Collect management warnings for anonymous uploads
      if (result.files?.[0]?.managementToken) {
        const f = result.files[0];
        mgmtWarnings.push({ name: file.name, token: f.managementToken, url: f.managementUrl, shareUrl: f.shareUrl });
      }
    } catch (e) {
      if (status) status.textContent = '✗';
      toast('Upload failed: ' + e.message);
    }
  }

  // Show management tokens in a modal
  if (mgmtWarnings.length) {
    const modal = document.getElementById('fileModal');
    const title = document.getElementById('modalTitle');
    const preview = document.getElementById('previewArea');
    const shareBox = document.getElementById('shareBox');
    const actions = document.getElementById('modalActions');
    const mgmtBox = document.getElementById('mgmtBox');
    const meta = document.getElementById('metaTable');

    title.textContent = 'Upload complete — save your management tokens!';
    preview.innerHTML = '';
    shareBox.style.display = 'none';
    meta.innerHTML = '';
    actions.innerHTML = '<button class="btn btn-primary" onclick="closeModal()">OK, I saved them</button>';

    let html = '<p style="margin-bottom:8px;font-weight:600">⚠ These tokens are shown ONCE. Save them securely to manage your uploads.</p>';
    for (const w of mgmtWarnings) {
      html += `<div style="margin-bottom:12px;padding:8px;background:#fff8e1;border-radius:6px">
        <strong>${escapeHtml(w.name)}</strong><br>
        <span style="font-size:0.8rem">Management token (save this!):</span><br>
        <code style="font-size:0.8rem;word-break:break-all">${escapeHtml(w.token)}</code><br>
        <span style="font-size:0.8rem">Management URL: </span>
        <a href="${escapeHtml(w.url)}" style="font-size:0.8rem">${escapeHtml(w.url)}</a><br>
        <span style="font-size:0.8rem">Share link: </span>
        <a href="${escapeHtml(w.shareUrl)}" style="font-size:0.8rem">${escapeHtml(w.shareUrl)}</a>
      </div>`;
    }
    mgmtBox.innerHTML = html;
    mgmtBox.style.display = '';
    modal.style.display = 'flex';
  }

  // Refresh gallery
  setTimeout(() => loadGallery(), 500);
}

// ── File modal ────────────────────────────────────────────────────────────────
async function openFileModal(id, shareToken, isOwner) {
  const modal = document.getElementById('fileModal');
  const title = document.getElementById('modalTitle');
  const preview = document.getElementById('previewArea');
  const shareBox = document.getElementById('shareBox');
  const actions = document.getElementById('modalActions');
  const mgmtBox = document.getElementById('mgmtBox');
  const meta = document.getElementById('metaTable');

  title.textContent = 'Loading…';
  preview.innerHTML = '';
  shareBox.style.display = 'none';
  actions.innerHTML = '';
  mgmtBox.style.display = 'none';
  meta.innerHTML = '';
  modal.style.display = 'flex';

  try {
    const params = shareToken ? `?share=${encodeURIComponent(shareToken)}` : '';
    const f = await api('GET', `/api/files/${id}${params}`);

    title.textContent = f.originalName;

    // Preview
    const contentUrl = `/api/files/${id}/content${params}`;
    const ct = f.contentType || '';
    if (ct.startsWith('image/')) {
      preview.innerHTML = `<img src="${contentUrl}" class="preview" alt="">`;
    } else if (ct.startsWith('video/')) {
      preview.innerHTML = `<video controls class="preview"><source src="${contentUrl}"></video>`;
    } else if (ct.startsWith('audio/')) {
      preview.innerHTML = `<audio controls class="preview"><source src="${contentUrl}"></audio>`;
    } else if (ct === 'application/pdf') {
      preview.innerHTML = `<iframe src="${contentUrl}#toolbar=0" class="preview"></iframe>`;
    } else if (ct === 'text/plain' && f.size < 1048576) {
      try {
        const text = await fetch(contentUrl).then(r => r.text());
        preview.innerHTML = `<pre class="preview">${escapeHtml(text)}</pre>`;
      } catch {}
    }

    // Metadata table
    meta.innerHTML = `
      <tr><td>Size</td><td>${fmtSize(f.size)}</td></tr>
      <tr><td>Type</td><td>${escapeHtml(f.contentType)}</td></tr>
      <tr><td>Visibility</td><td><span class="vis-badge vis-${f.visibility}">${f.visibility}</span></td></tr>
      <tr><td>Uploaded</td><td>${fmtDate(f.uploadedAt)}</td></tr>
      <tr><td>Expires</td><td>${fmtDate(f.expiresAt)}</td></tr>
    `;

    // Share box
    if (shareToken) {
      const shareUrl = window.location.origin + '/share/' + shareToken;
      shareBox.innerHTML = `<strong>Share link:</strong><br><a href="${escapeHtml(shareUrl)}" target="_blank" rel="noopener">${escapeHtml(shareUrl)}</a>
        <button class="btn-small btn-secondary" style="margin-left:8px" onclick="copy('${escapeHtml(shareUrl)}')">Copy</button>`;
      shareBox.style.display = '';
    }

    // Actions
    const btns = [];
    btns.push(`<a href="${contentUrl}" download="${escapeHtml(f.originalName)}" class="btn btn-primary btn-small">Download</a>`);

    if (f.isOwner || isOwner) {
      btns.push(`<button class="btn btn-secondary btn-small" onclick="revokeLink('${id}')">New Share Link</button>`);
      const togVis = f.visibility === 'public' ? 'private' : 'public';
      btns.push(`<button class="btn btn-secondary btn-small" onclick="toggleVisibility('${id}','${togVis}')">Make ${togVis}</button>`);
      btns.push(`<button class="btn btn-danger btn-small" onclick="deleteFile('${id}')">Delete</button>`);
    }

    actions.innerHTML = btns.join('');
  } catch (e) {
    title.textContent = 'Error';
    preview.innerHTML = `<p style="color:#c0392b">${escapeHtml(e.message)}</p>`;
    if (e.message.includes('Authentication')) {
      actions.innerHTML = '<button class="btn btn-primary" onclick="startLogin()">Sign In</button>';
    }
  }
}

function closeModal() {
  document.getElementById('fileModal').style.display = 'none';
}
document.getElementById('fileModal').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeModal();
});

// ── Owner actions ─────────────────────────────────────────────────────────────
async function revokeLink(id) {
  try {
    const data = await api('POST', `/api/files/${id}/revoke-link`);
    const url = window.location.origin + data.shareUrl;
    toast('New share link generated!');
    document.getElementById('shareBox').innerHTML = `<strong>New share link:</strong><br>
      <a href="${escapeHtml(url)}">${escapeHtml(url)}</a>
      <button class="btn-small btn-secondary" style="margin-left:8px" onclick="copy('${escapeHtml(url)}')">Copy</button>`;
    document.getElementById('shareBox').style.display = '';
  } catch (e) { toast('Failed: ' + e.message); }
}

async function toggleVisibility(id, newVis) {
  try {
    await api('PUT', `/api/files/${id}`, { visibility: newVis });
    toast('Visibility updated');
    closeModal();
    loadGallery();
    loadMyFiles();
  } catch (e) { toast('Failed: ' + e.message); }
}

async function deleteFile(id) {
  if (!confirm('Delete this file permanently?')) return;
  try {
    await api('DELETE', `/api/files/${id}`);
    toast('Deleted');
    closeModal();
    loadGallery();
    loadMyFiles();
  } catch (e) { toast('Failed: ' + e.message); }
}

function copy(text) {
  navigator.clipboard.writeText(text).then(() => toast('Copied!')).catch(() => toast('Copy failed'));
}

function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Start ─────────────────────────────────────────────────────────────────────
init().catch(console.error);
