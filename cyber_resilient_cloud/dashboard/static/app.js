const state = { trafficEvents: [], integrityStatus: [], chainEntries: [] };

const $ = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
}[char]));

function showToast(message) {
  const toast = $('toast');
  toast.textContent = message;
  toast.classList.add('show');
  window.setTimeout(() => toast.classList.remove('show'), 2200);
}

async function refreshData() {
  try {
    const [healthResponse, dataResponse] = await Promise.all([fetch('/health'), fetch('/dashboard/data')]);
    if (!healthResponse.ok || !dataResponse.ok) throw new Error('Backend request failed');
    const health = await healthResponse.json();
    const data = await dataResponse.json();
    $('health-status').textContent = health.status.toUpperCase();
    $('shield-count').textContent = health.shield_events;
    $('chain-count').textContent = data.chain_blocks.length;
    $('blocked-count').textContent = data.blocked_ips.length;
    state.chainEntries = data.chain_blocks.slice(-6);
    state.files = data.files || [];
    $('refresh-label').textContent = `Updated ${new Date().toLocaleTimeString()}`;
    render();
  } catch (error) {
    $('health-status').textContent = 'OFFLINE';
    $('refresh-label').textContent = 'Unable to reach backend';
    showToast('Could not refresh security data');
  }
}

async function postEvent(button, message) {
  button.disabled = true;
  try {
    const response = await fetch('/shield/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        protocol: 'tcp',
        packet_size: 1500,
        tcp_flags: 'SYN',
        http_entropy: 0.7
      })
    });
    if (!response.ok) throw new Error('Event request failed');
    const data = await response.json();
    state.trafficEvents.push(data);
    if (message) state.integrityStatus.push(message(data));
    showToast('Security event recorded');
    await refreshData();
  } catch (error) {
    showToast('The event could not be recorded');
  } finally {
    button.disabled = false;
  }
}

function render() {
  $('traffic-body').innerHTML = state.trafficEvents.slice(-5).reverse().map((item) =>
    `<tr><td><span class="pill">${escapeHtml(item.decision.reason)}</span></td><td>${escapeHtml(item.decision.source_ip || 'client')}</td><td>${escapeHtml(item.chain_length)}</td></tr>`
  ).join('') || '<tr><td class="empty" colspan="3">No traffic events yet</td></tr>';
  $('integrity-body').innerHTML = state.integrityStatus.slice(-5).reverse().map((item) =>
    `<tr><td>${escapeHtml(item.file)}</td><td><span class="pill">${escapeHtml(item.status)}</span></td></tr>`
  ).join('') || '<tr><td class="empty" colspan="2">No integrity events yet</td></tr>';
  $('chain-body').innerHTML = state.chainEntries.slice().reverse().map((item) =>
    `<tr><td>${escapeHtml(item.event)}</td><td>${escapeHtml(item.payload?.source_ip || item.payload?.filename || 'system')}</td><td>${escapeHtml(item.payload?.allowed === false ? 'Request blocked' : 'Hash verified')}</td></tr>`
  ).join('') || '<tr><td class="empty" colspan="3">No audit activity yet</td></tr>';
  $('files-body').innerHTML = (state.files || []).map((file) =>
    `<tr><td>${escapeHtml(file.filename)}</td><td>${formatBytes(file.plaintext_size)}</td><td>${new Date(file.created_at * 1000).toLocaleString()}</td><td><button class="secondary download-file" data-id="${escapeHtml(file.id)}">Download</button></td></tr>`
  ).join('') || '<tr><td class="empty" colspan="4">No encrypted files uploaded yet</td></tr>';
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}

function bytesToBase64(bytes) {
  let binary = '';
  bytes.forEach((value) => { binary += String.fromCharCode(value); });
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

async function deriveBrowserKey(password, salt) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptFile(file, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveBrowserKey(password, salt);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, await file.arrayBuffer()));
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', await file.arrayBuffer()));
  return { ciphertext, salt, nonce, plaintextHash: Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('') };
}

async function uploadFile() {
  const file = $('file-input').files[0];
  const password = $('file-password').value;
  if (!file || !password) return showToast('Choose a file and enter a password');
  if (file.size > 25 * 1024 * 1024) return showToast('Files are limited to 25 MB');
  const button = $('upload-file');
  button.disabled = true;
  try {
    const encrypted = await encryptFile(file, password);
    const response = await fetch('/files', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
      filename: file.name, mime_type: file.type || 'application/octet-stream', plaintext_size: file.size,
      plaintext_hash: encrypted.plaintextHash, salt: bytesToBase64(encrypted.salt),
      nonce: bytesToBase64(encrypted.nonce), ciphertext: bytesToBase64(encrypted.ciphertext)
    }) });
    if (!response.ok) throw new Error('upload failed');
    $('file-input').value = ''; $('file-password').value = '';
    showToast('Encrypted file stored successfully');
    await refreshData();
  } catch (error) {
    showToast('Encrypted upload failed');
  } finally { button.disabled = false; }
}

async function downloadFile(fileId) {
  const password = $('file-password').value;
  if (!password) return showToast('Enter the file password first');
  try {
    const response = await fetch(`/files/${fileId}/download`);
    if (!response.ok) throw new Error('download failed');
    const encrypted = new Uint8Array(await response.arrayBuffer());
    const key = await deriveBrowserKey(password, base64ToBytes(response.headers.get('X-Salt')));
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBytes(response.headers.get('X-Nonce')) }, key, encrypted);
    const blob = new Blob([plaintext], { type: response.headers.get('X-Mime-Type') || 'application/octet-stream' });
    const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = response.headers.get('X-File-Name') || 'download'; link.click(); URL.revokeObjectURL(link.href);
    showToast('File decrypted and downloaded');
  } catch (error) { showToast('Unable to decrypt file: check the password or integrity'); }
}

$('simulate-traffic').addEventListener('click', (event) => postEvent(event.currentTarget));
$('simulate-tamper').addEventListener('click', async () => {
  const files = state.files || [];
  if (!files.length) return showToast('Upload an encrypted file first');
  const result = await fetch(`/files/${files[0].id}/verify`, { method: 'POST' }).then((response) => response.json());
  showToast(result.valid ? 'Encrypted blob integrity verified' : 'Tampering detected');
});
$('upload-file').addEventListener('click', uploadFile);
$('files-body').addEventListener('click', (event) => {
  if (event.target.classList.contains('download-file')) downloadFile(event.target.dataset.id);
});
refreshData();
