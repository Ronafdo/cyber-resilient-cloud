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
    $('chain-count').textContent = health.chain_length;
    $('blocked-count').textContent = data.blocked_ips.length;
    state.chainEntries = data.chain_blocks.slice(-6);
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
    const response = await fetch('/shield/ingest', { method: 'POST' });
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
    `<tr><td><span class="pill">${escapeHtml(item.decision.reason)}</span></td><td>10.0.0.1</td><td>${escapeHtml(item.chain_length)}</td></tr>`
  ).join('') || '<tr><td class="empty" colspan="3">No traffic events yet</td></tr>';
  $('integrity-body').innerHTML = state.integrityStatus.slice(-5).reverse().map((item) =>
    `<tr><td>${escapeHtml(item.file)}</td><td><span class="pill">${escapeHtml(item.status)}</span></td></tr>`
  ).join('') || '<tr><td class="empty" colspan="2">No integrity events yet</td></tr>';
  $('chain-body').innerHTML = state.chainEntries.slice().reverse().map((item) =>
    `<tr><td>${escapeHtml(item.event)}</td><td>${escapeHtml(item.payload?.source_ip || 'system')}</td><td>${escapeHtml(item.payload?.allowed === false ? 'Request blocked' : 'Hash verified')}</td></tr>`
  ).join('') || '<tr><td class="empty" colspan="3">No audit activity yet</td></tr>';
}

$('simulate-traffic').addEventListener('click', (event) => postEvent(event.currentTarget));
$('simulate-tamper').addEventListener('click', (event) => postEvent(event.currentTarget, () => ({
  file: 'sample.txt', status: 'simulated'
})));
refreshData();
