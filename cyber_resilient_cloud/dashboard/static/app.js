const state = {
  trafficEvents: [],
  integrityStatus: [],
  chainEntries: [],
  activity: []
};

async function refreshData() {
  const healthResponse = await fetch('/health');
  const healthData = await healthResponse.json();
  document.getElementById('health-status').textContent = healthData.status;
  document.getElementById('shield-count').textContent = healthData.shield_events;
  document.getElementById('chain-count').textContent = healthData.chain_length;

  const dataResponse = await fetch('/dashboard/data');
  const data = await dataResponse.json();
  state.chainEntries = data.chain_blocks.slice(-5);
  state.activity = [
    { action: 'Health check', detail: 'Dashboard loaded from backend' },
    ...state.chainEntries.slice(-3).map((item) => ({ action: item.event, detail: item.payload?.source_ip || 'audit event' })),
    ...state.trafficEvents.slice(-2).map((item) => ({ action: 'Shield ingest', detail: item.decision.reason }))
  ].slice(-6);
  render();
}

async function loadDashboard() {
  document.getElementById('simulate-traffic').addEventListener('click', async () => {
    const response = await fetch('/shield/ingest', { method: 'POST' });
    const data = await response.json();
    state.trafficEvents.push(data);
    await refreshData();
  });

  document.getElementById('simulate-tamper').addEventListener('click', async () => {
    const response = await fetch('/shield/ingest', { method: 'POST' });
    const data = await response.json();
    state.integrityStatus.push({ file: 'sample.txt', status: 'Tamper simulated', decision: data.decision.reason });
    await refreshData();
  });

  await refreshData();
}

function render() {
  const trafficRows = state.trafficEvents
    .slice(-5)
    .map((item) => `<tr><td>${item.decision.reason}</td><td>${item.chain_length}</td></tr>`)
    .join('');
  document.getElementById('traffic-body').innerHTML = trafficRows;

  const integrityRows = state.integrityStatus
    .slice(-5)
    .map((item) => `<tr><td>${item.file}</td><td>${item.status}</td><td>${item.decision}</td></tr>`)
    .join('');
  document.getElementById('integrity-body').innerHTML = integrityRows;

  const activityRows = state.activity
    .slice(-6)
    .map((item) => `<tr><td>${item.action}</td><td>${item.detail}</td></tr>`)
    .join('');
  document.getElementById('activity-body').innerHTML = activityRows;

  const chainRows = state.chainEntries
    .slice(-5)
    .map((item) => `<tr><td>${item.event}</td><td>${item.payload?.source_ip || 'n/a'}</td></tr>`)
    .join('');
  document.getElementById('chain-body').innerHTML = chainRows;
}

loadDashboard();
