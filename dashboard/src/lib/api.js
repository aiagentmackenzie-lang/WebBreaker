const API_BASE = '/api';

export async function apiFetch(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`);
  return res.json();
}

export function wsConnect(scanId, onMessage) {
  const ws = new WebSocket(`ws://${location.host}/ws`);
  ws.onopen = () => ws.send(JSON.stringify({ type: 'subscribe', scanId }));
  ws.onmessage = (e) => {
    try { onMessage(JSON.parse(e.data)); } catch { /* ignore */ }
  };
  return ws;
}