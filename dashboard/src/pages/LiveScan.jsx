import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { apiFetch, wsConnect } from '../lib/api.js';
import SeverityBadge from '../components/SeverityBadge.jsx';
import ModuleStatus from '../components/ModuleStatus.jsx';
import FindingCard from '../components/FindingCard.jsx';
import StatsBar from '../components/StatsBar.jsx';

export default function LiveScan() {
  const [params] = useSearchParams();
  const scanId = params.get('scanId');
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [logs, setLogs] = useState([]);
  const [moduleStatuses, setModuleStatuses] = useState({});
  const wsRef = useRef(null);
  const logEndRef = useRef(null);

  useEffect(() => {
    if (!scanId) return;

    // Poll scan status
    const poll = setInterval(async () => {
      try {
        const data = await apiFetch(`/scan/${scanId}`);
        setScan(data);
        const f = await apiFetch(`/scan/${scanId}/findings`);
        setFindings(f);
      } catch { /* ignore */ }
    }, 3000);

    // WebSocket for live updates
    wsRef.current = wsConnect(scanId, (msg) => {
      if (msg.type === 'progress') {
        setLogs(prev => [...prev.slice(-200), msg.data]);
        // Parse module from log
        const moduleMatch = msg.data.match(/Running (\w+)/i);
        if (moduleMatch) setModuleStatuses(prev => ({ ...prev, [moduleMatch[1].toLowerCase()]: 'running' }));
        const doneMatch = msg.data.match(/✓ (\w+)/);
        if (doneMatch) setModuleStatuses(prev => ({ ...prev, [doneMatch[1].toLowerCase()]: 'done' }));
      }
      if (msg.type === 'complete') {
        setScan(prev => prev ? { ...prev, status: 'completed' } : null);
      }
    });

    return () => { clearInterval(poll); wsRef.current?.close(); };
  }, [scanId]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  if (!scanId) return <div className="text-[var(--wb-muted)]">No active scan. Start one from the New Scan page.</div>;

  const bySeverity = {};
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">📡 Live Scan</h2>
        <div className="text-sm text-[var(--wb-muted)]">
          Scan ID: <span className="font-mono text-[var(--wb-text)]">{scanId}</span>
          {scan && <span className="ml-3">Status: <span className={scan.status === 'completed' ? 'text-[var(--wb-green)]' : 'text-[var(--wb-yellow)]'}>{scan.status}</span></span>}
        </div>
      </div>

      {/* Stats */}
      <StatsBar findings={findings} />

      {/* Module statuses */}
      <ModuleStatus statuses={moduleStatuses} />

      {/* Findings */}
      <div>
        <h3 className="text-lg font-semibold mb-3">🚨 Findings ({findings.length})</h3>
        <div className="space-y-2 max-h-96 overflow-auto">
          {findings.map((f, i) => <FindingCard key={i} finding={f} />)}
          {!findings.length && <div className="text-[var(--wb-muted)] text-sm">No findings yet...</div>}
        </div>
      </div>

      {/* Live log */}
      <div>
        <h3 className="text-lg font-semibold mb-3">📋 Scan Log</h3>
        <div className="bg-black/50 rounded-lg p-3 font-mono text-xs text-green-400 h-64 overflow-auto">
          {logs.map((log, i) => <div key={i}>{log}</div>)}
          <div ref={logEndRef} />
        </div>
      </div>
    </div>
  );
}