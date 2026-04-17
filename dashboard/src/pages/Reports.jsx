import React, { useState, useEffect } from 'react';
import { apiFetch } from '../lib/api.js';

export default function Reports() {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState('');
  const [report, setReport] = useState(null);
  const [triage, setTriage] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => { apiFetch('/scans').then(setScans).catch(() => {}); }, []);

  const generateReport = async () => {
    if (!selectedScan) return;
    setLoading(true);
    try {
      const data = await apiFetch(`/scan/${selectedScan}/report`, { method: 'POST' });
      setReport(data);
    } catch {}
    setLoading(false);
  };

  const runTriage = async () => {
    if (!selectedScan) return;
    try {
      const data = await apiFetch(`/scan/${selectedScan}/triage`, { method: 'POST' });
      setTriage(data);
    } catch {}
  };

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">📊 Reports</h2>

      <div className="flex gap-4 items-end">
        <select value={selectedScan} onChange={e => setSelectedScan(e.target.value)}
          className="px-3 py-2 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded-lg text-sm">
          <option value="">Select scan...</option>
          {scans.map(s => <option key={s.id} value={s.id}>{s.id} — {s.target}</option>)}
        </select>
        <button onClick={generateReport} disabled={!selectedScan || loading}
          className="px-4 py-2 bg-[var(--wb-red)] text-white rounded-lg text-sm font-medium hover:bg-red-600 disabled:opacity-50">
          {loading ? 'Generating...' : '📄 Generate Report'}
        </button>
        <button onClick={runTriage} disabled={!selectedScan}
          className="px-4 py-2 bg-[var(--wb-cyan)] text-black rounded-lg text-sm font-medium hover:bg-cyan-400 disabled:opacity-50">
          🤖 AI Triage
        </button>
      </div>

      {/* Report */}
      {report && (
        <div className="space-y-4">
          <div className="bg-[var(--wb-surface)] rounded-lg p-4 border border-[var(--wb-border)]">
            <h3 className="text-lg font-semibold mb-3">Scan Report — {report.scanId}</h3>
            <div className="grid grid-cols-3 gap-4 text-sm mb-4">
              <div><span className="text-[var(--wb-muted)]">Target:</span> {report.target}</div>
              <div><span className="text-[var(--wb-muted)]">Status:</span> {report.status}</div>
              <div><span className="text-[var(--wb-muted)]">Total Findings:</span> {report.totalFindings}</div>
            </div>
            {report.bySeverity && (
              <div className="flex gap-3 mb-3">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(sev => (
                  report.bySeverity[sev] ? (
                    <span key={sev} className={`px-2 py-1 rounded text-xs font-bold sev-badge-${sev.toLowerCase()}`}>
                      {sev}: {report.bySeverity[sev]}
                    </span>
                  ) : null
                ))}
              </div>
            )}
            {report.byType && (
              <div className="text-sm">
                <span className="text-[var(--wb-muted)]">By Type: </span>
                {Object.entries(report.byType).map(([t, c]) => `${t} (${c})`).join(', ')}
              </div>
            )}
          </div>
        </div>
      )}

      {/* AI Triage */}
      {triage && (
        <div className="bg-[var(--wb-surface)] rounded-lg p-4 border border-[var(--wb-border)]">
          <h3 className="text-lg font-semibold mb-3">🤖 AI Triage {triage.aiTriaged ? '(AI-Powered)' : '(Rule-Based Fallback)'}</h3>
          {triage.analysis?.executive_summary && (
            <div className="mb-3 text-sm bg-black/30 rounded p-3">{triage.analysis.executive_summary}</div>
          )}
          {triage.analysis?.attack_narrative && (
            <div className="mb-3">
              <h4 className="font-medium text-sm mb-1">Attack Narrative</h4>
              <p className="text-sm text-[var(--wb-muted)]">{triage.analysis.attack_narrative}</p>
            </div>
          )}
          {triage.analysis?.prioritized && (
            <div>
              <h4 className="font-medium text-sm mb-1">Prioritized Findings</h4>
              <div className="space-y-1">
                {triage.analysis.prioritized.slice(0, 10).map((p, i) => (
                  <div key={i} className="flex gap-2 text-sm">
                    <span className={`font-bold ${p.priority === 'P1' ? 'text-[var(--wb-red)]' : p.priority === 'P2' ? 'text-[var(--wb-yellow)]' : 'text-[var(--wb-muted)]'}`}>{p.priority}</span>
                    <span className="text-[var(--wb-muted)]">{p.reason}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}