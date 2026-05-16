import React, { useState, useEffect } from 'react';
import { apiFetch } from '../lib/api.js';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  INFO: '#6b7280',
};

export default function Reports() {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState('');
  const [report, setReport] = useState(null);
  const [triage, setTriage] = useState(null);
  const [reportFormat, setReportFormat] = useState('json');
  const [loading, setLoading] = useState(false);

  useEffect(() => { apiFetch('/scans').then(setScans).catch(() => {}); }, []);

  const generateReport = async () => {
    if (!selectedScan) return;
    setLoading(true);
    try {
      const data = await apiFetch(`/scan/${selectedScan}/report`, {
        method: 'POST',
        body: JSON.stringify({ format: reportFormat }),
      });
      setReport(data);
      setTriage(null);
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

  const downloadReport = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `webbreaker-report-${selectedScan}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const severityBadge = (sev, count) => (
    <span key={sev} className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm font-bold"
      style={{ backgroundColor: `${SEVERITY_COLORS[sev] || '#6b7280'}22`, color: SEVERITY_COLORS[sev] || '#6b7280', border: `1px solid ${SEVERITY_COLORS[sev] || '#6b7280'}44` }}>
      {sev}: {count}
    </span>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">📊 Reports</h2>
        {report && (
          <button onClick={downloadReport}
            className="px-4 py-2 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded-lg text-sm font-medium hover:bg-white/10 transition-colors">
            ⬇ Download JSON
          </button>
        )}
      </div>

      {/* Controls */}
      <div className="flex flex-wrap gap-4 items-end">
        <div className="flex flex-col gap-1">
          <label className="text-xs text-[var(--wb-muted)]">Scan</label>
          <select value={selectedScan} onChange={e => setSelectedScan(e.target.value)}
            className="px-3 py-2 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded-lg text-sm min-w-[240px]">
            <option value="">Select scan...</option>
            {scans.map(s => (
              <option key={s.id} value={s.id}>
                {s.id} — {s.target} ({s.status})
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-col gap-1">
          <label className="text-xs text-[var(--wb-muted)]">Format</label>
          <select value={reportFormat} onChange={e => setReportFormat(e.target.value)}
            className="px-3 py-2 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded-lg text-sm">
            <option value="json">JSON</option>
            <option value="stix">STIX 2.1</option>
          </select>
        </div>

        <button onClick={generateReport} disabled={!selectedScan || loading}
          className="px-4 py-2 bg-[var(--wb-red)] text-white rounded-lg text-sm font-medium hover:bg-red-600 disabled:opacity-50 transition-colors">
          {loading ? '⏳ Generating...' : '📄 Generate Report'}
        </button>

        <button onClick={runTriage} disabled={!selectedScan}
          className="px-4 py-2 bg-[var(--wb-cyan)] text-black rounded-lg text-sm font-medium hover:bg-cyan-400 disabled:opacity-50 transition-colors">
          🤖 AI Triage
        </button>
      </div>

      {/* Report Summary */}
      {report && (
        <div className="space-y-4">
          <div className="bg-[var(--wb-surface)] rounded-lg p-5 border border-[var(--wb-border)]">
            <h3 className="text-lg font-semibold mb-4">Scan Report — {report.scanId}</h3>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-5">
              <div className="bg-black/20 rounded-lg p-3">
                <div className="text-xs text-[var(--wb-muted)]">Target</div>
                <div className="text-sm font-mono truncate">{report.target}</div>
              </div>
              <div className="bg-black/20 rounded-lg p-3">
                <div className="text-xs text-[var(--wb-muted)]">Status</div>
                <div className="text-sm capitalize">{report.status}</div>
              </div>
              <div className="bg-black/20 rounded-lg p-3">
                <div className="text-xs text-[var(--wb-muted)]">Total Findings</div>
                <div className="text-2xl font-bold">{report.totalFindings}</div>
              </div>
              <div className="bg-black/20 rounded-lg p-3">
                <div className="text-xs text-[var(--wb-muted)]">URLs Discovered</div>
                <div className="text-2xl font-bold">{report.urlsDiscovered ?? '—'}</div>
              </div>
            </div>

            {report.bySeverity && (
              <div className="flex flex-wrap gap-2 mb-4">
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(sev =>
                  report.bySeverity[sev] ? severityBadge(sev, report.bySeverity[sev]) : null
                )}
              </div>
            )}

            {report.byType && Object.keys(report.byType).length > 0 && (
              <div className="text-sm text-[var(--wb-muted)]">
                <span className="font-medium text-white">By Type: </span>
                {Object.entries(report.byType).map(([t, c]) => `${t} (${c})`).join(' · ')}
              </div>
            )}
          </div>

          {/* Findings Table */}
          {report.findings && report.findings.length > 0 && (
            <div className="bg-[var(--wb-surface)] rounded-lg border border-[var(--wb-border)] overflow-hidden">
              <h4 className="text-sm font-semibold px-4 py-3 border-b border-[var(--wb-border)]">Findings Detail</h4>
              <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-[var(--wb-surface)]">
                    <tr className="border-b border-[var(--wb-border)]">
                      <th className="text-left px-4 py-2 text-[var(--wb-muted)]">Severity</th>
                      <th className="text-left px-4 py-2 text-[var(--wb-muted)]">Type</th>
                      <th className="text-left px-4 py-2 text-[var(--wb-muted)]">URL</th>
                      <th className="text-left px-4 py-2 text-[var(--wb-muted)]">Parameter</th>
                      <th className="text-left px-4 py-2 text-[var(--wb-muted)]">Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.findings.map((f, i) => (
                      <tr key={i} className="border-b border-[var(--wb-border)]/50 hover:bg-white/5">
                        <td className="px-4 py-2">
                          <span className="font-bold text-xs px-2 py-0.5 rounded"
                            style={{ color: SEVERITY_COLORS[f.severity] || '#6b7280' }}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="px-4 py-2">{f.type}</td>
                        <td className="px-4 py-2 font-mono text-xs max-w-[200px] truncate">{f.url}</td>
                        <td className="px-4 py-2">{f.parameter}</td>
                        <td className="px-4 py-2">
                          {f.confidence !== undefined ? `${(f.confidence * 100).toFixed(0)}%` : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* AI Triage */}
      {triage && (
        <div className="bg-[var(--wb-surface)] rounded-lg p-5 border border-[var(--wb-border)]">
          <h3 className="text-lg font-semibold mb-3">
            🤖 AI Triage {triage.aiTriaged ? '(AI-Powered)' : '(Rule-Based Fallback)'}
          </h3>
          {triage.analysis?.executive_summary && (
            <div className="mb-4 text-sm bg-black/30 rounded-lg p-4 border-l-4 border-[var(--wb-red)]">
              {triage.analysis.executive_summary}
            </div>
          )}
          {triage.analysis?.attack_narrative && (
            <div className="mb-4">
              <h4 className="font-medium text-sm mb-1">Attack Narrative</h4>
              <p className="text-sm text-[var(--wb-muted)]">{triage.analysis.attack_narrative}</p>
            </div>
          )}
          {triage.analysis?.prioritized && (
            <div>
              <h4 className="font-medium text-sm mb-2">Prioritized Findings</h4>
              <div className="space-y-1">
                {triage.analysis.prioritized.slice(0, 15).map((p) => (
                  <div key={p.index} className="flex gap-2 text-sm py-1 px-2 rounded hover:bg-white/5">
                    <span className={`font-bold min-w-[28px] ${p.priority === 'P1' ? 'text-[var(--wb-red)]' : p.priority === 'P2' ? 'text-[var(--wb-yellow)]' : 'text-[var(--wb-muted)]'}`}>
                      {p.priority}
                    </span>
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