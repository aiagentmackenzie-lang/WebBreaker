import React, { useState, useEffect } from 'react';
import { apiFetch } from '../lib/api.js';
import SeverityBadge from '../components/SeverityBadge.jsx';

export default function Findings() {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState('');
  const [findings, setFindings] = useState([]);
  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  useEffect(() => {
    apiFetch('/scans').then(setScans).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedScan) return;
    const path = severityFilter ? `/scan/${selectedScan}/findings?severity=${severityFilter}` : `/scan/${selectedScan}/findings`;
    apiFetch(path).then(setFindings).catch(() => setFindings([]));
  }, [selectedScan, severityFilter]);

  const filtered = findings.filter(f =>
    !filter || f.url.toLowerCase().includes(filter.toLowerCase()) || f.type.toLowerCase().includes(filter.toLowerCase()) || f.evidence.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">🚨 Findings</h2>

      {/* Filters */}
      <div className="flex gap-4 items-end">
        <div>
          <label className="block text-sm mb-1">Scan</label>
          <select value={selectedScan} onChange={e => setSelectedScan(e.target.value)}
            className="px-3 py-2 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded-lg text-sm">
            <option value="">Select scan...</option>
            {scans.map(s => <option key={s.id} value={s.id}>{s.id} — {s.target}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-sm mb-1">Severity</label>
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
            className="px-3 py-2 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded-lg text-sm">
            <option value="">All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>
        <div className="flex-1">
          <label className="block text-sm mb-1">Search</label>
          <input type="text" value={filter} onChange={e => setFilter(e.target.value)} placeholder="URL, type, evidence..."
            className="w-full px-3 py-2 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded-lg text-sm" />
        </div>
      </div>

      {/* Table */}
      {filtered.length > 0 ? (
        <div className="overflow-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--wb-border)] text-left text-[var(--wb-muted)]">
                <th className="pb-2 pr-4">Severity</th>
                <th className="pb-2 pr-4">Type</th>
                <th className="pb-2 pr-4">URL</th>
                <th className="pb-2 pr-4">Parameter</th>
                <th className="pb-2 pr-4">Evidence</th>
                <th className="pb-2">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr key={f.id} className="border-b border-[var(--wb-border)]/50 hover:bg-white/5">
                  <td className="py-2 pr-4"><SeverityBadge severity={f.severity} /></td>
                  <td className="py-2 pr-4">{f.type}</td>
                  <td className="py-2 pr-4 font-mono text-xs max-w-xs truncate">{f.url}</td>
                  <td className="py-2 pr-4">{f.parameter}</td>
                  <td className="py-2 pr-4 max-w-md truncate">{f.evidence}</td>
                  <td className="py-2">{(f.confidence * 100).toFixed(0)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="text-[var(--wb-muted)]">{selectedScan ? 'No findings for this scan.' : 'Select a scan to view findings.'}</div>
      )}
    </div>
  );
}