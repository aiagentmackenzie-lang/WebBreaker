import React, { useState, useEffect } from 'react';
import { apiFetch } from '../lib/api.js';

export default function Recon() {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState('');
  const [recon, setRecon] = useState([]);

  useEffect(() => { apiFetch('/scans').then(setScans).catch(() => {}); }, []);

  useEffect(() => {
    if (!selectedScan) return;
    apiFetch(`/scan/${selectedScan}/recon`).then(setRecon).catch(() => setRecon([]));
  }, [selectedScan]);

  const allTech = [...new Set(recon.flatMap(r => r.tech?.split(',') || []))].filter(Boolean);

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">🗺️ Recon</h2>

      <div>
        <select value={selectedScan} onChange={e => setSelectedScan(e.target.value)}
          className="px-3 py-2 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded-lg text-sm">
          <option value="">Select scan...</option>
          {scans.map(s => <option key={s.id} value={s.id}>{s.id} — {s.target}</option>)}
        </select>
      </div>

      {/* Tech stack */}
      {allTech.length > 0 && (
        <div>
          <h3 className="text-lg font-semibold mb-2">🛠️ Detected Technologies</h3>
          <div className="flex flex-wrap gap-2">
            {allTech.map(t => <span key={t} className="px-2 py-1 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded text-xs">{t}</span>)}
          </div>
        </div>
      )}

      {/* URLs discovered */}
      <div>
        <h3 className="text-lg font-semibold mb-2">🌐 Discovered URLs ({recon.length})</h3>
        <div className="space-y-1 max-h-96 overflow-auto">
          {recon.map((r, i) => (
            <div key={i} className="flex items-center gap-3 py-1.5 px-3 bg-[var(--wb-surface)] rounded text-sm">
              <span className={`font-mono text-xs px-1.5 py-0.5 rounded ${r.status_code >= 400 ? 'bg-[var(--wb-red)]/20 text-[var(--wb-red)]' : 'bg-[var(--wb-green)]/20 text-[var(--wb-green)]'}`}>
                {r.status_code || '---'}
              </span>
              <span className="font-mono text-xs flex-1 truncate">{r.url}</span>
              <span className="text-xs text-[var(--wb-muted)]">{r.method}</span>
              <span className="text-xs text-[var(--wb-muted)]">{r.content_length || 0}B</span>
              <span className="text-xs text-[var(--wb-muted)]">d{r.depth}</span>
            </div>
          ))}
        </div>
      </div>

      {!selectedScan && <div className="text-[var(--wb-muted)]">Select a scan to view recon data.</div>}
    </div>
  );
}