import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiFetch } from '../lib/api.js';

const MODULES = [
  { id: 'recon', label: 'Recon & Spider', desc: 'URL discovery, forms, tech fingerprint', checked: true },
  { id: 'sqli', label: 'SQL Injection', desc: 'Error, boolean, time-based, UNION, OOB', checked: true },
  { id: 'xss', label: 'XSS', desc: 'Reflected, stored, DOM-based', checked: true },
  { id: 'csrf', label: 'CSRF', desc: 'Missing tokens, SameSite, PoC builder', checked: true },
  { id: 'cmdi', label: 'Command Injection', desc: 'OS command injection (Linux + Windows)', checked: true },
  { id: 'lfi', label: 'LFI', desc: 'Path traversal, PHP wrappers', checked: true },
  { id: 'rfi', label: 'RFI', desc: 'Remote file inclusion', checked: false },
  { id: 'dirbrute', label: 'Dir Brute Force', desc: 'Directory & file discovery', checked: true },
  { id: 'fuzz', label: 'Parameter Fuzz', desc: 'Hidden params, anomaly detection', checked: false },
  { id: 'headers', label: 'Security Headers', desc: '25+ headers, CSP analysis, grading', checked: true },
  { id: 'session', label: 'Session Analysis', desc: 'Cookie security, entropy, fixation', checked: true },
];

export default function NewScan() {
  const navigate = useNavigate();
  const [target, setTarget] = useState('');
  const [modules, setModules] = useState(MODULES.filter(m => m.checked).map(m => m.id));
  const [depth, setDepth] = useState(3);
  const [threads, setThreads] = useState(20);
  const [stealth, setStealth] = useState(false);
  const [proxy, setProxy] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const toggleModule = (id) => {
    setModules(prev => prev.includes(id) ? prev.filter(m => m !== id) : [...prev, id]);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!target) return setError('Target URL is required');
    setLoading(true);
    setError('');

    try {
      const result = await apiFetch('/scan', {
        method: 'POST',
        body: JSON.stringify({ target, modules: modules.join(','), depth, threads, stealth: stealth || undefined, proxy: proxy || undefined }),
      });
      navigate(`/live?scanId=${result.scanId}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl">
      <h2 className="text-2xl font-bold mb-6">🔍 New Scan</h2>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target */}
        <div>
          <label className="block text-sm font-medium mb-1">Target URL *</label>
          <input
            type="url"
            value={target}
            onChange={e => setTarget(e.target.value)}
            placeholder="https://example.com"
            className="w-full px-3 py-2 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded-lg focus:outline-none focus:border-[var(--wb-red)]"
          />
        </div>

        {/* Modules */}
        <div>
          <label className="block text-sm font-medium mb-2">Scanner Modules</label>
          <div className="grid grid-cols-2 gap-2">
            {MODULES.map(m => (
              <label key={m.id} className="flex items-start gap-2 p-2 rounded bg-[var(--wb-surface)] border border-[var(--wb-border)] cursor-pointer hover:border-[var(--wb-red)]/50 transition-colors">
                <input
                  type="checkbox"
                  checked={modules.includes(m.id)}
                  onChange={() => toggleModule(m.id)}
                  className="mt-1 accent-[var(--wb-red)]"
                />
                <div>
                  <div className="text-sm font-medium">{m.label}</div>
                  <div className="text-xs text-[var(--wb-muted)]">{m.desc}</div>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Settings */}
        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1">Depth</label>
            <input type="number" min={1} max={10} value={depth} onChange={e => setDepth(+e.target.value)}
              className="w-full px-3 py-2 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded-lg" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Threads</label>
            <input type="number" min={1} max={100} value={threads} onChange={e => setThreads(+e.target.value)}
              className="w-full px-3 py-2 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded-lg" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Proxy</label>
            <input type="text" value={proxy} onChange={e => setProxy(e.target.value)} placeholder="http://127.0.0.1:8080"
              className="w-full px-3 py-2 bg-[var(--wb-surface)] border border-[var(--wb-border)] rounded-lg" />
          </div>
        </div>

        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={stealth} onChange={e => setStealth(e.target.checked)} className="accent-[var(--wb-red)]" />
          Stealth mode (slower, randomized timing)
        </label>

        {error && <div className="text-[var(--wb-red)] text-sm">{error}</div>}

        <button
          type="submit"
          disabled={loading || !target}
          className="px-6 py-2.5 bg-[var(--wb-red)] text-white font-bold rounded-lg hover:bg-red-600 disabled:opacity-50 transition-colors"
        >
          {loading ? 'Starting...' : '🔥 Start Scan'}
        </button>
      </form>
    </div>
  );
}