import React from 'react';
import { Routes, Route, NavLink } from 'react-router-dom';
import NewScan from './pages/NewScan.jsx';
import LiveScan from './pages/LiveScan.jsx';
import Findings from './pages/Findings.jsx';
import Recon from './pages/Recon.jsx';
import Reports from './pages/Reports.jsx';

const navItems = [
  { to: '/', label: 'New Scan', icon: '🔍' },
  { to: '/live', label: 'Live Scan', icon: '📡' },
  { to: '/findings', label: 'Findings', icon: '🚨' },
  { to: '/recon', label: 'Recon', icon: '🗺️' },
  { to: '/reports', label: 'Reports', icon: '📊' },
];

export default function App() {
  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <nav className="w-56 bg-[var(--wb-surface)] border-r border-[var(--wb-border)] flex flex-col">
        <div className="p-4 border-b border-[var(--wb-border)]">
          <h1 className="text-xl font-bold">🔥 WebBreaker</h1>
          <p className="text-xs text-[var(--wb-muted)]">Web App Pentest Toolkit</p>
        </div>
        <div className="flex-1 py-2">
          {navItems.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-2 px-4 py-2.5 text-sm transition-colors ${
                  isActive ? 'bg-[var(--wb-red)]/20 text-[var(--wb-red)] border-r-2 border-[var(--wb-red)]' : 'text-[var(--wb-muted)] hover:text-[var(--wb-text)] hover:bg-white/5'
                }`
              }
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </div>
        <div className="p-4 text-xs text-[var(--wb-muted)] border-t border-[var(--wb-border)]">
          v1.0.0 — Authorized Use Only
        </div>
      </nav>

      {/* Main content */}
      <main className="flex-1 overflow-auto p-6">
        <Routes>
          <Route path="/" element={<NewScan />} />
          <Route path="/live" element={<LiveScan />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/recon" element={<Recon />} />
          <Route path="/reports" element={<Reports />} />
        </Routes>
      </main>
    </div>
  );
}