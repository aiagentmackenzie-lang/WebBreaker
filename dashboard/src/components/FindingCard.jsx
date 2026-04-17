import React from 'react';
import SeverityBadge from './SeverityBadge.jsx';

export default function FindingCard({ finding }) {
  return (
    <div className="bg-[var(--wb-surface)] rounded-lg p-3 border border-[var(--wb-border)] hover:border-[var(--wb-red)]/30 transition-colors">
      <div className="flex items-center gap-3 mb-1">
        <SeverityBadge severity={finding.severity} />
        <span className="text-sm font-medium">{finding.type}</span>
        <span className="text-xs text-[var(--wb-muted)] ml-auto">{(finding.confidence * 100).toFixed(0)}%</span>
      </div>
      <div className="font-mono text-xs text-[var(--wb-muted)] truncate">{finding.url}</div>
      <div className="text-xs mt-1">
        <span className="text-[var(--wb-muted)]">param:</span> {finding.parameter}
        <span className="mx-2">|</span>
        <span className="text-[var(--wb-muted)]">payload:</span> {finding.payload?.slice(0, 50)}
      </div>
      {finding.evidence && <div className="text-xs text-[var(--wb-yellow)] mt-1 truncate">{finding.evidence}</div>}
    </div>
  );
}