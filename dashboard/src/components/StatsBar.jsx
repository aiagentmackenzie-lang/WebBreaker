export default function StatsBar({ findings }) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) { counts[f.severity] = (counts[f.severity] || 0) + 1; }

  return (
    <div className="flex gap-4">
      {Object.entries(counts).map(([sev, count]) => (
        <div key={sev} className={`px-4 py-2 rounded-lg border border-[var(--wb-border)] bg-[var(--wb-surface)] min-w-[80px] text-center`}>
          <div className={`text-xl font-bold sev-${sev.toLowerCase()}`}>{count}</div>
          <div className="text-xs text-[var(--wb-muted)]">{sev}</div>
        </div>
      ))}
      <div className="px-4 py-2 rounded-lg border border-[var(--wb-red)]/30 bg-[var(--wb-red)]/10 min-w-[80px] text-center">
        <div className="text-xl font-bold text-[var(--wb-red)]">{findings.length}</div>
        <div className="text-xs text-[var(--wb-muted)]">Total</div>
      </div>
    </div>
  );
}