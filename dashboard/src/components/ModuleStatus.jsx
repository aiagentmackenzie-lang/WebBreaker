const ALL_MODULES = ['recon', 'sqli', 'xss', 'csrf', 'cmdi', 'lfi', 'rfi', 'dirbrute', 'fuzz', 'headers', 'session'];

export default function ModuleStatus({ statuses }) {
  return (
    <div className="flex flex-wrap gap-2">
      {ALL_MODULES.map(m => {
        const status = statuses[m];
        const color = status === 'done' ? 'bg-[var(--wb-green)]/20 text-[var(--wb-green)] border-[var(--wb-green)]/50' :
                      status === 'running' ? 'bg-[var(--wb-yellow)]/20 text-[var(--wb-yellow)] border-[var(--wb-yellow)]/50 animate-pulse' :
                      'bg-[var(--wb-surface)] text-[var(--wb-muted)] border-[var(--wb-border)]';
        return (
          <span key={m} className={`px-2 py-1 rounded text-xs border ${color}`}>
            {status === 'done' ? '✓' : status === 'running' ? '⟳' : '○'} {m}
          </span>
        );
      })}
    </div>
  );
}