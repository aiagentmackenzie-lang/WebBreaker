export default function SeverityBadge({ severity }) {
  const classes = {
    CRITICAL: 'sev-badge-critical',
    HIGH: 'sev-badge-high',
    MEDIUM: 'sev-badge-medium',
    LOW: 'sev-badge-low',
    INFO: 'sev-badge-info',
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold ${classes[severity] || 'sev-badge-info'}`}>
      {severity}
    </span>
  );
}