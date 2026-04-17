"""HTML Report generator — professional reports with embedded evidence."""

import json
from datetime import datetime, timezone


def generate_html_report(scan_data: dict, findings: list[dict], recon: list[dict] = None, ai_summary: str = "") -> str:
    """Generate a professional HTML report."""

    severity_colors = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#06b6d4",
        "INFO": "#94a3b8",
    }

    # Count by severity
    by_severity = {}
    by_type = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        t = f.get("type", "Unknown")
        by_type[t] = by_type.get(t, 0) + 1

    findings_rows = ""
    for f in findings:
        color = severity_colors.get(f.get("severity", "INFO"), "#94a3b8")
        findings_rows += f"""
        <tr>
          <td><span style="color:{color};font-weight:bold">{f.get('severity','')}</span></td>
          <td>{f.get('type','')}</td>
          <td><code>{f.get('url','')}</code></td>
          <td>{f.get('parameter','')}</td>
          <td><code>{f.get('payload','')[:60]}</code></td>
          <td>{f.get('evidence','')[:80]}</td>
          <td>{f.get('remediation','')[:80]}</td>
          <td>{int(f.get('confidence',1)*100)}%</td>
        </tr>"""

    recon_rows = ""
    if recon:
        for r in recon[:50]:
            recon_rows += f"""
        <tr>
          <td><code>{r.get('url','')}</code></td>
          <td>{r.get('status_code','')}</td>
          <td>{r.get('method','GET')}</td>
          <td>{r.get('content_length',0)}</td>
          <td>{r.get('tech','')}</td>
          <td>{r.get('depth',0)}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WebBreaker Security Report — {scan_data.get('target','')}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #f1f5f9; padding: 40px; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ font-size: 2em; margin-bottom: 8px; }}
  h2 {{ font-size: 1.5em; margin: 30px 0 15px; border-bottom: 2px solid #ef4444; padding-bottom: 8px; }}
  .meta {{ color: #94a3b8; margin-bottom: 30px; }}
  .stats {{ display: flex; gap: 15px; margin-bottom: 30px; flex-wrap: wrap; }}
  .stat {{ padding: 15px 20px; background: #1e293b; border-radius: 8px; min-width: 100px; text-align: center; }}
  .stat .number {{ font-size: 2em; font-weight: bold; }}
  .stat .label {{ font-size: 0.8em; color: #94a3b8; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 0.85em; }}
  th {{ text-align: left; padding: 10px; background: #1e293b; border-bottom: 2px solid #334155; color: #94a3b8; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #334155; vertical-align: top; }}
  tr:hover {{ background: rgba(255,255,255,0.03); }}
  code {{ font-family: 'Fira Code', monospace; font-size: 0.9em; background: #0f172a; padding: 2px 5px; border-radius: 3px; }}
  .ai-summary {{ background: #1e293b; border-left: 4px solid #06b6d4; padding: 15px 20px; margin-bottom: 20px; border-radius: 0 8px 8px 0; }}
  .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #334155; color: #64748b; font-size: 0.8em; }}
</style>
</head>
<body>
<div class="container">
  <h1>🔥 WebBreaker Security Report</h1>
  <div class="meta">
    <strong>Target:</strong> {scan_data.get('target','')} &nbsp;|&nbsp;
    <strong>Scan ID:</strong> {scan_data.get('id','')} &nbsp;|&nbsp;
    <strong>Date:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &nbsp;|&nbsp;
    <strong>Status:</strong> {scan_data.get('status','')}
  </div>

  {"<div class='ai-summary'><strong>🤖 AI Executive Summary</strong><br/>" + ai_summary + "</div>" if ai_summary else ""}

  <h2>📊 Summary</h2>
  <div class="stats">
    <div class="stat"><div class="number" style="color:#ef4444">{by_severity.get('CRITICAL',0)}</div><div class="label">CRITICAL</div></div>
    <div class="stat"><div class="number" style="color:#f97316">{by_severity.get('HIGH',0)}</div><div class="label">HIGH</div></div>
    <div class="stat"><div class="number" style="color:#eab308">{by_severity.get('MEDIUM',0)}</div><div class="label">MEDIUM</div></div>
    <div class="stat"><div class="number" style="color:#06b6d4">{by_severity.get('LOW',0)}</div><div class="label">LOW</div></div>
    <div class="stat"><div class="number" style="color:#94a3b8">{by_severity.get('INFO',0)}</div><div class="label">INFO</div></div>
    <div class="stat"><div class="number" style="color:#f1f5f9">{len(findings)}</div><div class="label">TOTAL</div></div>
  </div>

  <h2>🚨 Findings</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th><th>Payload</th><th>Evidence</th><th>Remediation</th><th>Confidence</th></tr>
    </thead>
    <tbody>{findings_rows}</tbody>
  </table>

  {"<h2>🗺️ Reconnaissance</h2><table><thead><tr><th>URL</th><th>Status</th><th>Method</th><th>Size</th><th>Tech</th><th>Depth</th></tr></thead><tbody>" + recon_rows + "</tbody></table>" if recon_rows else ""}

  <div class="footer">
    <p>Generated by WebBreaker v1.0.0 — Web Application Penetration Testing Toolkit</p>
    <p>For authorized security assessments only. This report is confidential.</p>
  </div>
</div>
</body>
</html>"""

    return html


def save_html_report(output_path: str, scan_data: dict, findings: list[dict], recon: list[dict] = None, ai_summary: str = ""):
    """Save HTML report to file."""
    html = generate_html_report(scan_data, findings, recon, ai_summary)
    with open(output_path, "w") as f:
        f.write(html)
    return output_path