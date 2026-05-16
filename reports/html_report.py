"""HTML Report generator — professional reports with Jinja2 templates."""

import os
from datetime import datetime, timezone
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

# Template directory (relative to this file)
_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")

# Severity colors for both HTML and PDF
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#06b6d4",
    "INFO": "#94a3b8",
}

# Severity weights for risk score calculation
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
    "INFO": 0.5,
}


def calculate_risk_score(findings: list[dict]) -> tuple[int, str]:
    """Calculate an overall risk score (0-100) from findings.

    Returns (score, color) where color is a CSS hex color.
    """
    if not findings:
        return 0, "#22c55e"  # Green — no findings

    total_weight = sum(
        SEVERITY_WEIGHTS.get(f.get("severity", "INFO"), 0.5) for f in findings
    )
    # Normalize: a single critical = ~30/100, scales logarithmically
    import math
    raw = min(100, int(10 * math.log2(total_weight + 1)))

    if raw >= 80:
        color = "#ef4444"  # Red
    elif raw >= 60:
        color = "#f97316"  # Orange
    elif raw >= 40:
        color = "#eab308"  # Yellow
    elif raw >= 20:
        color = "#06b6d4"  # Cyan
    else:
        color = "#22c55e"  # Green

    return raw, color


def generate_html_report(
    scan_data: dict,
    findings: list[dict],
    recon: Optional[list[dict]] = None,
    ai_summary: str = "",
) -> str:
    """Generate a professional HTML report using Jinja2 template.

    Args:
        scan_data: Scan metadata dict with keys: id, target, status, started_at, completed_at
        findings: List of finding dicts from Database.get_findings()
        recon: Optional list of recon dicts from Database.get_recon()
        ai_summary: Optional AI-generated executive summary text

    Returns:
        Complete HTML string for the report.
    """
    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")

    # Calculate risk score
    risk_score, risk_color = calculate_risk_score(findings)

    # Build severity summary
    by_severity = {}
    by_type = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        t = f.get("type", "Unknown")
        by_type[t] = by_type.get(t, 0) + 1

    severities = []
    for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        severities.append({
            "name": sev_name,
            "count": by_severity.get(sev_name, 0),
            "color": SEVERITY_COLORS.get(sev_name, "#94a3b8"),
        })

    # Add computed fields to findings for template
    enriched_findings = []
    for f in findings:
        ef = dict(f)
        # Ensure confidence is a float 0-1
        if "confidence" not in ef or ef["confidence"] is None:
            ef["confidence"] = 1.0
        ef["confidence"] = float(ef["confidence"])
        enriched_findings.append(ef)

    # Add computed fields to recon for template
    enriched_recon = []
    if recon:
        for r in recon:
            er = dict(r)
            # tech field may be comma-separated string or empty
            if "tech" not in er or er["tech"] is None:
                er["tech"] = ""
            enriched_recon.append(er)

    html = template.render(
        scan_data=scan_data,
        findings=enriched_findings,
        recon=enriched_recon,
        ai_summary=ai_summary,
        risk_score=risk_score,
        risk_color=risk_color,
        severities=severities,
        total_findings=len(findings),
        severity_colors=SEVERITY_COLORS,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
    )

    return html


def save_html_report(
    output_path: str,
    scan_data: dict,
    findings: list[dict],
    recon: Optional[list[dict]] = None,
    ai_summary: str = "",
) -> str:
    """Generate and save HTML report to file.

    Args:
        output_path: Path to write the HTML file
        scan_data: Scan metadata dict
        findings: List of finding dicts
        recon: Optional list of recon dicts
        ai_summary: Optional AI-generated executive summary

    Returns:
        The output_path that was written.
    """
    html = generate_html_report(scan_data, findings, recon, ai_summary)

    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path