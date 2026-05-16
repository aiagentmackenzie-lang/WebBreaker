"""PDF Report generator — WeasyPrint-powered professional PDF reports."""

import os
from typing import Optional

from .html_report import generate_html_report


def generate_pdf_report(
    scan_data: dict,
    findings: list[dict],
    output_path: str,
    recon: Optional[list[dict]] = None,
    ai_summary: str = "",
) -> str:
    """Generate a professional PDF report using WeasyPrint.

    Args:
        scan_data: Scan metadata dict with keys: id, target, status, started_at, completed_at
        findings: List of finding dicts from Database.get_findings()
        output_path: Path to write the PDF file
        recon: Optional list of recon dicts from Database.get_recon()
        ai_summary: Optional AI-generated executive summary text

    Returns:
        The output_path that was written.
    """
    from weasyprint import HTML

    # Generate HTML content
    html_content = generate_html_report(scan_data, findings, recon, ai_summary)

    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # WeasyPrint renders PDF from the HTML string
    html_doc = HTML(string=html_content)
    html_doc.write_pdf(output_path)

    return output_path


def generate_pdf_from_html(
    html_content: str,
    output_path: str,
) -> str:
    """Convert an existing HTML string to PDF using WeasyPrint.

    This is useful when you've already generated or customized an HTML report
    and just need the PDF conversion.

    Args:
        html_content: Complete HTML string
        output_path: Path to write the PDF file

    Returns:
        The output_path that was written.
    """
    from weasyprint import HTML

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    html_doc = HTML(string=html_content)
    html_doc.write_pdf(output_path)

    return output_path


def is_weasyprint_available() -> bool:
    """Check if WeasyPrint is importable and functional.

    Returns:
        True if WeasyPrint can be imported, False otherwise.
    """
    try:
        import weasyprint  # noqa: F401
        return True
    except (ImportError, OSError):
        # OSError occurs when native libraries (pango, etc.) are missing
        return False