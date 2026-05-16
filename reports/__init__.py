"""WebBreaker report generators."""

from .html_report import generate_html_report, save_html_report, calculate_risk_score, SEVERITY_COLORS
from .pdf_report import generate_pdf_report, generate_pdf_from_html, is_weasyprint_available
from .stix_export import generate_stix_bundle, export_stix_json

__all__ = [
    "generate_html_report",
    "save_html_report",
    "calculate_risk_score",
    "SEVERITY_COLORS",
    "generate_pdf_report",
    "generate_pdf_from_html",
    "is_weasyprint_available",
    "generate_stix_bundle",
    "export_stix_json",
]