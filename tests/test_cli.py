"""Tests for WebBreaker CLI report command."""

import json
import os

import pytest
from click.testing import CliRunner

from cli import cli


# ── Fixtures ────────────────────────────────────────────────────────

@pytest.fixture
def db_with_scan(tmp_path):
    """Create a temporary database with a scan and findings for testing."""
    from core.database import Database
    from core.config import Finding, Severity, FindingType

    db_path = str(tmp_path / "test.db")
    db = Database(db_path)
    db.connect()

    scan_id = "test1234"
    db.create_scan(scan_id, "https://test.example.com", {"modules": ["recon", "sqli"]})

    findings = [
        Finding(
            finding_type=FindingType.SQLI,
            severity=Severity.HIGH,
            url="https://test.example.com/page?id=1",
            parameter="id",
            payload="' OR 1=1--",
            evidence="MySQL error detected",
            remediation="Use parameterized queries",
            confidence=0.9,
            timestamp="2026-05-16T12:00:00+00:00",
        ),
        Finding(
            finding_type=FindingType.HEADERS,
            severity=Severity.MEDIUM,
            url="https://test.example.com/",
            parameter="X-Frame-Options",
            payload="",
            evidence="Missing X-Frame-Options header",
            remediation="Add X-Frame-Options: DENY",
            confidence=1.0,
            timestamp="2026-05-16T12:01:00+00:00",
        ),
    ]
    for f in findings:
        db.insert_finding(scan_id, f)

    db.update_scan_status(scan_id, "completed", len(findings))
    db.close()
    return db_path


# ── Terminal Report Tests ──────────────────────────────────────────

class TestCLITerminalReport:
    def test_terminal_report(self, db_with_scan):
        """Default terminal report shows scan summary."""
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "test1234", "--db", db_with_scan])
        assert result.exit_code == 0
        assert "test1234" in result.output
        assert "test.example.com" in result.output
        assert "completed" in result.output.lower()

    def test_report_scan_not_found(self, db_with_scan):
        """Report for nonexistent scan shows error."""
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "nonexistent", "--db", db_with_scan])
        assert result.exit_code == 0
        assert "not found" in result.output

    def test_report_with_severity_filter(self, db_with_scan):
        """Report with severity filter still works (terminal)."""
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "test1234", "-s", "HIGH", "--db", db_with_scan])
        assert result.exit_code == 0
        assert "test1234" in result.output


# ── JSON Report Tests ───────────────────────────────────────────────

class TestCLIJSONReport:
    def test_json_report_to_file(self, db_with_scan, tmp_path):
        """JSON report writes structured data to file."""
        runner = CliRunner()
        output_path = str(tmp_path / "report.json")
        result = runner.invoke(cli, ["report", "test1234", "-f", "json", "-o", output_path, "--db", db_with_scan])
        assert result.exit_code == 0
        assert os.path.exists(output_path)
        with open(output_path) as f:
            data = json.load(f)
        assert "scan" in data
        assert "findings" in data
        assert "stats" in data
        assert data["scan"]["id"] == "test1234"
        assert len(data["findings"]) == 2
        assert data["findings"][0]["severity"] == "HIGH"

    def test_json_report_to_stdout(self, db_with_scan):
        """JSON report to stdout without -o prints JSON."""
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "test1234", "-f", "json", "--db", db_with_scan])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "scan" in data
        assert "findings" in data

    def test_json_report_with_severity_filter(self, db_with_scan, tmp_path):
        """JSON report with severity filter only includes matching findings."""
        runner = CliRunner()
        output_path = str(tmp_path / "report.json")
        result = runner.invoke(cli, ["report", "test1234", "-f", "json", "-s", "HIGH", "-o", output_path, "--db", db_with_scan])
        assert result.exit_code == 0
        with open(output_path) as f:
            data = json.load(f)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "HIGH"


# ── HTML Report Tests ──────────────────────────────────────────────

class TestCLIHTMLReport:
    def test_html_report_to_file(self, db_with_scan, tmp_path):
        """HTML report writes valid HTML to file."""
        runner = CliRunner()
        output_path = str(tmp_path / "report.html")
        result = runner.invoke(cli, ["report", "test1234", "-f", "html", "-o", output_path, "--db", db_with_scan])
        assert result.exit_code == 0
        assert os.path.exists(output_path)
        with open(output_path) as f:
            content = f.read()
        assert "test.example.com" in content
        assert "SQL Injection" in content
        assert "<!DOCTYPE html>" in content

    def test_html_report_default_filename(self, db_with_scan, tmp_path):
        """HTML report without -o uses default filename."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(cli, ["report", "test1234", "-f", "html", "--db", db_with_scan])
            assert result.exit_code == 0
            # Check default filename was suggested in output
            assert "webbreaker-report-test1234.html" in result.output or "HTML report" in result.output


# ── PDF Report Tests ───────────────────────────────────────────────

class TestCLIPDFReport:
    def test_pdf_report_to_file(self, db_with_scan, tmp_path):
        """PDF report generates a file (if WeasyPrint available)."""
        from reports.pdf_report import is_weasyprint_available
        runner = CliRunner()
        output_path = str(tmp_path / "report.pdf")
        result = runner.invoke(cli, ["report", "test1234", "-f", "pdf", "-o", output_path, "--db", db_with_scan])
        assert result.exit_code == 0
        if is_weasyprint_available():
            assert os.path.exists(output_path)
            assert os.path.getsize(output_path) > 100
        else:
            # Should fall back to HTML
            assert "HTML report" in result.output or "unavailable" in result.output


# ── STIX Report Tests ──────────────────────────────────────────────

class TestCLISTIXReport:
    def test_stix_report_to_file(self, db_with_scan, tmp_path):
        """STIX report writes valid JSON bundle to file."""
        runner = CliRunner()
        output_path = str(tmp_path / "stix.json")
        result = runner.invoke(cli, ["report", "test1234", "-f", "stix", "-o", output_path, "--db", db_with_scan])
        assert result.exit_code == 0
        assert os.path.exists(output_path)
        with open(output_path) as f:
            data = json.load(f)
        assert data["type"] == "bundle"
        assert len(data["objects"]) > 0

    def test_stix_default_filename(self, db_with_scan, tmp_path):
        """STIX report without -o uses default filename."""
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(cli, ["report", "test1234", "-f", "stix", "--db", db_with_scan])
            assert result.exit_code == 0
            assert "webbreaker-stix-test1234.json" in result.output or "STIX" in result.output


# ── Format Validation Tests ─────────────────────────────────────────

class TestCLIReportFormatValidation:
    def test_invalid_format_rejected(self, db_with_scan):
        """Invalid format choice is rejected by Click."""
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "test1234", "-f", "xml", "--db", db_with_scan])
        assert result.exit_code != 0
        assert "Invalid value" in result.output or "Error" in result.output

    def test_format_choices_accepted(self, db_with_scan, tmp_path):
        """All valid format choices are accepted."""
        runner = CliRunner()
        for fmt in ["terminal", "json", "html", "pdf", "stix"]:
            result = runner.invoke(cli, ["report", "test1234", "-f", fmt, "--db", db_with_scan])
            # All should succeed (terminal doesn't need output file)
            assert result.exit_code == 0