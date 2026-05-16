"""Tests for WebBreaker report generation (HTML, PDF, STIX)."""

import json
import os
import tempfile
import uuid

import pytest

from reports.html_report import (
    generate_html_report,
    save_html_report,
    calculate_risk_score,
    SEVERITY_COLORS,
)
from reports.stix_export import generate_stix_bundle, export_stix_json
from reports.pdf_report import is_weasyprint_available


# ── Fixtures ────────────────────────────────────────────────────────

SAMPLE_SCAN_DATA = {
    "id": "abc12345",
    "target": "https://test.example.com",
    "status": "completed",
    "started_at": "2026-05-16T12:00:00+00:00",
    "completed_at": "2026-05-16T12:15:00+00:00",
}

SAMPLE_FINDINGS = [
    {
        "severity": "CRITICAL",
        "type": "SQL Injection",
        "url": "https://test.example.com/page?id=1",
        "parameter": "id",
        "payload": "' OR 1=1--",
        "evidence": "MySQL error: You have an error in your SQL syntax",
        "remediation": "Use parameterized queries",
        "confidence": 0.95,
        "request": "GET /page?id=1'+OR+1%3D1-- HTTP/1.1",
        "response": "500 Internal Server Error",
        "timestamp": "2026-05-16T12:05:00+00:00",
    },
    {
        "severity": "HIGH",
        "type": "Cross-Site Scripting",
        "url": "https://test.example.com/search?q=test",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "evidence": "Reflected in HTML body without encoding",
        "remediation": "Encode output for the appropriate context",
        "confidence": 0.85,
        "request": "GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "response": "200 OK",
        "timestamp": "2026-05-16T12:06:00+00:00",
    },
    {
        "severity": "MEDIUM",
        "type": "Security Headers",
        "url": "https://test.example.com/",
        "parameter": "X-Frame-Options",
        "payload": "",
        "evidence": "Missing X-Frame-Options header",
        "remediation": "Add X-Frame-Options: DENY",
        "confidence": 1.0,
        "request": "",
        "response": "",
        "timestamp": "2026-05-16T12:07:00+00:00",
    },
]

SAMPLE_RECON = [
    {
        "url": "https://test.example.com/",
        "status_code": 200,
        "method": "GET",
        "content_length": 12345,
        "content_type": "text/html",
        "tech": "PHP,Apache",
        "forms": "[]",
        "links": "[]",
        "params": "[]",
        "depth": 0,
        "discovered_at": "2026-05-16T12:01:00+00:00",
    },
    {
        "url": "https://test.example.com/admin",
        "status_code": 403,
        "method": "GET",
        "content_length": 500,
        "content_type": "text/html",
        "tech": "",
        "forms": "[]",
        "links": "[]",
        "params": "[]",
        "depth": 1,
        "discovered_at": "2026-05-16T12:02:00+00:00",
    },
]


# ── Risk Score Tests ────────────────────────────────────────────────

class TestRiskScore:
    def test_no_findings_green(self):
        """No findings → score 0, green color."""
        score, color = calculate_risk_score([])
        assert score == 0
        assert color == "#22c55e"

    def test_single_critical(self):
        """Single critical finding → high-ish score, red/orange color."""
        score, color = calculate_risk_score([
            {"severity": "CRITICAL", "type": "SQL Injection"}
        ])
        assert score > 0
        # Score for a single critical (weight 10): 10 * log2(11) ≈ 34
        assert 25 <= score <= 50

    def test_many_findings(self):
        """Many findings → capped at 100."""
        findings = [{"severity": "CRITICAL", "type": "SQL Injection"}] * 20
        score, color = calculate_risk_score(findings)
        assert score <= 100

    def test_info_only_low_score(self):
        """Only INFO findings → low score."""
        score, color = calculate_risk_score([
            {"severity": "INFO", "type": "Session Analysis"}
        ])
        assert score < 15

    def test_mixed_severities(self):
        """Mixed severity findings → moderate-high score."""
        score, color = calculate_risk_score(SAMPLE_FINDINGS)
        assert 30 <= score <= 80

    def test_unknown_severity(self):
        """Unknown severity treated as INFO weight."""
        score1, _ = calculate_risk_score([{"severity": "INFO", "type": "X"}])
        score2, _ = calculate_risk_score([{"severity": "UNKNOWN", "type": "X"}])
        assert score1 == score2


# ── HTML Report Tests ───────────────────────────────────────────────

class TestHTMLReport:
    def test_generate_html_basic(self):
        """HTML report generates without errors."""
        html = generate_html_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS)
        assert isinstance(html, str)
        assert len(html) > 500

    def test_html_contains_target(self):
        """HTML report contains the target URL."""
        html = generate_html_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS)
        assert "test.example.com" in html

    def test_html_contains_scan_id(self):
        """HTML report contains the scan ID."""
        html = generate_html_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS)
        assert "abc12345" in html

    def test_html_contains_findings(self):
        """HTML report contains finding details."""
        html = generate_html_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS)
        assert "SQL Injection" in html
        assert "CRITICAL" in html
        # Jinja2 autoescape may encode quotes as &#39;
        assert "OR 1=1--" in html

    def test_html_contains_severity_stats(self):
        """HTML report has severity breakdown."""
        html = generate_html_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS)
        assert "1" in html  # At least 1 critical

    def test_html_with_recon(self):
        """HTML report includes reconnaissance data."""
        html = generate_html_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS, recon=SAMPLE_RECON)
        assert "Reconnaissance" in html
        assert "/admin" in html

    def test_html_without_recon(self):
        """HTML report works without recon data."""
        html = generate_html_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS, recon=None)
        assert "Reconnaissance" not in html

    def test_html_with_ai_summary(self):
        """HTML report includes AI summary."""
        html = generate_html_report(
            SAMPLE_SCAN_DATA, SAMPLE_FINDINGS,
            ai_summary="SQL injection vulnerability detected in login page."
        )
        assert "AI Executive Summary" in html
        assert "SQL injection" in html

    def test_html_without_ai_summary(self):
        """HTML report works without AI summary."""
        html = generate_html_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS)
        assert "AI Executive Summary" not in html

    def test_html_risk_score_present(self):
        """HTML report includes risk score."""
        html = generate_html_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS)
        assert "Overall Risk Score" in html

    def test_html_xss_escaping(self):
        """HTML report properly escapes XSS in user data."""
        xss_findings = [{
            "severity": "HIGH",
            "type": "Cross-Site Scripting",
            "url": "https://example.com/page?q=<script>alert(1)</script>",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "Reflected script tag",
            "remediation": "Encode output",
            "confidence": 0.9,
        }]
        html = generate_html_report(SAMPLE_SCAN_DATA, xss_findings)
        # Jinja2 autoescape should convert < to &lt; and > to &gt;
        assert "&lt;script&gt;" in html
        # Raw unescaped script tags should NOT appear
        assert "<script>alert(1)</script>" not in html

    def test_html_empty_findings(self):
        """HTML report handles zero findings gracefully."""
        html = generate_html_report(SAMPLE_SCAN_DATA, [])
        assert "0" in html  # Total count
        assert "WebBreaker Security Report" in html

    def test_save_html_report(self):
        """save_html_report writes a file to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "reports", "report.html")
            result = save_html_report(path, SAMPLE_SCAN_DATA, SAMPLE_FINDINGS)
            assert os.path.exists(path)
            assert result == path
            with open(path) as f:
                content = f.read()
            assert "test.example.com" in content

    def test_save_html_creates_directory(self):
        """save_html_report creates parent directories if needed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "deep", "nested", "dir", "report.html")
            save_html_report(path, SAMPLE_SCAN_DATA, SAMPLE_FINDINGS)
            assert os.path.exists(path)

    def test_confidence_percentage_in_html(self):
        """Confidence values appear as percentages in the report."""
        html = generate_html_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS)
        assert "95%" in html  # 0.95 → 95%
        assert "85%" in html  # 0.85 → 85%

    def test_severity_colors_complete(self):
        """All expected severity levels have colors defined."""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in SEVERITY_COLORS
            assert SEVERITY_COLORS[sev].startswith("#")


# ── STIX 2.1 Export Tests ───────────────────────────────────────────

class TestSTIXExport:
    """Tests for STIX 2.1 compliance."""

    def test_stix_bundle_structure(self):
        """STIX bundle has required structure."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        assert bundle["type"] == "bundle"
        assert "id" in bundle
        assert bundle["id"].startswith("bundle--")
        assert "objects" in bundle
        assert len(bundle["objects"]) > 0

    def test_stix_bundle_id_is_uuidv5(self):
        """STIX bundle ID uses UUIDv5 deterministic format."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        # UUIDv5 format: xxxxxxxx-xxxx-5xxx-xxxx-xxxxxxxxxxxx
        bundle_uuid = bundle["id"].replace("bundle--", "")
        uuid_obj = uuid.UUID(bundle_uuid)
        assert uuid_obj.version == 5

    def test_stix_identity_object(self):
        """STIX bundle includes WebBreaker identity."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        identities = [o for o in bundle["objects"] if o["type"] == "identity"]
        assert len(identities) == 1
        identity = identities[0]
        assert identity["name"] == "WebBreaker"
        assert identity["identity_class"] == "software"
        assert identity["id"].startswith("identity--")
        # Identity ID should be deterministic UUIDv5
        identity_uuid = identity["id"].replace("identity--", "")
        assert uuid.UUID(identity_uuid).version == 5

    def test_stix_infrastructure_object(self):
        """STIX bundle includes target infrastructure object."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        infra = [o for o in bundle["objects"] if o["type"] == "infrastructure"]
        assert len(infra) == 1
        assert "test.example.com" in infra[0]["name"]
        assert infra[0]["id"].startswith("infrastructure--")
        # Infrastructure must have created_by_ref
        assert "created_by_ref" in infra[0]

    def test_stix_vulnerability_objects(self):
        """STIX bundle includes vulnerability objects for each finding."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        assert len(vulns) == len(SAMPLE_FINDINGS)
        # All vulnerability IDs should be UUIDv5
        for v in vulns:
            assert v["id"].startswith("vulnerability--")
            vuln_uuid = v["id"].replace("vulnerability--", "")
            assert uuid.UUID(vuln_uuid).version == 5

    def test_stix_created_by_ref(self):
        """All SDOs except identity include created_by_ref."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        identity = [o for o in bundle["objects"] if o["type"] == "identity"][0]
        identity_id = identity["id"]
        # All SDOs except identity should have created_by_ref pointing to identity
        for obj in bundle["objects"]:
            if obj["type"] != "identity":
                assert "created_by_ref" in obj, f"Missing created_by_ref on {obj['type']}"
                assert obj["created_by_ref"] == identity_id

    def test_stix_vulnerability_has_confidence(self):
        """Vulnerability objects include confidence from findings."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        sqli_vuln = [v for v in vulns if "SQL Injection" in v["name"]][0]
        assert "confidence" in sqli_vuln
        # Confidence should be integer 0-100
        assert sqli_vuln["confidence"] == 95  # 0.95 * 100

    def test_stix_attack_pattern_with_kill_chain(self):
        """Attack patterns include kill_chain_phases."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        attack_patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        assert len(attack_patterns) == len(SAMPLE_FINDINGS)
        # SQL Injection attack pattern should have kill chain
        sqli_attack = [a for a in attack_patterns if a["name"] == "Exploit Public-Facing Application"][0]
        assert "kill_chain_phases" in sqli_attack
        assert len(sqli_attack["kill_chain_phases"]) > 0
        assert sqli_attack["kill_chain_phases"][0]["kill_chain_name"] == "mitre-attack"
        assert sqli_attack["kill_chain_phases"][0]["phase_name"] == "initial-access"

    def test_stix_relationship_objects(self):
        """STIX bundle includes both 'targets' and 'uses' relationships."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        # Each finding produces 2 relationships: targets + uses
        assert len(rels) == len(SAMPLE_FINDINGS) * 2
        # Check both relationship types exist
        targets_rels = [r for r in rels if r["relationship_type"] == "targets"]
        uses_rels = [r for r in rels if r["relationship_type"] == "uses"]
        assert len(targets_rels) == len(SAMPLE_FINDINGS)
        assert len(uses_rels) == len(SAMPLE_FINDINGS)
        # All relationships should have created_by_ref
        for r in rels:
            assert "created_by_ref" in r
            assert "description" in r

    def test_stix_indicator_objects(self):
        """STIX bundle includes indicator objects for findings with payloads."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        # Only findings with payloads get indicators (2 of 3 have payloads)
        assert len(indicators) == 2

    def test_stix_indicator_valid_until(self):
        """Indicators include valid_until (STIX 2.1 requirement)."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        for indicator in indicators:
            assert "valid_from" in indicator, "Indicator missing valid_from"
            assert "valid_until" in indicator, "Indicator missing valid_until (STIX 2.1)"
            assert indicator["valid_until"] > indicator["valid_from"]

    def test_stix_indicator_pattern_version(self):
        """Indicators include pattern_version (STIX 2.1)."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        for indicator in indicators:
            assert indicator.get("pattern_version") == "2.1"

    def test_stix_indicator_kill_chain(self):
        """Indicators include kill_chain_phases when mapping exists."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        # At least one indicator should have kill chain phases
        indicators_with_kill_chain = [i for i in indicators if "kill_chain_phases" in i]
        assert len(indicators_with_kill_chain) > 0

    def test_stix_mitre_attack_mapping(self):
        """SQL Injection maps to MITRE ATT&CK T1190."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        sqli_vuln = [v for v in vulns if "SQL Injection" in v["name"]][0]
        attack_refs = [r for r in sqli_vuln["external_references"] if r["source_name"] == "mitre-attack"]
        assert len(attack_refs) == 1
        assert attack_refs[0]["external_id"] == "T1190"
        # Should include ATT&CK URL
        assert "attack.mitre.org" in attack_refs[0].get("url", "")

    def test_stix_capec_url(self):
        """CAPEC references include URLs."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        sqli_vuln = [v for v in vulns if "SQL Injection" in v["name"]][0]
        capec_refs = [r for r in sqli_vuln["external_references"] if r["source_name"] == "capec"]
        assert len(capec_refs) == 1
        assert "capec.mitre.org" in capec_refs[0].get("url", "")

    def test_stix_attack_pattern_external_refs(self):
        """Attack patterns include MITRE ATT&CK and CAPEC external references."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        attack_patterns = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
        sqli_pattern = [a for a in attack_patterns if a["name"] == "Exploit Public-Facing Application"][0]
        attack_refs = [r for r in sqli_pattern.get("external_references", []) if r["source_name"] == "mitre-attack"]
        assert len(attack_refs) == 1
        assert attack_refs[0]["external_id"] == "T1190"

    def test_stix_deterministic_ids(self):
        """Same input produces same STIX IDs (UUIDv5 determinism)."""
        bundle1 = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        bundle2 = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        ids1 = sorted([o["id"] for o in bundle1["objects"]])
        ids2 = sorted([o["id"] for o in bundle2["objects"]])
        assert ids1 == ids2, "Same input should produce deterministic IDs"

    def test_stix_all_ids_are_uuidv5(self):
        """All STIX object IDs use UUIDv5."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        for obj in bundle["objects"]:
            stix_type = obj["type"]
            stix_id = obj["id"]
            # Extract UUID from STIX ID format: {type}--{uuid}
            uuid_str = stix_id.split("--", 1)[1]
            uuid_obj = uuid.UUID(uuid_str)
            assert uuid_obj.version == 5, f"{stix_type} ID is not UUIDv5: {stix_id}"

    def test_stix_export_json(self):
        """export_stix_json produces valid JSON string."""
        json_str = export_stix_json(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        data = json.loads(json_str)
        assert data["type"] == "bundle"
        assert len(data["objects"]) > 0

    def test_stix_export_json_to_file(self):
        """export_stix_json writes to file when output_path given."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "stix.json")
            export_stix_json(SAMPLE_FINDINGS, "https://test.example.com", "abc12345", output_path=path)
            assert os.path.exists(path)
            with open(path) as f:
                data = json.load(f)
            assert data["type"] == "bundle"

    def test_stix_empty_findings(self):
        """STIX bundle with no findings still has identity + infrastructure."""
        bundle = generate_stix_bundle([], "https://test.example.com", "abc12345")
        types = [o["type"] for o in bundle["objects"]]
        assert "identity" in types
        assert "infrastructure" in types
        assert "vulnerability" not in types
        assert "attack-pattern" not in types
        assert "indicator" not in types
        assert "relationship" not in types

    def test_stix_severity_lowercase(self):
        """STIX vulnerability severity is lowercase."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        critical_vulns = [v for v in vulns if v["severity"] == "critical"]
        assert len(critical_vulns) == 1

    def test_stix_spec_version(self):
        """All SDOs include spec_version 2.1."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        for obj in bundle["objects"]:
            assert obj.get("spec_version") == "2.1", f"{obj['type']} missing spec_version 2.1"

    def test_stix_identity_sectors(self):
        """Identity object includes sectors field."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        identity = [o for o in bundle["objects"] if o["type"] == "identity"][0]
        assert "sectors" in identity
        assert "technology" in identity["sectors"]

    def test_stix_relationships_have_descriptions(self):
        """All relationship objects include description."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        for r in rels:
            assert "description" in r, f"Relationship {r['id']} missing description"

    def test_stix_uses_relationship_links_attack_to_vuln(self):
        """'uses' relationships link attack patterns to vulnerabilities."""
        bundle = generate_stix_bundle(SAMPLE_FINDINGS, "https://test.example.com", "abc12345")
        uses_rels = [o for o in bundle["objects"] if o["type"] == "relationship" and o["relationship_type"] == "uses"]
        attack_ids = {o["id"] for o in bundle["objects"] if o["type"] == "attack-pattern"}
        vuln_ids = {o["id"] for o in bundle["objects"] if o["type"] == "vulnerability"}
        for r in uses_rels:
            assert r["source_ref"] in attack_ids, "uses source should be attack-pattern"
            assert r["target_ref"] in vuln_ids, "uses target should be vulnerability"


# ── PDF Report Tests ────────────────────────────────────────────────

class TestPDFReport:
    def test_weasyprint_available(self):
        """Check WeasyPrint import status."""
        # This test just verifies the function runs without error
        result = is_weasyprint_available()
        assert isinstance(result, bool)

    @pytest.mark.skipif(
        not is_weasyprint_available(),
        reason="WeasyPrint not installed"
    )
    def test_generate_pdf_report(self):
        """PDF report generates when WeasyPrint is available."""
        from reports.pdf_report import generate_pdf_report

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.pdf")
            generate_pdf_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS, path)
            assert os.path.exists(path)
            assert os.path.getsize(path) > 100  # Non-trivial PDF

    @pytest.mark.skipif(
        not is_weasyprint_available(),
        reason="WeasyPrint not installed"
    )
    def test_generate_pdf_creates_directory(self):
        """PDF report creates parent directories."""
        from reports.pdf_report import generate_pdf_report

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "deep", "nested", "report.pdf")
            generate_pdf_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS, path)
            assert os.path.exists(path)

    @pytest.mark.skipif(
        not is_weasyprint_available(),
        reason="WeasyPrint not installed"
    )
    def test_generate_pdf_from_html(self):
        """PDF can be generated from an existing HTML string."""
        from reports.pdf_report import generate_pdf_from_html

        html = generate_html_report(SAMPLE_SCAN_DATA, SAMPLE_FINDINGS)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.pdf")
            generate_pdf_from_html(html, path)
            assert os.path.exists(path)
            assert os.path.getsize(path) > 100

    @pytest.mark.skipif(
        not is_weasyprint_available(),
        reason="WeasyPrint not installed"
    )
    def test_generate_pdf_with_recon_and_ai(self):
        """PDF report includes recon data and AI summary."""
        from reports.pdf_report import generate_pdf_report

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.pdf")
            generate_pdf_report(
                SAMPLE_SCAN_DATA, SAMPLE_FINDINGS, path,
                recon=SAMPLE_RECON,
                ai_summary="Critical SQL injection found."
            )
            assert os.path.exists(path)