"""Tests for WebBreaker core modules."""

import pytest
from core.config import ScanConfig, Finding, Severity, FindingType


class TestScanConfig:
    def test_authorized_config(self):
        config = ScanConfig(target="https://example.com", authorized=True)
        assert config.target == "https://example.com"
        assert config.authorized is True
        assert config.scope == "https://example.com"

    def test_unauthorized_raises(self):
        with pytest.raises(PermissionError):
            ScanConfig(target="https://example.com", authorized=False)

    def test_custom_scope(self):
        config = ScanConfig(target="https://app.example.com", authorized=True, scope="https://example.com")
        assert config.scope == "https://example.com"

    def test_stealth_mode(self):
        config = ScanConfig(target="https://example.com", authorized=True, stealth=True, rate_limit=20)
        assert config.rate_limit == 20

    def test_default_values(self):
        config = ScanConfig(target="https://example.com", authorized=True)
        assert config.depth == 3
        assert config.threads == 20
        assert config.timeout == 10
        assert config.delay == 0.0
        assert config.proxy is None


class TestFinding:
    def test_finding_to_dict(self):
        f = Finding(
            finding_type=FindingType.SQLI,
            severity=Severity.HIGH,
            url="https://example.com/page?id=1",
            parameter="id",
            payload="' OR 1=1--",
            evidence="MySQL error detected",
            remediation="Use parameterized queries",
            confidence=0.9,
            timestamp="2026-04-17T00:00:00+00:00",
        )
        d = f.to_dict()
        assert d["type"] == "SQL Injection"
        assert d["severity"] == "HIGH"
        assert d["url"] == "https://example.com/page?id=1"
        assert d["confidence"] == 0.9

    def test_all_severities(self):
        for sev in Severity:
            assert sev.value in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_all_finding_types(self):
        for ft in FindingType:
            assert ft.value is not None


class TestDatabase:
    def test_create_and_query_scan(self):
        from core.database import Database
        import os
        db_path = "test_webbreaker.db"
        try:
            db = Database(db_path)
            db.connect()
            db.create_scan("test123", "https://example.com", {"modules": ["sqli"]})
            scan = db.get_scan("test123")
            assert scan is not None
            assert scan["target"] == "https://example.com"
            assert scan["status"] == "running"
        finally:
            db.close()
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_insert_finding(self):
        from core.database import Database
        import os
        db_path = "test_webbreaker.db"
        try:
            db = Database(db_path)
            db.connect()
            db.create_scan("test456", "https://example.com", {})
            finding = Finding(
                finding_type=FindingType.XSS,
                severity=Severity.HIGH,
                url="https://example.com/search",
                parameter="q",
                payload="<script>alert(1)</script>",
                evidence="Reflected in response",
                timestamp="2026-04-17T00:00:00+00:00",
            )
            db.insert_finding("test456", finding)
            findings = db.get_findings("test456")
            assert len(findings) == 1
            assert findings[0]["type"] == "Cross-Site Scripting"
            assert findings[0]["severity"] == "HIGH"
        finally:
            db.close()
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_list_scans(self):
        from core.database import Database
        import os
        db_path = "test_webbreaker.db"
        try:
            db = Database(db_path)
            db.connect()
            db.create_scan("s1", "https://a.com", {})
            db.create_scan("s2", "https://b.com", {})
            scans = db.list_scans()
            assert len(scans) == 2
        finally:
            db.close()
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_delete_scan(self):
        from core.database import Database
        import os
        db_path = "test_webbreaker.db"
        try:
            db = Database(db_path)
            db.connect()
            db.create_scan("del1", "https://example.com", {})
            finding = Finding(
                finding_type=FindingType.LFI,
                severity=Severity.CRITICAL,
                url="https://example.com/page",
                parameter="file",
                payload="../../../etc/passwd",
                evidence="root:x:0:0:",
                timestamp="2026-04-17T00:00:00+00:00",
            )
            db.insert_finding("del1", finding)
            db.delete_scan("del1")
            assert db.get_scan("del1") is None
            assert db.get_findings("del1") == []
        finally:
            db.close()
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_stats(self):
        from core.database import Database
        import os
        db_path = "test_webbreaker.db"
        try:
            db = Database(db_path)
            db.connect()
            db.create_scan("stat1", "https://example.com", {})
            for i, (ft, sev) in enumerate([
                (FindingType.SQLI, Severity.CRITICAL),
                (FindingType.XSS, Severity.HIGH),
                (FindingType.XSS, Severity.MEDIUM),
            ]):
                db.insert_finding("stat1", Finding(
                    finding_type=ft, severity=sev,
                    url="https://example.com", parameter="p",
                    payload="test", evidence="test",
                    timestamp=f"2026-04-17T00:0{i}:00+00:00",
                ))
            stats = db.get_stats("stat1")
            assert stats["total_findings"] == 3
            assert stats["by_severity"]["CRITICAL"] == 1
            assert stats["by_type"]["Cross-Site Scripting"] == 2
        finally:
            db.close()
            if os.path.exists(db_path):
                os.remove(db_path)


class TestReconTechDetection:
    def test_detect_php(self):
        from core.recon import ReconScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = ReconScanner(config)

        class FakeResp:
            headers = {"X-Powered-By": "PHP/8.1", "Server": "nginx"}
            text = '<html><body>PHPSESSID cookie</body></html>'

        tech = scanner._detect_tech(FakeResp(), FakeResp.text)
        assert "PHP" in tech
        assert "Nginx" in tech

    def test_detect_react(self):
        from core.recon import ReconScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = ReconScanner(config)

        class FakeResp:
            headers = {"Server": "nginx"}
            text = '<div data-reactroot="">__NEXT_DATA__</div>'

        tech = scanner._detect_tech(FakeResp(), FakeResp.text)
        assert "React" in tech

    def test_extract_forms(self):
        from core.recon import ReconScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = ReconScanner(config)

        html = '''<form action="/login" method="POST">
            <input type="text" name="username" value="">
            <input type="password" name="password" value="">
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="submit" name="submit" value="Login">
        </form>'''

        forms = scanner._extract_forms(html, "https://example.com")
        assert len(forms) == 1
        assert forms[0]["method"] == "POST"
        assert forms[0]["has_csrf_token"] is True
        assert len(forms[0]["fields"]) == 4


class TestSQLiDetection:
    def test_error_pattern_detection(self):
        from core.sqli import SQLiScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = SQLiScanner(config)

        result = scanner._check_error_patterns("Warning: mysqli_fetch_array() expects parameter")
        assert result is not None
        assert result[0] == "MySQL"

    def test_postgresql_error(self):
        from core.sqli import SQLiScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = SQLiScanner(config)

        result = scanner._check_error_patterns("PostgreSQL error: syntax error at end of input")
        assert result is not None
        assert result[0] == "PostgreSQL"

    def test_no_error(self):
        from core.sqli import SQLiScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = SQLiScanner(config)

        result = scanner._check_error_patterns("Everything is fine, no errors here")
        assert result is None


class TestXSSDetection:
    def test_reflection_detection(self):
        from core.xss import XSSScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = XSSScanner(config)

        result = scanner._detect_reflection("<script>alert(1)</script>", '<p><script>alert(1)</script></p>')
        assert result == "reflected"

    def test_html_encoded_reflection(self):
        from core.xss import XSSScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = XSSScanner(config)

        result = scanner._detect_reflection("<script>alert(1)</script>", '<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>')
        assert result == "html_encoded"

    def test_no_reflection(self):
        from core.xss import XSSScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = XSSScanner(config)

        result = scanner._detect_reflection("<script>alert(1)</script>", "Hello World")
        assert result is None

    def test_dom_xss_detection(self):
        from core.xss import XSSScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = XSSScanner(config)

        js = "document.getElementById('output').innerHTML = location.hash.substring(1);"
        results = scanner._detect_dom_xss(js)
        assert len(results) > 0
        assert any("innerHTML" in str(r["sinks"]) for r in results)


class TestCSRF:
    def test_csrf_token_detection(self):
        from core.csrf import CSRFScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = CSRFScanner(config)

        form_with_token = {
            "method": "POST",
            "action": "/update",
            "fields": [
                {"name": "username", "type": "text", "value": ""},
                {"name": "csrf_token", "type": "hidden", "value": "abc123"},
            ],
        }
        assert scanner._has_csrf_token(form_with_token) is True

        form_without_token = {
            "method": "POST",
            "action": "/update",
            "fields": [
                {"name": "username", "type": "text", "value": ""},
            ],
        }
        assert scanner._has_csrf_token(form_without_token) is False


class TestHeaders:
    def test_csp_bypass_detection(self):
        from core.headers import HeaderScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = HeaderScanner(config)

        csp = "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' * data: http://cdn.evil.com"
        bypasses = scanner._analyze_csp_bypasses(csp)
        assert len(bypasses) > 0
        types = [b["type"] for b in bypasses]
        assert "unsafe-inline" in types
        assert "unsafe-eval" in types
        assert "wildcard" in types
        assert "data_uri" in types
        assert "http_source" in types

    def test_grade_calculation(self):
        from core.headers import HeaderScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = HeaderScanner(config)

        # No findings = A
        assert scanner._calculate_grade([]) == "A"

        # Many high findings = F
        many_high = [Finding(
            finding_type=FindingType.HEADERS, severity=Severity.HIGH,
            url="x", parameter="x", payload="x", evidence="x",
        )] * 10
        assert scanner._calculate_grade(many_high) == "F"


class TestSessionEntropy:
    def test_high_entropy(self):
        from core.session import SessionScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = SessionScanner(config)

        # Random hex string should have high entropy
        entropy = scanner._calculate_entropy("a8f3b2c1d4e5f67890abcdef12345678")
        assert entropy > 3.0

    def test_low_entropy(self):
        from core.session import SessionScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = SessionScanner(config)

        # Repetitive string should have low entropy
        entropy = scanner._calculate_entropy("aaaaaaaaaaaaaaaa")
        assert entropy < 1.0

    def test_empty_string(self):
        from core.session import SessionScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = SessionScanner(config)

        assert scanner._calculate_entropy("") == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])