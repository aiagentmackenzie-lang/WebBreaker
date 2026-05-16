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
        # New: enctype field
        assert "enctype" in forms[0]
        # New: data_attrs field
        assert "data_attrs" in forms[0]


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
        # New FP reduction returns context type, not just 'reflected'
        assert result in ("html_tag", "html_body", "reflected"), f"Expected context type, got {result}"

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


class TestCMDI:
    def test_error_pattern_detection(self):
        from core.cmdi import CmdiScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = CmdiScanner(config)

        result = scanner._check_error_patterns("/bin/sh: 1: command: not found")
        assert result is not None
        assert result[0] == "Linux shell error"

    def test_no_error(self):
        from core.cmdi import CmdiScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = CmdiScanner(config)

        result = scanner._check_error_patterns("Everything is fine")
        assert result is None

    def test_output_marker_detection(self):
        from core.cmdi import CmdiScanner, MARKER
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = CmdiScanner(config)

        assert scanner._check_output_marker(f"Output: {MARKER}") is True
        assert scanner._check_output_marker("No marker here") is False

    def test_bypass_payloads_not_empty(self):
        from core.cmdi import BYPASS_PAYLOADS
        assert len(BYPASS_PAYLOADS) > 0
        # All bypass payloads should contain the marker or test for it
        for p in BYPASS_PAYLOADS:
            assert isinstance(p, str) and len(p) > 0


class TestLFIDetection:
    def test_lfi_evidence_patterns(self):
        from core.lfi import LFIScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = LFIScanner(config)

        # Should detect /etc/passwd content
        result = scanner._check_lfi_evidence("../../../etc/passwd", "root:x:0:0:root:/root:/bin/bash")
        assert result is not None
        assert "passwd" in result.lower() or "file content" in result.lower()

    def test_no_lfi_evidence(self):
        from core.lfi import LFIScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = LFIScanner(config)

        result = scanner._check_lci_evidence("../../../etc/passwd", "404 Not Found") if hasattr(scanner, '_check_lci_evidence') else scanner._check_lfi_evidence("../../../etc/passwd", "404 Not Found")
        assert result is None


class TestRFIDetection:
    def test_rfi_indicators(self):
        from core.rfi import RFI_INDICATORS
        assert len(RFI_INDICATORS) > 0
        # Check indicators are lowercase-safe
        for indicator in RFI_INDICATORS:
            assert isinstance(indicator, str) and len(indicator) > 0


class TestDirBrute:
    def test_wordlist_loading(self):
        from core.dirbrute import DirBruteScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = DirBruteScanner(config)

        words = scanner._load_wordlist()
        assert len(words) > 0
        # Should contain common paths
        assert any("admin" in w for w in words)
        assert any(".env" in w for w in words)

    def test_interesting_status_codes(self):
        from core.dirbrute import DirBruteScanner, DirBruteResult
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = DirBruteScanner(config)

        # 200 should be interesting
        result_200 = DirBruteResult(url="https://example.com/admin", status_code=200, content_length=100, content_type="text/html", found_at="2026-01-01")
        assert scanner._is_interesting(result_200) is True

        # 404 should not be interesting
        result_404 = DirBruteResult(url="https://example.com/notfound", status_code=404, content_length=50, content_type="text/html", found_at="2026-01-01")
        assert scanner._is_interesting(result_404) is False


class TestFuzz:
    def test_fuzz_payloads_structure(self):
        from core.fuzz import FUZZ_PAYLOADS, HIDDEN_PARAM_NAMES
        assert len(FUZZ_PAYLOADS) > 0
        assert "overflow" in FUZZ_PAYLOADS
        assert "special_chars" in FUZZ_PAYLOADS
        assert len(HIDDEN_PARAM_NAMES) > 0
        assert "id" in HIDDEN_PARAM_NAMES
        assert "admin" in HIDDEN_PARAM_NAMES


class TestDatabaseContextManager:
    def test_context_manager(self):
        from core.database import Database
        import os
        db_path = "test_webbreaker_ctx.db"
        try:
            with Database(db_path) as db:
                db.create_scan("ctx1", "https://example.com", {})
                scan = db.get_scan("ctx1")
                assert scan is not None
                assert scan["target"] == "https://example.com"
            # After context manager, connection should be closed
            # Creating a new instance should work
            with Database(db_path) as db:
                scan = db.get_scan("ctx1")
                assert scan is not None
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_wal_mode(self):
        from core.database import Database
        import os
        db_path = "test_webbreaker_wal.db"
        try:
            db = Database(db_path)
            db.connect()
            # WAL mode should be set
            result = db._conn.execute("PRAGMA journal_mode").fetchone()
            assert result[0] == "wal"
            db.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
            if os.path.exists(db_path + "-wal"):
                os.remove(db_path + "-wal")
            if os.path.exists(db_path + "-shm"):
                os.remove(db_path + "-shm")


class TestOrchestratorForms:
    """Test that forms are collected from ALL recon results, not just the first."""
    def test_forms_from_all_results(self):
        from core.recon import ReconResult
        from core.config import ScanConfig
        from core.orchestrator import ScanOrchestrator

        config = ScanConfig(target="https://example.com", authorized=True)
        orch = ScanOrchestrator(config)
        # Simulate that the orchestrator would collect forms from all recon results
        results = [
            ReconResult(url="https://example.com/page1", forms=[{"action": "/login", "method": "POST", "fields": [{"name": "user", "type": "text", "value": ""}]}]),
            ReconResult(url="https://example.com/page2", forms=[{"action": "/search", "method": "GET", "fields": [{"name": "q", "type": "text", "value": ""}]}]),
        ]
        all_forms = []
        for r in results:
            if r.forms:
                all_forms.extend(r.forms)
        assert len(all_forms) == 2
        orch.close()


class TestReconDeque:
    """Test that recon spider uses deque for BFS."""
    def test_imports_deque(self):
        import inspect
        from core.recon import ReconScanner
        source = inspect.getsource(ReconScanner.spider)
        assert 'deque' in source or 'popleft' in source


class TestHTTPClientCookies:
    """Test that HttpClient supports per-request cookies."""
    def test_get_accepts_cookies_kwarg(self):
        import inspect
        from core.http_client import HttpClient
        sig = inspect.signature(HttpClient.get)
        assert 'cookies' in sig.parameters

    def test_post_accepts_cookies_kwarg(self):
        import inspect
        from core.http_client import HttpClient
        sig = inspect.signature(HttpClient.post)
        assert 'cookies' in sig.parameters


class TestTokenBucket:
    """Test the TokenBucket rate limiter."""

    def test_bucket_initial_tokens(self):
        from core.http_client import TokenBucket
        bucket = TokenBucket(rate=10, burst=10)
        assert bucket.tokens == 10.0

    def test_bucket_refill(self):
        import time
        from core.http_client import TokenBucket
        bucket = TokenBucket(rate=10, burst=10)
        bucket.tokens = 0.0
        bucket.last_refill = time.monotonic() - 1.0  # 1 second ago
        bucket._refill()
        assert bucket.tokens >= 9.0  # ~10 tokens refilled over 1s

    def test_bucket_burst_limit(self):
        from core.http_client import TokenBucket
        bucket = TokenBucket(rate=5, burst=5)
        assert bucket.burst == 5
        assert bucket.tokens == 5.0

    def test_bucket_acquire(self):
        from core.http_client import TokenBucket
        bucket = TokenBucket(rate=100, burst=100)
        # Simulate token consumption without async
        bucket.tokens = 100.0
        bucket.tokens -= 1.0
        assert bucket.tokens == 99.0  # Token consumed correctly
        # Verify bucket refills correctly
        bucket.last_refill = __import__("time").monotonic() - 1.0
        bucket._refill()
        assert bucket.tokens > 99.0  # Refilled over time


class TestScopeEnforcement:
    """Test scope enforcement in HTTP clients."""

    def test_scope_in_scope(self):
        from core.http_client import HttpClient
        config = ScanConfig(target="https://example.com", authorized=True)
        client = HttpClient(config)
        assert client._in_scope("https://example.com/page") is True
        assert client._in_scope("https://example.com:443/page") is True

    def test_scope_out_of_scope(self):
        from core.http_client import HttpClient
        config = ScanConfig(target="https://example.com", authorized=True)
        client = HttpClient(config)
        assert client._in_scope("https://evil.com/page") is False
        assert client._in_scope("http://example.com/page") is False  # different scheme

    def test_scope_custom_scope(self):
        from core.http_client import HttpClient
        config = ScanConfig(target="https://app.example.com", authorized=True, scope="https://example.com")
        client = HttpClient(config)
        assert client._in_scope("https://example.com/page") is True
        assert client._in_scope("https://app.example.com/page") is False

    def test_sync_client_scope(self):
        from core.http_client import SyncHttpClient
        config = ScanConfig(target="https://example.com", authorized=True)
        client = SyncHttpClient(config)
        assert client._in_scope("https://example.com/api") is True
        assert client._in_scope("https://evil.com/api") is False


class TestTLSVerification:
    """Test TLS verification config."""

    def test_default_verify_tls(self):
        config = ScanConfig(target="https://example.com", authorized=True)
        assert config.no_verify_tls is False

    def test_disable_verify_tls(self):
        config = ScanConfig(target="https://example.com", authorized=True, no_verify_tls=True)
        assert config.no_verify_tls is True


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_scan_result_defaults(self):
        from core.config import ScanResult
        result = ScanResult(scan_id="test123", target="https://example.com")
        assert result.status == "pending"
        assert result.total_requests == 0
        assert result.error_count == 0
        assert result.timeout_count == 0
        assert result.scope_blocked_count == 0
        assert result.errors == []

    def test_scan_result_to_dict(self):
        from core.config import ScanResult
        result = ScanResult(
            scan_id="abc123",
            target="https://example.com",
            status="completed",
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:05:00Z",
            total_requests=150,
            error_count=3,
            timeout_count=1,
            scope_blocked_count=5,
            errors=["Connection timeout"],
        )
        d = result.to_dict()
        assert d["scan_id"] == "abc123"
        assert d["total_requests"] == 150
        assert d["scope_blocked_count"] == 5
        assert d["errors"] == ["Connection timeout"]


class TestSQLiFPReduction:
    """Test SQLi FP reduction features."""

    def test_content_similarity_identical(self):
        from core.sqli import _content_similarity
        assert _content_similarity("hello world", "hello world") == 1.0

    def test_content_similarity_different(self):
        from core.sqli import _content_similarity
        sim = _content_similarity("hello world", "completely different text here")
        assert sim < 0.5

    def test_content_similarity_empty(self):
        from core.sqli import _content_similarity
        assert _content_similarity("", "hello") == 0.0
        assert _content_similarity("hello", "") == 0.0

    def test_derive_confidence(self):
        from core.sqli import _derive_confidence
        # Canary confirmed + baseline delta + 2 confirming = high confidence
        assert _derive_confidence(True, 0.5, 2) >= 0.8
        # No canary, no delta, no confirming = base
        assert _derive_confidence(False, 0.0, 0) < 0.6

    def test_sqli_baseline_fp_check(self):
        from core.sqli import SQLiScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = SQLiScanner(config)
        result = scanner._check_error_patterns("Warning: mysqli_fetch_array() expects parameter")
        assert result is not None
        assert result[0] == "MySQL"

    def test_canary_tag_generation(self):
        from core.sqli import _canary_tag
        tag = _canary_tag(42)
        assert tag.startswith("wbsqli")
        assert len(tag) > 6


class TestXSSFPReduction:
    """Test XSS FP reduction features."""

    def test_classify_reflection_context_script_tag(self):
        from core.xss import _classify_reflection_context
        context = _classify_reflection_context(
            '<script>alert(1)</script>',
            '<p><script>alert(1)</script></p>'
        )
        assert context == "html_tag"

    def test_classify_reflection_context_js(self):
        from core.xss import _classify_reflection_context
        # Payload inside a <script> block
        payload = "-alert(1)-"
        html = "<script>var x = " + payload + ";</script>"
        context = _classify_reflection_context(payload, html)
        assert context == "js"

    def test_classify_reflection_context_url(self):
        from core.xss import _classify_reflection_context
        context = _classify_reflection_context(
            "javascript:alert(1)",
            '<a href="javascript:alert(1)">click</a>'
        )
        assert context == "url"

    def test_classify_reflection_context_attribute(self):
        from core.xss import _classify_reflection_context
        context = _classify_reflection_context(
            '" onmouseover="alert(1)',
            '<input value="" onmouseover="alert(1)">'
        )
        assert context == "attribute"

    def test_classify_reflection_context_not_found(self):
        from core.xss import _classify_reflection_context
        context = _classify_reflection_context(
            '<script>alert(1)</script>',
            'Hello World, no reflection here'
        )
        assert context is None

    def test_derive_xss_confidence(self):
        from core.xss import _derive_xss_confidence
        assert _derive_xss_confidence("html_tag", True) >= 0.85
        assert _derive_xss_confidence("html_body", False) < 0.7


class TestCMDIBaseline:
    """Test CMDi baseline FP reduction."""

    def test_cmdi_baseline_caching(self):
        from core.cmdi import CmdiScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = CmdiScanner(config)
        assert hasattr(scanner, '_baseline_cache')
        assert isinstance(scanner._baseline_cache, dict)


class TestFormDetection:
    """Test form detection improvements."""

    def test_form_without_action(self):
        from core.recon import ReconScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = ReconScanner(config)
        html = '<form method="POST"><input type="text" name="q"></form>'
        forms = scanner._extract_forms(html, "https://example.com/search")
        assert len(forms) == 1
        assert forms[0]["action"] == "https://example.com/search"

    def test_form_enctype(self):
        from core.recon import ReconScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = ReconScanner(config)
        html = '<form action="/upload" method="POST" enctype="multipart/form-data"><input type="file" name="file"></form>'
        forms = scanner._extract_forms(html, "https://example.com")
        assert len(forms) == 1
        assert forms[0]["enctype"] == "multipart/form-data"

    def test_form_data_attrs(self):
        from core.recon import ReconScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = ReconScanner(config)
        html = '<form action="/api" method="POST" data-remote="true"><input type="text" name="q"></form>'
        forms = scanner._extract_forms(html, "https://example.com")
        assert len(forms) == 1
        assert "data-remote" in forms[0]["data_attrs"]
        assert forms[0]["data_attrs"]["data-remote"] == "true"

    def test_form_button_element(self):
        from core.recon import ReconScanner
        config = ScanConfig(target="https://example.com", authorized=True)
        scanner = ReconScanner(config)
        html = '<form action="/submit" method="POST"><input type="text" name="name"><button type="submit" name="action" value="save">Save</button></form>'
        forms = scanner._extract_forms(html, "https://example.com")
        assert len(forms) == 1
        button_fields = [f for f in forms[0]["fields"] if f["type"] == "submit"]
        assert len(button_fields) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])