"""Integration tests for WebBreaker scanners against a deliberately vulnerable Flask app.

These tests spin up a real HTTP server with intentional vulnerabilities
and verify that WebBreaker's scanners detect them correctly.

Run with:
    pytest tests/integration/ --run-integration -v
"""

import pytest

import threading
import time
import warnings

import httpx

from core.config import ScanConfig, FindingType
from core.http_client import HttpClient

# Suppress Flask development server warnings
warnings.filterwarnings("ignore", message=".*development server.*")

# ── Test Server Setup ──────────────────────────────────────────────

_vuln_port = 18888
_vuln_url = f"http://127.0.0.1:{_vuln_port}"
_server_started = False


def _start_vuln_app():
    """Start the vulnerable Flask app in a background thread."""
    global _server_started
    if _server_started:
        return True
    from tests.integration.vulnerable_app import create_app
    app = create_app()
    server = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=_vuln_port, debug=False, use_reloader=False),
        daemon=True,
    )
    server.start()
    # Wait for server to be ready
    for _ in range(50):
        try:
            r = httpx.get(f"{_vuln_url}/", timeout=1)
            if r.status_code == 200:
                _server_started = True
                return True
        except (httpx.ConnectError, httpx.TimeoutException):
            time.sleep(0.1)
    return False


@pytest.fixture(scope="session", autouse=True)
def vuln_server():
    """Start the vulnerable app once per test session."""
    if not _start_vuln_app():
        pytest.skip("Could not start vulnerable Flask app")
    yield


@pytest.fixture
def config():
    """Create a ScanConfig pointing at the vulnerable app."""
    return ScanConfig(target=_vuln_url, authorized=True, depth=2, threads=5, timeout=10)



# ── SQL Injection Integration Tests ────────────────────────────────

class TestSQLiIntegration:
    """Integration tests for SQL injection scanner."""

    @pytest.mark.asyncio
    async def test_sqli_detects_user_endpoint(self, config):
        """SQLi scanner should detect injection in /user?id= endpoint."""
        from core.sqli import SQLiScanner
        scanner = SQLiScanner(config)
        try:
            findings = await scanner.scan_url(f"{_vuln_url}/user", params=[{"name": "id", "type": "query"}])
            sqli_findings = [f for f in findings if f.finding_type == FindingType.SQLI]
            assert len(sqli_findings) > 0, "Should detect SQL injection in /user endpoint"
        finally:
            await scanner.close()

    @pytest.mark.asyncio
    async def test_sqli_finding_has_evidence(self, config):
        """SQLi findings should include evidence."""
        from core.sqli import SQLiScanner
        scanner = SQLiScanner(config)
        try:
            findings = await scanner.scan_url(f"{_vuln_url}/user", params=[{"name": "id", "type": "query"}])
            sqli_findings = [f for f in findings if f.finding_type == FindingType.SQLI]
            if sqli_findings:
                finding = sqli_findings[0]
                assert finding.evidence, "Finding should have evidence"
        finally:
            await scanner.close()


# ── XSS Integration Tests ────────────────────────────────────────────

class TestXSSIntegration:
    """Integration tests for XSS scanner."""

    @pytest.mark.asyncio
    async def test_xss_detects_search_endpoint(self, config):
        """XSS scanner should detect reflected XSS in /search?q= endpoint."""
        from core.xss import XSSScanner
        scanner = XSSScanner(config)
        try:
            findings = await scanner.scan_url(f"{_vuln_url}/search", params=[{"name": "q", "type": "query"}])
            xss_findings = [f for f in findings if f.finding_type == FindingType.XSS]
            assert len(xss_findings) > 0, "Should detect XSS in /search endpoint"
        finally:
            await scanner.close()


# ── Security Headers Integration Tests ──────────────────────────────

class TestHeadersIntegration:
    """Integration tests for security headers scanner."""

    @pytest.mark.asyncio
    async def test_headers_detect_missing_security_headers(self, config):
        """Header scanner should detect missing security headers."""
        from core.headers import HeaderScanner
        scanner = HeaderScanner(config)
        try:
            findings = await scanner.scan(_vuln_url)
            assert len(findings) > 0, "Should detect missing security headers"
            assert all(f.finding_type == FindingType.HEADERS for f in findings)
        finally:
            await scanner.close()


# ── Recon Integration Tests ─────────────────────────────────────────

class TestReconIntegration:
    """Integration tests for reconnaissance scanner."""

    @pytest.mark.asyncio
    async def test_recon_spider_discovers_urls(self, config):
        """Recon scanner should discover URLs via spidering."""
        from core.recon import ReconScanner
        scanner = ReconScanner(config)
        try:
            results = await scanner.spider(_vuln_url)
            assert len(results) > 0, "Should discover at least the homepage"
            urls = [r.url for r in results]
            assert any("/search" in u for u in urls), "Should find /search"
            assert any("/user" in u for u in urls), "Should find /user"
        finally:
            await scanner.close()

    def test_recon_fingerprint_detects_server(self, config):
        """Recon fingerprint should detect server technology."""
        from core.recon import ReconScanner
        scanner = ReconScanner(config)
        results = scanner.fingerprint(_vuln_url)
        assert isinstance(results, dict), "Should return dict"
        assert results.get("status_code") == 200, "Should get 200 from homepage"
        assert "server" in results, "Should include server header"


# ── Command Injection Integration Tests ─────────────────────────────

class TestCMDiIntegration:
    """Integration tests for command injection scanner."""

    @pytest.mark.asyncio
    async def test_cmdi_scans_ping_endpoint(self, config):
        """CMDi scanner should scan the /ping endpoint."""
        from core.cmdi import CmdiScanner
        scanner = CmdiScanner(config)
        try:
            findings = await scanner.scan_url(f"{_vuln_url}/ping", params=[{"name": "host", "type": "query"}])
            assert isinstance(findings, list), "Should return a list of findings"
        finally:
            await scanner.close()


# ── LFI Integration Tests ───────────────────────────────────────────

class TestLFIIntegration:
    """Integration tests for Local File Inclusion scanner."""

    @pytest.mark.asyncio
    async def test_lfi_scans_view_endpoint(self, config):
        """LFI scanner should scan the /view endpoint."""
        from core.lfi import LFIScanner
        scanner = LFIScanner(config)
        try:
            findings = await scanner.scan_url(f"{_vuln_url}/view", params=[{"name": "file", "type": "query"}])
            assert isinstance(findings, list), "Should return a list of findings"
        finally:
            await scanner.close()


# ── CSRF Integration Tests ──────────────────────────────────────────

class TestCSRFIntegration:
    """Integration tests for CSRF scanner."""

    @pytest.mark.asyncio
    async def test_csrf_scans_forms(self, config):
        """CSRF scanner should scan forms without CSRF tokens."""
        from core.csrf import CSRFScanner
        from core.recon import ReconScanner
        # First, get forms from the app
        recon = ReconScanner(config)
        try:
            await recon.spider(_vuln_url)
            forms = recon.get_all_forms()
            if not forms:
                pytest.skip("No forms discovered by recon")
            scanner = CSRFScanner(config)
            findings = await scanner.scan_forms(forms, _vuln_url)
            assert isinstance(findings, list), "Should return findings list"
        finally:
            await recon.close()


# ── Session Analysis Integration Tests ──────────────────────────────

class TestSessionIntegration:
    """Integration tests for session analysis."""

    @pytest.mark.asyncio
    async def test_session_scanner_detects_issues(self, config):
        """Session scanner should detect session issues."""
        from core.session import SessionScanner
        scanner = SessionScanner(config)
        try:
            findings = await scanner.scan(_vuln_url)
            assert isinstance(findings, list), "Should return findings list"
        finally:
            await scanner.close()


# ── Orchestrator Integration Tests ──────────────────────────────────

class TestOrchestratorIntegration:
    """Integration tests for the full scan orchestrator."""

    @pytest.mark.asyncio
    async def test_full_scan_completes(self, config):
        """Full scan against vulnerable app should complete and find issues."""
        from core.orchestrator import ScanOrchestrator
        orchestrator = ScanOrchestrator(config, db_path=":memory:")
        try:
            findings = await orchestrator.run(["recon", "headers"])
            assert isinstance(findings, list), "Should return list of findings"
            assert len(findings) > 0, "Should find at least missing headers"
        finally:
            orchestrator.close()


# ── HTTP Client Integration Tests ───────────────────────────────────

class TestHTTPClientIntegration:
    """Integration tests for the HTTP client against real server."""

    @pytest.mark.asyncio
    async def test_http_client_get(self, config):
        """HttpClient should successfully GET the vulnerable app."""
        client = HttpClient(config)
        try:
            response = await client.get(f"{_vuln_url}/")
            assert response is not None, "Should get a response"
            assert response.status_code == 200
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_http_client_scope_enforcement(self):
        """HttpClient should block out-of-scope requests."""
        config = ScanConfig(target="https://example.com", authorized=True)
        client = HttpClient(config)
        try:
            response = await client.get(f"{_vuln_url}/")
            assert response is None, "Should block out-of-scope request"
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_http_client_rate_limiting(self, config):
        """HttpClient should respect rate limits."""
        import time
        client = HttpClient(config)
        try:
            start = time.time()
            for _ in range(5):
                await client.get(f"{_vuln_url}/")
            elapsed = time.time() - start
            # With default rate_limit=100, 5 requests should complete quickly
            assert elapsed < 10, f"5 requests took {elapsed:.1f}s — rate limiting too aggressive?"
        finally:
            await client.close()