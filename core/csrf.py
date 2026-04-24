"""CSRF Detection module — finds missing tokens, weak tokens, and builds PoCs."""

import html
import re
import asyncio
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from typing import Optional

from .config import Finding, Severity, FindingType, ScanConfig
from .http_client import HttpClient


CSRF_TOKEN_NAMES = {
    "csrfmiddlewaretoken", "csrf_token", "csrfmiddlewaretoken",
    "authenticity_token", "_token", "xsrf-token", "anti_forgery_token",
    "csrf", "csrftoken", "_csrf_token", "__requestverificationtoken",
    "csrfmiddlewaretoken", "token", "anticsrf", "__csrf",
}

SAME_SITE_VALUES = {"strict", "lax", "none"}


class CSRFScanner:
    """CSRF vulnerability detection and PoC generation."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(config)
        self.findings: list[Finding] = []

    def _has_csrf_token(self, form: dict) -> bool:
        """Check if a form has a CSRF token field."""
        for field in form["fields"]:
            name_lower = field.get("name", "").lower()
            if name_lower in CSRF_TOKEN_NAMES:
                return True
        return False

    def _check_token_predictability(self, form: dict) -> Optional[str]:
        """Check if CSRF tokens appear predictable or reused."""
        token_fields = []
        for field in form["fields"]:
            name_lower = field.get("name", "").lower()
            if name_lower in CSRF_TOKEN_NAMES:
                token_fields.append(field)

        if not token_fields:
            return None

        for tf in token_fields:
            value = tf.get("value", "")
            # Check for short/predictable tokens
            if len(value) < 16:
                return f"Short token ({len(value)} chars): {value[:8]}..."
            # Check for numeric-only tokens
            if value.isdigit():
                return f"Numeric-only token: {value}"
            # Check for common patterns
            if re.match(r"^[a-f0-9]{8}$", value):
                return f"8-char hex token (low entropy): {value}"
        return None

    async def _check_same_site_cookies(self, url: str) -> list[dict]:
        """Analyze cookie SameSite attributes."""
        resp = await self.client.get(url)
        if not resp:
            return []

        cookies_analysis = []
        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not set_cookie_headers:
            sc = resp.headers.get("set-cookie", "")
            if sc:
                set_cookie_headers = [sc]

        for cookie_header in set_cookie_headers:
            parts = [p.strip().lower() for p in cookie_header.split(";")]
            cookie_name = parts[0].split("=")[0] if "=" in parts[0] else "unknown"

            has_samesite = any("samesite" in p for p in parts)
            samesite_value = None
            for p in parts:
                if "samesite" in p:
                    val = p.split("=")[-1].strip() if "=" in p else ""
                    samesite_value = val if val in SAME_SITE_VALUES else None

            has_secure = any("secure" in p for p in parts)
            has_httponly = any("httponly" in p for p in parts)

            cookies_analysis.append({
                "name": cookie_name,
                "has_samesite": has_samesite,
                "samesite_value": samesite_value,
                "has_secure": has_secure,
                "has_httponly": has_httponly,
                "raw": cookie_header,
            })

        return cookies_analysis

    async def _check_referer_validation(self, url: str, form_action: str) -> bool:
        """Test if the endpoint validates Origin/Referer headers."""
        # Baseline: request with normal headers
        baseline = await self.client.post(form_action, data={"test": "1"})
        if not baseline:
            return False

        baseline_status = baseline.status_code
        baseline_len = len(baseline.content)

        # If baseline itself fails, can't test meaningfully
        if baseline_status >= 400:
            return False

        # Request without Referer
        resp_no_ref = await self.client.post(form_action, headers={"Referer": "", "Origin": ""}, data={"test": "1"})
        if not resp_no_ref:
            return False

        # Request with foreign Referer
        resp_foreign = await self.client.post(form_action, headers={"Referer": "https://evil.com", "Origin": "https://evil.com"}, data={"test": "1"})
        if not resp_foreign:
            return False

        # Weak validation = both bypasses succeed with same status and similar body as baseline
        def _matches_baseline(resp):
            if not resp:
                return False
            return (
                resp.status_code == baseline_status and
                abs(len(resp.content) - baseline_len) < 100
            )

        return _matches_baseline(resp_no_ref) and _matches_baseline(resp_foreign)

    def _generate_poc_html(self, form: dict, target_origin: str) -> str:
        """Generate a CSRF PoC HTML page."""
        fields_html = ""
        for field in form["fields"]:
            name = field.get("name", "")
            value = field.get("value", "")
            if name.lower() not in CSRF_TOKEN_NAMES:
                fields_html += f'    <input type="hidden" name="{html.escape(str(name), quote=True)}" value="{html.escape(str(value), quote=True)}" />\n'

        method = html.escape(str(form.get("method", "POST")), quote=True)
        action = html.escape(str(form.get("action", "")), quote=True)

        poc = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
  <h1>CSRF Proof of Concept</h1>
  <p>This page auto-submits a form to the target. For authorized testing only.</p>
  <form id="csrf_form" action="{action}" method="{method}">
{fields_html}    <input type="submit" value="Submit Request" />
  </form>
  <script>
    // Auto-submit on page load
    document.getElementById('csrf_form').submit();
  </script>
</body>
</html>"""
        return poc

    async def scan_forms(self, forms: list[dict], base_url: str) -> list[Finding]:
        """Analyze forms for CSRF vulnerabilities."""
        findings = []

        for form in forms:
            if form.get("method", "GET").upper() != "POST":
                continue  # GET forms generally not CSRF-relevant

            action = form.get("action", base_url)

            # 1. Missing CSRF token
            if not self._has_csrf_token(form):
                severity = Severity.HIGH
                poc = self._generate_poc_html(form, urlparse(base_url).netloc)
                findings.append(Finding(
                    finding_type=FindingType.CSRF,
                    severity=severity,
                    url=action, parameter="[form]", payload="Missing CSRF token",
                    evidence=f"POST form at {action} has no CSRF token field",
                    remediation="Add anti-CSRF tokens to all state-changing forms. Validate token server-side.",
                    confidence=0.95,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

            # 2. Predictable token
            predictability = self._check_token_predictability(form)
            if predictability:
                findings.append(Finding(
                    finding_type=FindingType.CSRF,
                    severity=Severity.MEDIUM,
                    url=action, parameter="[form]", payload="Weak CSRF token",
                    evidence=predictability,
                    remediation="Use cryptographically random tokens with sufficient entropy (32+ chars).",
                    confidence=0.7,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

            # 3. SameSite cookie check
            cookie_analysis = await self._check_same_site_cookies(base_url)
            for cookie in cookie_analysis:
                if not cookie["has_samesite"] or cookie["samesite_value"] == "none":
                    findings.append(Finding(
                        finding_type=FindingType.CSRF,
                        severity=Severity.MEDIUM,
                        url=base_url, parameter=f"cookie:{cookie['name']}",
                        payload=f"SameSite={cookie.get('samesite_value', 'missing')}",
                        evidence=f"Cookie '{cookie['name']}' SameSite={cookie.get('samesite_value', 'NOT SET')}",
                        remediation='Set SameSite=Strict or SameSite=Lax on all session cookies.',
                        confidence=0.8,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))

            # 4. Referer/Origin validation
            referer_weak = await self._check_referer_validation(base_url, action)
            if referer_weak:
                findings.append(Finding(
                    finding_type=FindingType.CSRF,
                    severity=Severity.MEDIUM,
                    url=action, parameter="[Referer validation]",
                    payload="Missing Referer/Origin validation",
                    evidence="Server accepted requests without valid Referer and with foreign Origin",
                    remediation="Validate Origin and Referer headers on state-changing endpoints.",
                    confidence=0.75,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

        self.findings.extend(findings)
        return findings

    async def close(self):
        await self.client.close()