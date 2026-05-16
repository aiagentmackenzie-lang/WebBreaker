"""Command Injection scanner — OS command injection detection (Linux + Windows).

FP reduction strategy:
- Time-based: 2-sample baseline, require ≥3× baseline AND ≥4.5s absolute
- Output-based: verify marker is in response AND not in baseline
- Error-based: verify error pattern not in baseline response
- Filter bypass: same baseline check
- Confidence scoring based on evidence quality
- Request/response logging: store full HTTP data in findings
"""

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
    '; ec\\ho CMDI_WEBBREAKER_7341',  # backslash escape: echo -> ec\ho
    '; ec\x00ho CMDI_WEBBREAKER_7341',  # null byte bypass: ec\x00ho
    "|cmd /c echo CMDI_WEBBREAKER_7341",
    ";printf 'CMDI_WEBBREAKER_7341'",
    "|ping -c 1 127.0.0.1",
    "%0aecho CMDI_WEBBREAKER_7341",
    "%0decho CMDI_WEBBREAKER_7341",
]

MARKER = "CMDI_WEBBREAKER_7341"


class CmdiScanner:
    """OS Command Injection detection with baseline FP reduction."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(config)
        self.findings: list[Finding] = []
        self._baseline_cache: dict[str, str] = {}  # url -> baseline text

    async def _get_baseline(self, url: str) -> Optional[str]:
        """Get baseline response for FP comparison."""
        if url in self._baseline_cache:
            return self._baseline_cache[url]
        resp = await self.client.get(url)
        if resp:
            self._baseline_cache[url] = resp.text[:2000]
            return self._baseline_cache[url]
        return None

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
        """Test a parameter for command injection with baseline FP reduction."""
        findings = []
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        original_value = params_dict.get(param, [""])[0]

        # Get baseline for FP comparison
        baseline = await self._get_baseline(url)

        # 1. Time-based detection — 2-sample baseline
        baseline_time = None
        baseline_start = time.monotonic()
        baseline_resp = await self.client.get(url)
        baseline_time = time.monotonic() - baseline_start if baseline_resp else 2.0

        # Take second baseline sample for reliability
        if baseline_time < 1.0:
            baseline_start2 = time.monotonic()
            baseline_resp2 = await self.client.get(url)
            if baseline_resp2:
                second_time = time.monotonic() - baseline_start2
                baseline_time = max(baseline_time, second_time)

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

            if resp and elapsed >= max(4.5, baseline_time * 3):
                confidence = 0.85 if baseline_time < 1.0 else 0.80
                findings.append(Finding(
                    finding_type=FindingType.CMDI,
                    severity=Severity.CRITICAL,
                    url=url, parameter=param, payload=payload,
                    evidence=f"Time-based: response took {elapsed:.2f}s (baseline {baseline_time:.2f}s, ratio {elapsed/max(baseline_time,0.01):.1f}x)",
                    request=f"GET {url}" if method == "GET" else f"POST {url} [{param}={test_value[:100]}]",
                    response=resp.text[:500] if resp else "",
                    remediation="Never pass user input to OS commands. Use language-native APIs instead.",
                    confidence=confidence,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))
                break

        # 2. Output-based detection — verify marker not in baseline
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

                # FP check: marker should NOT be in baseline
                if self._check_output_marker(resp.text):
                    if baseline and MARKER in baseline:
                        continue  # Marker in baseline — false positive
                    findings.append(Finding(
                        finding_type=FindingType.CMDI,
                        severity=Severity.CRITICAL,
                        url=url, parameter=param, payload=payload,
                        evidence=f"Output marker '{MARKER}' found in response" + (" (baseline checked)" if baseline else ""),
                        request=f"GET {url}" if method == "GET" else f"POST {url} [{param}={test_value[:100]}]",
                        response=resp.text[:500],
                        remediation="Never pass user input to OS commands. Use allowlisted commands only.",
                        confidence=0.95,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    break

                cmd_output = self._check_command_output(resp.text)
                if cmd_output:
                    if baseline:
                        # Check if the same pattern exists in baseline
                        if self._check_command_output(baseline):
                            continue  # Pattern in baseline — likely FP
                    findings.append(Finding(
                        finding_type=FindingType.CMDI,
                        severity=Severity.CRITICAL,
                        url=url, parameter=param, payload=payload,
                        evidence=f"Command output detected: {cmd_output}" + (" (baseline checked)" if baseline else ""),
                        request=f"GET {url}" if method == "GET" else f"POST {url} [{param}={test_value[:100]}]",
                        response=resp.text[:500],
                        remediation="Never pass user input to OS commands. Use language-native APIs.",
                        confidence=0.90,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    break

        # 3. Error-based detection — verify error not in baseline
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
                    # FP check: error pattern in baseline?
                    if baseline:
                        baseline_error = self._check_error_patterns(baseline)
                        if baseline_error and baseline_error[1] == error[1]:
                            continue  # Same error in baseline — likely FP
                    findings.append(Finding(
                        finding_type=FindingType.CMDI,
                        severity=Severity.HIGH,
                        url=url, parameter=param, payload=payload,
                        evidence=f"Error-based: {error[0]} — {error[1]}" + (" (baseline checked)" if baseline else ""),
                        request=f"GET {url}" if method == "GET" else f"POST {url} [{param}={test_value[:100]}]",
                        response=resp.text[:500],
                        remediation="Never pass user input to OS commands. Validate and sanitize all input.",
                        confidence=0.80,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    break

        # 4. Filter bypass attempts — baseline check
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

                if resp:
                    marker_found = self._check_output_marker(resp.text)
                    error = self._check_error_patterns(resp.text)
                    # FP checks
                    if marker_found and baseline and MARKER in baseline:
                        continue
                    if error and baseline:
                        baseline_error = self._check_error_patterns(baseline)
                        if baseline_error and baseline_error[1] == error[1]:
                            continue

                    if marker_found or error:
                        evidence = f"Marker found" if marker_found else f"Error: {error[1]}"
                        findings.append(Finding(
                            finding_type=FindingType.CMDI,
                            severity=Severity.HIGH,
                            url=url, parameter=param, payload=f"[bypass] {payload}",
                            evidence=f"Filter bypass: {evidence}" + (" (baseline checked)" if baseline else ""),
                            request=f"GET {url}" if method == "GET" else f"POST {url} [{param}={test_value[:100]}]",
                            response=resp.text[:500],
                            remediation="Fix underlying injection AND improve input filtering. Use allowlists.",
                            confidence=0.75,
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