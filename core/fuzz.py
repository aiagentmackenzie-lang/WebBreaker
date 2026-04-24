"""Parameter Fuzzing module — discovers hidden params and anomalies via mutation."""

import asyncio
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime, timezone
from typing import Optional

from .config import Finding, Severity, FindingType, ScanConfig
from .http_client import HttpClient


# Fuzz payloads by category
FUZZ_PAYLOADS = {
    "overflow": [
        "A" * 100, "A" * 500, "A" * 1000, "A" * 5000, "A" * 10000,
    ],
    "format_string": [
        "%s" * 10, "%x" * 10, "%n" * 10, "%p" * 10,
        "%s%s%s%s", "%x%x%x%x",
    ],
    "null_bytes": [
        "test%00", "%00", "test\x00", "test%00.jpg",
    ],
    "type_juggling": [
        "0", "1", "-1", "0.0", "true", "false", "null", "[]", "{}",
    ],
    "special_chars": [
        "'", '"', "`", "\\", "\\\\", "\n", "\r\n", "\t",
        "{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}",
    ],
    "integer_overflow": [
        "2147483647", "2147483648", "-2147483649", "9999999999999",
    ],
    "path_traversal": [
        "../", "..\\", "/etc/passwd", "C:\\Windows\\win.ini",
    ],
}

# Common hidden parameter names to probe
HIDDEN_PARAM_NAMES = [
    "id", "user", "username", "email", "role", "admin", "debug",
    "test", "dev", "api_key", "key", "token", "secret", "password",
    "page", "file", "path", "dir", "cmd", "exec", "query", "search",
    "limit", "offset", "sort", "order", "filter", "include", "exclude",
    "redirect", "url", "next", "return", "callback", "format",
    "lang", "locale", "country", "currency", "timezone",
    "verbose", "dry_run", "mock", "internal", "source",
]


class FuzzScanner:
    """Parameter fuzzing for anomaly and hidden parameter discovery."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(config)
        self.findings: list[Finding] = []
        self._baselines: dict[str, dict] = {}

    async def _get_baseline(self, url: str, method: str = "GET") -> Optional[dict]:
        """Get baseline response for diffing."""
        key = f"{method}:{url}"
        if key in self._baselines:
            return self._baselines[key]

        if method == "GET":
            resp = await self.client.get(url)
        else:
            resp = await self.client.post(url, data={})

        if not resp:
            return None

        baseline = {
            "status": resp.status_code,
            "length": len(resp.content),
            "headers": dict(resp.headers),
            "text_sample": resp.text[:1000],
        }
        self._baselines[key] = baseline
        return baseline

    def _is_anomalous(self, response, baseline: dict) -> Optional[str]:
        """Check if a response differs significantly from baseline."""
        if not response:
            return None

        status_diff = response.status_code != baseline["status"]
        length_diff = abs(len(response.content) - baseline["length"])
        length_pct = length_diff / max(baseline["length"], 1) * 100

        if status_diff and response.status_code in (200, 201, 500):
            if response.status_code == 500 and baseline["status"] != 500:
                return f"Status changed from {baseline['status']} to 500 (server error)"
            return f"Status changed from {baseline['status']} to {response.status_code}"

        if length_pct > 20:
            return f"Response length changed by {length_pct:.0f}% ({baseline['length']} -> {len(response.content)})"

        # Check for error messages not in baseline
        error_keywords = ["error", "exception", "traceback", "stack", "syntax", "fatal"]
        for kw in error_keywords:
            if kw in response.text.lower() and kw not in baseline["text_sample"].lower():
                return f"New error keyword '{kw}' appeared in response"

        return None

    async def fuzz_param(self, url: str, param: str, method: str = "GET") -> list[Finding]:
        """Fuzz a single parameter with various payloads."""
        findings = []
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        baseline = await self._get_baseline(url, method)
        if not baseline:
            return findings

        for category, payloads in FUZZ_PAYLOADS.items():
            for payload in payloads[:5]:  # Limit per category
                if method == "GET":
                    tp = dict(params_dict)
                    tp[param] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
                    resp = await self.client.get(test_url)
                else:
                    resp = await self.client.post(url, data={param: payload})

                if not resp:
                    continue

                anomaly = self._is_anomalous(resp, baseline)
                if anomaly:
                    severity = Severity.HIGH if "500" in anomaly or "error" in anomaly.lower() else Severity.MEDIUM
                    findings.append(Finding(
                        finding_type=FindingType.FUZZ,
                        severity=severity,
                        url=url, parameter=param, payload=f"[{category}] {payload[:50]}",
                        evidence=f"Fuzz anomaly: {anomaly}",
                        response=resp.text[:300],
                        remediation="Validate and sanitize all input. Implement error handling that doesn't leak info.",
                        confidence=0.7,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))

        return findings

    async def discover_params(self, url: str) -> list[Finding]:
        """Probe for hidden parameters by sending common names."""
        findings = []
        baseline = await self._get_baseline(url)
        if not baseline:
            return findings

        for param_name in HIDDEN_PARAM_NAMES:
            test_url = f"{url}{'&' if '?' in url else '?'}{param_name}=test"
            resp = await self.client.get(test_url)
            if not resp:
                continue

            # Check if the parameter is acknowledged (different response)
            anomaly = self._is_anomalous(resp, baseline)
            if anomaly:
                findings.append(Finding(
                    finding_type=FindingType.FUZZ,
                    severity=Severity.LOW,
                    url=url, parameter=param_name, payload="test",
                    evidence=f"Hidden param detected: {anomaly}",
                    remediation="Remove or protect undocumented parameters. Review API exposure.",
                    confidence=0.6,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

        return findings

    async def scan_url(self, url: str, params: list[dict] = None) -> list[Finding]:
        """Fuzz all parameters of a URL."""
        all_findings = []
        if params:
            for p in params:
                findings = await self.fuzz_param(url, p["name"])
                all_findings.extend(findings)
        else:
            parsed = urlparse(url)
            for param_name in parse_qs(parsed.query).keys():
                findings = await self.fuzz_param(url, param_name)
                all_findings.extend(findings)
        # Also discover hidden params
        hidden = await self.discover_params(url)
        all_findings.extend(hidden)
        return all_findings

    async def close(self):
        await self.client.close()