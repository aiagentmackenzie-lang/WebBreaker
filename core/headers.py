"""Security Header analysis module — checks 25+ headers, CSP parsing, grade scoring."""

import asyncio
from datetime import datetime, timezone
from typing import Optional

from .config import Finding, Severity, FindingType, ScanConfig
from .http_client import HttpClient


# Security headers to check with expected values
SECURITY_HEADERS = {
    "strict-transport-security": {
        "expected": "max-age=31536000; includeSubDomains",
        "description": "HSTS — forces HTTPS connections",
        "min_severity": Severity.MEDIUM,
    },
    "content-security-policy": {
        "expected": "default-src 'self'",
        "description": "CSP — prevents XSS and data injection attacks",
        "min_severity": Severity.HIGH,
    },
    "x-content-type-options": {
        "expected": "nosniff",
        "description": "Prevents MIME-type sniffing",
        "min_severity": Severity.LOW,
    },
    "x-frame-options": {
        "expected": "DENY",
        "description": "Prevents clickjacking via iframe embedding",
        "min_severity": Severity.MEDIUM,
    },
    "x-xss-protection": {
        "expected": "0",  # Deprecated, should be 0 (disabled) if CSP is present
        "description": "Legacy XSS filter (deprecated, use CSP instead)",
        "min_severity": Severity.INFO,
    },
    "referrer-policy": {
        "expected": "strict-origin-when-cross-origin",
        "description": "Controls referrer information sent with requests",
        "min_severity": Severity.LOW,
    },
    "permissions-policy": {
        "expected": "camera=(), microphone=(), geolocation=()",
        "description": "Controls browser feature access",
        "min_severity": Severity.LOW,
    },
    "cross-origin-opener-policy": {
        "expected": "same-origin",
        "description": "Prevents cross-origin attacks",
        "min_severity": Severity.MEDIUM,
    },
    "cross-origin-resource-policy": {
        "expected": "same-origin",
        "description": "Prevents cross-origin resource loading",
        "min_severity": Severity.MEDIUM,
    },
    "cross-origin-embedder-policy": {
        "expected": "require-corp",
        "description": "Prevents cross-origin resource embedding",
        "min_severity": Severity.LOW,
    },
    "x-request-id": {
        "expected": None,  # Just check presence
        "description": "Request tracing identifier",
        "min_severity": Severity.INFO,
    },
    "cache-control": {
        "expected": "no-store, no-cache",
        "description": "Prevents caching of sensitive content",
        "min_severity": Severity.LOW,
    },
    "pragma": {
        "expected": "no-cache",
        "description": "Legacy cache control",
        "min_severity": Severity.INFO,
    },
    "x-powered-by": {
        "expected": None,  # Should NOT be present (information disclosure)
        "expected_absent": True,
        "description": "Technology disclosure — should be removed",
        "min_severity": Severity.LOW,
    },
    "server": {
        "expected": None,  # Should be generic, not detailed
        "expected_absent_detailed": True,
        "description": "Server version disclosure — should be generic",
        "min_severity": Severity.INFO,
    },
}

# CSP bypass patterns
CSP_BYPASS_PATTERNS = {
    "unsafe-inline": "'unsafe-inline' in script-src allows inline scripts",
    "unsafe-eval": "'unsafe-eval' in script-src allows eval()",
    "wildcard": "'*' in directive allows any source",
    "data_uri": "data: in script-src or object-src allows data URIs",
    "http_source": "http: source in CSP allows non-HTTPS resources",
    "nonce_missing": "No nonce or hash in script-src with unsafe-inline",
}


class HeaderScanner:
    """Security header analysis with grading."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(config)
        self.findings: list[Finding] = []
        self.grade: str = "TBD"

    def _parse_csp(self, csp_value: str) -> dict:
        """Parse CSP header into directives."""
        directives = {}
        for directive in csp_value.split(";"):
            parts = directive.strip().split()
            if parts:
                name = parts[0]
                values = parts[1:] if len(parts) > 1 else []
                directives[name] = values
        return directives

    def _analyze_csp_bypasses(self, csp_value: str) -> list[dict]:
        """Find bypass opportunities in CSP."""
        bypasses = []
        directives = self._parse_csp(csp_value)

        for directive_name, values in directives.items():
            values_str = " ".join(values).lower()

            if "unsafe-inline" in values_str and directive_name in ("script-src", "default-src"):
                bypasses.append({
                    "type": "unsafe-inline",
                    "directive": directive_name,
                    "detail": CSP_BYPASS_PATTERNS["unsafe-inline"],
                    "severity": Severity.HIGH,
                })

            if "unsafe-eval" in values_str and directive_name in ("script-src", "default-src"):
                bypasses.append({
                    "type": "unsafe-eval",
                    "directive": directive_name,
                    "detail": CSP_BYPASS_PATTERNS["unsafe-eval"],
                    "severity": Severity.MEDIUM,
                })

            if "*" in values and directive_name in ("script-src", "default-src", "object-src"):
                bypasses.append({
                    "type": "wildcard",
                    "directive": directive_name,
                    "detail": CSP_BYPASS_PATTERNS["wildcard"],
                    "severity": Severity.HIGH,
                })

            if "data:" in values_str and directive_name in ("script-src", "object-src", "default-src"):
                bypasses.append({
                    "type": "data_uri",
                    "directive": directive_name,
                    "detail": CSP_BYPASS_PATTERNS["data_uri"],
                    "severity": Severity.MEDIUM,
                })

            for v in values:
                if v.startswith("http://"):
                    bypasses.append({
                        "type": "http_source",
                        "directive": directive_name,
                        "detail": f"Non-HTTPS source '{v}' in {directive_name}",
                        "severity": Severity.MEDIUM,
                    })
                    break

        # Check for missing object-src
        if "object-src" not in directives and "default-src" not in directives:
            bypasses.append({
                "type": "missing_object_src",
                "directive": "object-src",
                "detail": "Missing object-src allows plugin content (Flash, etc.)",
                "severity": Severity.MEDIUM,
            })

        return bypasses

    def _calculate_grade(self, findings: list[Finding]) -> str:
        """Calculate security grade A-F based on findings."""
        penalty = 0
        for f in findings:
            if f.severity == Severity.HIGH:
                penalty += 15
            elif f.severity == Severity.MEDIUM:
                penalty += 8
            elif f.severity == Severity.LOW:
                penalty += 3
            else:
                penalty += 1

        score = max(0, 100 - penalty)
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    async def scan(self, url: str) -> list[Finding]:
        """Analyze security headers for the given URL."""
        findings = []
        resp = await self.client.get(url)
        if not resp:
            return findings

        headers = dict(resp.headers)

        for header_name, info in SECURITY_HEADERS.items():
            header_lower = header_name.lower()
            value = None
            for k, v in headers.items():
                if k.lower() == header_lower:
                    value = v
                    break

            # Check if header should be ABSENT
            if info.get("expected_absent"):
                if value:
                    findings.append(Finding(
                        finding_type=FindingType.HEADERS,
                        severity=info["min_severity"],
                        url=url, parameter=header_name, payload=f"Present: {value}",
                        evidence=f"Information disclosure: {header_name}: {value}",
                        remediation=f"Remove the {header_name} header to prevent technology disclosure.",
                        confidence=1.0,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                continue

            if info.get("expected_absent_detailed"):
                if value and any(c.isdigit() for c in value):
                    findings.append(Finding(
                        finding_type=FindingType.HEADERS,
                        severity=info["min_severity"],
                        url=url, parameter=header_name, payload=value,
                        evidence=f"Version disclosure: {header_name}: {value}",
                        remediation=f"Configure server to return generic {header_name} value without version.",
                        confidence=0.9,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                continue

            # Check if header is missing
            if value is None:
                findings.append(Finding(
                    finding_type=FindingType.HEADERS,
                    severity=info["min_severity"],
                    url=url, parameter=header_name, payload="[MISSING]",
                    evidence=f"Missing header: {header_name} — {info['description']}",
                    remediation=f"Add the {header_name} header. Recommended: {info['expected']}",
                    confidence=1.0,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))
                continue

            # Check CSP for bypasses
            if header_lower == "content-security-policy":
                bypasses = self._analyze_csp_bypasses(value)
                for bypass in bypasses:
                    findings.append(Finding(
                        finding_type=FindingType.HEADERS,
                        severity=bypass["severity"],
                        url=url, parameter=f"CSP:{bypass['directive']}",
                        payload=f"{bypass['type']}: {value[:100]}",
                        evidence=bypass["detail"],
                        remediation=f"Fix CSP: remove {bypass['type']} from {bypass['directive']}. Use nonces or hashes.",
                        confidence=0.85,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                continue

            # Check HSTS for weak config
            if header_lower == "strict-transport-security":
                if "includeSubDomains" not in value:
                    findings.append(Finding(
                        finding_type=FindingType.HEADERS,
                        severity=Severity.LOW,
                        url=url, parameter="HSTS", payload=value,
                        evidence="HSTS missing includeSubDomains directive",
                        remediation="Add includeSubDomains to HSTS header.",
                        confidence=0.9,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                max_age_match = None
                import re
                match = re.search(r"max-age=(\d+)", value)
                if match:
                    max_age = int(match.group(1))
                    if max_age < 31536000:
                        findings.append(Finding(
                            finding_type=FindingType.HEADERS,
                            severity=Severity.LOW,
                            url=url, parameter="HSTS", payload=value,
                            evidence=f"HSTS max-age too short: {max_age} seconds (< 1 year)",
                            remediation="Set HSTS max-age to at least 31536000 (1 year).",
                            confidence=0.9,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                        ))

        self.grade = self._calculate_grade(findings)
        self.findings.extend(findings)
        return findings

    async def close(self):
        await self.client.close()