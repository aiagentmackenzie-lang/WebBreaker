"""Session Analysis module — cookie security, session fixation, token entropy."""

import re
import math
import asyncio
from collections import Counter
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Optional

from .config import Finding, Severity, FindingType, ScanConfig
from .http_client import HttpClient


class SessionScanner:
    """Session and cookie security analysis."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(config)
        self.findings: list[Finding] = []

    def _calculate_entropy(self, value: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not value:
            return 0.0
        counter = Counter(value)
        length = len(value)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _parse_cookies(self, set_cookie_headers: list[str]) -> list[dict]:
        """Parse Set-Cookie headers into structured data."""
        cookies = []
        for header in set_cookie_headers:
            parts = [p.strip() for p in header.split(";")]
            if not parts:
                continue

            name_value = parts[0]
            if "=" not in name_value:
                continue

            name, value = name_value.split("=", 1)
            cookie = {
                "name": name.strip(),
                "value": value.strip(),
                "raw": header,
                "attributes": {},
            }

            for part in parts[1:]:
                part_lower = part.lower().strip()
                if "=" in part:
                    attr_name, attr_value = part.split("=", 1)
                    cookie["attributes"][attr_name.strip().lower()] = attr_value.strip()
                else:
                    cookie["attributes"][part_lower] = True

            cookies.append(cookie)
        return cookies

    async def scan(self, url: str) -> list[Finding]:
        """Analyze session and cookie security for a URL."""
        findings = []

        # 1. Get initial response and capture cookies
        resp = await self.client.get(url)
        if not resp:
            return findings

        set_cookie_headers = []
        # httpx stores cookies differently
        for key, value in resp.headers.multi_items():
            if key.lower() == "set-cookie":
                set_cookie_headers.append(value)

        if not set_cookie_headers:
            # No cookies at all — might be an API endpoint
            return findings

        cookies = self._parse_cookies(set_cookie_headers)

        # 2. Analyze each cookie
        for cookie in cookies:
            name = cookie["name"]
            value = cookie["value"]
            attrs = cookie["attributes"]

            # Check Secure flag
            if not attrs.get("secure"):
                findings.append(Finding(
                    finding_type=FindingType.SESSION,
                    severity=Severity.MEDIUM,
                    url=url, parameter=f"cookie:{name}", payload="[Missing Secure flag]",
                    evidence=f"Cookie '{name}' missing Secure flag — can be sent over HTTP",
                    remediation="Add Secure flag to all session cookies to prevent HTTP transmission.",
                    confidence=1.0,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

            # Check HttpOnly flag
            if not attrs.get("httponly"):
                # Only flag session-related cookies
                session_keywords = ["session", "sess", "sid", "token", "auth", "login"]
                if any(kw in name.lower() for kw in session_keywords):
                    findings.append(Finding(
                        finding_type=FindingType.SESSION,
                        severity=Severity.MEDIUM,
                        url=url, parameter=f"cookie:{name}", payload="[Missing HttpOnly flag]",
                        evidence=f"Session cookie '{name}' missing HttpOnly flag — accessible via JavaScript (XSS risk)",
                        remediation="Add HttpOnly flag to session cookies to prevent JavaScript access.",
                        confidence=1.0,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))

            # Check SameSite attribute
            samesite = attrs.get("samesite", "").lower() if isinstance(attrs.get("samesite"), str) else ""
            if not samesite or samesite == "none":
                findings.append(Finding(
                    finding_type=FindingType.SESSION,
                    severity=Severity.MEDIUM,
                    url=url, parameter=f"cookie:{name}",
                    payload=f"SameSite={samesite or 'NOT SET'}",
                    evidence=f"Cookie '{name}' SameSite={samesite or 'NOT SET'} — vulnerable to CSRF",
                    remediation='Set SameSite=Strict or SameSite=Lax on all cookies.',
                    confidence=0.9,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

            # Check token entropy
            entropy = self._calculate_entropy(value)
            if len(value) > 8 and entropy < 3.0:
                findings.append(Finding(
                    finding_type=FindingType.SESSION,
                    severity=Severity.HIGH,
                    url=url, parameter=f"cookie:{name}", payload=f"Entropy: {entropy:.2f}",
                    evidence=f"Low entropy ({entropy:.2f} bits/char) in cookie '{name}' — may be predictable",
                    remediation="Use cryptographically random tokens with sufficient entropy (128+ bits).",
                    confidence=0.7,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

            # Check for short session IDs
            if any(kw in name.lower() for kw in session_keywords) and len(value) < 16:
                findings.append(Finding(
                    finding_type=FindingType.SESSION,
                    severity=Severity.HIGH,
                    url=url, parameter=f"cookie:{name}", payload=f"Length: {len(value)}",
                    evidence=f"Short session ID ({len(value)} chars) in cookie '{name}' — brute-forceable",
                    remediation="Use session tokens of at least 128 bits (16+ bytes, 32+ hex chars).",
                    confidence=0.8,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

        # 3. Test session fixation — does the server accept a pre-set session ID?
        session_cookies = [c for c in cookies if any(kw in c["name"].lower() for kw in session_keywords)]
        if session_cookies:
            session_cookie = session_cookies[0]
            # Send request with a custom session ID
            custom_session_id = "WEBBREAKER_FIXATION_TEST_1234567890"
            test_cookies = {session_cookie["name"]: custom_session_id}

            resp2 = await self.client.get(url, cookies=test_cookies)
            if resp2:
                # Check if the server accepted our custom session ID
                for key, value in resp2.headers.multi_items():
                    if key.lower() == "set-cookie" and session_cookie["name"] in value:
                        if custom_session_id not in value:
                            # Server issued a new session ID — good, not vulnerable
                            pass
                        else:
                            findings.append(Finding(
                                finding_type=FindingType.SESSION,
                                severity=Severity.HIGH,
                                url=url, parameter=f"cookie:{session_cookie['name']}",
                                payload="[Session fixation]",
                                evidence=f"Server accepted pre-set session ID for '{session_cookie['name']}'",
                                remediation="Regenerate session ID after authentication. Never accept client-supplied session IDs.",
                                confidence=0.85,
                                timestamp=datetime.now(timezone.utc).isoformat(),
                            ))

        # 4. Check for missing security headers related to sessions
        hsts = resp.headers.get("strict-transport-security", "")
        if not hsts:
            findings.append(Finding(
                finding_type=FindingType.SESSION,
                severity=Severity.MEDIUM,
                url=url, parameter="[HSTS]", payload="[Missing]",
                evidence="No Strict-Transport-Security header — session cookies can be intercepted over HTTP",
                remediation="Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                confidence=0.9,
                timestamp=datetime.now(timezone.utc).isoformat(),
            ))

        self.findings.extend(findings)
        return findings

    async def close(self):
        await self.client.close()