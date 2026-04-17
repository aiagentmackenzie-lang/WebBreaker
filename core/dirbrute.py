"""Directory Brute Force module — discover hidden paths and files."""

import asyncio
import os
from urllib.parse import urljoin
from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict

from .config import Finding, Severity, FindingType, ScanConfig
from .http_client import HttpClient


# Built-in wordlists
COMMON_DIRS = [
    "admin", "login", "dashboard", "api", "config", "backup", "db",
    "test", "dev", "staging", "uploads", "files", "docs", "src",
    "wp-admin", "wp-content", "wp-includes", "cgi-bin", ".git",
    ".env", ".svn", ".hg", "server-status", "server-info",
    "phpmyadmin", "phpinfo", "info", "status", "health",
    "robots.txt", "sitemap.xml", ".well-known", "favicon.ico",
]

COMMON_FILES = [
    ".env", ".htaccess", ".htpasswd", ".gitignore", ".gitconfig",
    "web.config", "config.php", "config.yml", "config.json", "config.ini",
    "database.yml", "database.sql", "db.sql", "dump.sql", "backup.sql",
    "phpinfo.php", "info.php", "test.php", "admin.php", "login.php",
    "wp-config.php", "wp-login.php",
    "package.json", "composer.json", "Gemfile", "requirements.txt",
    "Dockerfile", "docker-compose.yml", ".dockerenv",
    "id_rsa", "id_dsa", ".ssh", "credentials", "secrets",
    "error_log", "access.log", "debug.log", "error.log",
]

COMMON_EXTENSIONS = [
    "", ".php", ".asp", ".aspx", ".jsp", ".py", ".rb", ".js",
    ".html", ".htm", ".txt", ".json", ".xml", ".yml", ".ini",
    ".bak", ".old", ".orig", ".save", ".swp", ".tmp",
    ".zip", ".tar.gz", ".rar", ".sql", ".env",
]


class DirBruteResult:
    def __init__(self, url, status_code, content_length, content_type, found_at):
        self.url = url
        self.status_code = status_code
        self.content_length = content_length
        self.content_type = content_type
        self.found_at = found_at


class DirBruteScanner:
    """Directory and file brute forcing with smart filtering."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(config)
        self.findings: list[Finding] = []
        self.results: list[DirBruteResult] = []
        self._baseline_lengths: dict[int, list[int]] = defaultdict(list)  # status -> lengths

    def _load_wordlist(self, path: Optional[str] = None, extensions: Optional[list[str]] = None) -> list[str]:
        """Load wordlist from file or use built-in."""
        words = []
        if path and os.path.isfile(path):
            with open(path) as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        else:
            words = COMMON_DIRS + COMMON_FILES

        # Add extensions
        exts = extensions or COMMON_EXTENSIONS
        expanded = []
        for word in words:
            if "." in word.split("/")[-1]:
                # Already has extension
                expanded.append(word)
            else:
                for ext in exts:
                    expanded.append(word + ext)
        return expanded

    async def _check_url(self, base_url: str, path: str) -> Optional[DirBruteResult]:
        """Check a single URL path."""
        url = urljoin(base_url, path if path.startswith("/") else f"/{path}")
        resp = await self.client.get(url)
        if not resp:
            return None

        # Filter out 404s and other non-interesting responses
        if resp.status_code in (404, 429, 503):
            return None

        content_length = len(resp.content)
        content_type = resp.headers.get("content-type", "")

        return DirBruteResult(
            url=url, status_code=resp.status_code,
            content_length=content_length, content_type=content_type,
            found_at=datetime.now(timezone.utc).isoformat(),
        )

    def _is_interesting(self, result: DirBruteResult) -> bool:
        """Filter out false positives (custom 404 pages, etc.)."""
        # Record content lengths per status code
        self._baseline_lengths[result.status_code].append(result.content_length)

        # If many responses of the same status have the same length, it's likely a custom error page
        lengths = self._baseline_lengths[result.status_code]
        if len(lengths) > 10:
            from collections import Counter
            counter = Counter(lengths)
            most_common_length, count = counter.most_common(1)[0]
            if count / len(lengths) > 0.8 and result.content_length == most_common_length:
                return False

        # Always interesting: 200, 201, 203, 206, 301, 302, 401, 403
        if result.status_code in (200, 201, 203, 206, 301, 302, 401, 403):
            return True

        return False

    async def scan(self, base_url: str, wordlist_path: Optional[str] = None,
                   extensions: Optional[list[str]] = None,
                   recursive: bool = True,
                   max_depth: int = 2,
                   callback=None) -> list[DirBruteResult]:
        """Brute force directories and files on the target."""
        wordlist = self._load_wordlist(wordlist_path, extensions)
        self.results = []
        self._baseline_lengths = defaultdict(list)

        # Phase 1: Initial scan
        tasks = []
        sem = asyncio.Semaphore(self.config.threads)

        async def bounded_check(path):
            async with sem:
                result = await self._check_url(base_url, path)
                if result and self._is_interesting(result):
                    self.results.append(result)
                    if callback:
                        callback(result)
                return result

        # Batch requests
        batch_size = self.config.threads * 2
        for i in range(0, len(wordlist), batch_size):
            batch = wordlist[i:i + batch_size]
            tasks = [bounded_check(path) for path in batch]
            await asyncio.gather(*tasks, return_exceptions=True)

        # Phase 2: Recursive scan of discovered directories
        if recursive:
            dirs_to_recurse = [
                r for r in self.results
                if r.status_code in (200, 301, 302, 403)
                and r.url.endswith("/")
                and not r.url.endswith("//")
            ][:max_depth * 5]

            depth = 0
            while dirs_to_recurse and depth < max_depth:
                next_dirs = []
                for dir_result in dirs_to_recurse:
                    for path in COMMON_DIRS[:20]:  # Smaller wordlist for recursion
                        result = await self._check_url(dir_result.url, path)
                        if result and self._is_interesting(result):
                            result.url = urljoin(dir_result.url, path)
                            self.results.append(result)
                            if result.status_code in (200, 301, 302, 403) and result.url.endswith("/"):
                                next_dirs.append(result)
                            if callback:
                                callback(result)
                dirs_to_recurse = next_dirs
                depth += 1

        # Convert interesting results to findings
        for result in self.results:
            severity = Severity.INFO
            if any(s in result.url.lower() for s in [".env", "config", "credential", "secret", ".git"]):
                severity = Severity.HIGH
            elif any(s in result.url.lower() for s in ["admin", "phpmyadmin", "backup", "dump", ".sql"]):
                severity = Severity.MEDIUM
            elif result.status_code == 403:
                severity = Severity.LOW

            self.findings.append(Finding(
                finding_type=FindingType.DIRBRUTE,
                severity=severity,
                url=result.url, parameter="[path]", payload=result.url.split(base_url)[-1],
                evidence=f"Status {result.status_code}, Content-Length {result.content_length}, Type {result.content_type}",
                remediation="Remove sensitive files. Restrict access with authentication. Disable directory listing.",
                confidence=0.9 if result.status_code == 200 else 0.7,
                timestamp=result.found_at,
            ))

        return self.results

    async def close(self):
        await self.client.close()