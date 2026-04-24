"""Reconnaissance & Spidering module — discovers attack surface."""

import re
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Optional
from bs4 import BeautifulSoup

from .config import ScanConfig
from .http_client import HttpClient


# Tech fingerprint signatures
TECH_SIGNATURES = {
    "PHP": [r"\.php", r"X-Powered-By: PHP", r"PHPSESSID"],
    "ASP.NET": [r"\.aspx?", r"X-AspNet-Version", r"__VIEWSTATE", r"ASP.NET_SessionId"],
    "Django": [r"csrfmiddlewaretoken", r"X-Frame-Options: DENY", r"djdt"],
    "Flask": [r"flask", r"X-Session-Id"],
    "Express": [r"X-Powered-By: Express", r"etag: W/"],
    "Nginx": [r"Server: nginx", r"nginx/"],
    "Apache": [r"Server: Apache", r"apache/"],
    "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
    "jQuery": [r"jquery", r"jQuery v"],
    "React": [r"__NEXT_DATA__", r"_next/", r"react", r"data-reactroot"],
    "Vue": [r"vue", r"data-v-", r"__vue__"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN", r"laravel"],
    "Ruby on Rails": [r"csrf-token", r"authenticity_token", r"X-Runtime"],
    "Spring Boot": [r"X-Application-Context", r"spring"],
}


class ReconResult:
    def __init__(self, url, method="GET", status_code=0, content_length=0,
                 content_type="", tech=None, forms=None, links=None, params=None, depth=0):
        self.url = url
        self.method = method
        self.status_code = status_code
        self.content_length = content_length
        self.content_type = content_type
        self.tech = tech or []
        self.forms = forms or []
        self.links = links or []
        self.params = params or []
        self.depth = depth


class ReconScanner:
    """Reconnaissance & web spider for attack surface discovery."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(config)
        self.visited: set[str] = set()
        self.results: list[ReconResult] = []
        self.scope_domain = urlparse(config.scope).netloc

    def _in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.netloc == self.scope_domain or parsed.netloc.endswith(f".{self.scope_domain}")

    def _detect_tech(self, response, html: str) -> list[str]:
        """Detect technologies from response headers and HTML."""
        detected = []
        headers_str = " ".join(f"{k}: {v}" for k, v in response.headers.items()) if response else ""
        combined = f"{headers_str} {html}"

        for tech, patterns in TECH_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.append(tech)
                    break
        return detected

    def _extract_forms(self, html: str, base_url: str) -> list[dict]:
        """Extract forms with their fields and actions."""
        soup = BeautifulSoup(html, "lxml")
        forms = []
        for form in soup.find_all("form"):
            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                field = {
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                }
                fields.append(field)
            forms.append({
                "action": urljoin(base_url, form.get("action", "")),
                "method": form.get("method", "GET").upper(),
                "fields": fields,
                "has_csrf_token": any(
                    f["name"].lower() in ("csrfmiddlewaretoken", "csrf_token",
                                           "authenticity_token", "_token",
                                           "csrfmiddlewaretoken", "xsrf-token",
                                           "anti_forgery_token")
                    for f in fields
                ),
            })
        return forms

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract and resolve all links from HTML."""
        soup = BeautifulSoup(html, "lxml")
        links = []
        for tag in soup.find_all(["a", "link", "script", "img", "iframe"]):
            href = tag.get("href") or tag.get("src")
            if href:
                full_url = urljoin(base_url, href)
                if self._in_scope(full_url):
                    links.append(full_url)
        return list(set(links))

    def _extract_params(self, url: str) -> list[dict]:
        """Extract URL parameters."""
        parsed = urlparse(url)
        params = []
        for name, values in parse_qs(parsed.query).items():
            for value in values:
                params.append({"name": name, "value": value})
        return params

    async def spider(self, start_url: str, callback=None) -> list[ReconResult]:
        """Crawl the target site up to configured depth."""
        queue = [(start_url, 0)]
        self.visited = set()
        self.results = []

        while queue:
            url, depth = queue.pop(0)
            if url in self.visited or depth > self.config.depth:
                continue
            if not self._in_scope(url):
                continue

            self.visited.add(url)

            resp = await self.client.get(url)
            if not resp:
                continue

            html = resp.text
            content_type = resp.headers.get("content-type", "")

            # Only parse HTML responses
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                result = ReconResult(
                    url=url, status_code=resp.status_code,
                    content_length=len(resp.content), content_type=content_type,
                    depth=depth,
                )
                self.results.append(result)
                if callback:
                    callback(result)
                continue

            tech = self._detect_tech(resp, html)
            forms = self._extract_forms(html, url)
            links = self._extract_links(html, url)
            params = self._extract_params(url)

            result = ReconResult(
                url=url, status_code=resp.status_code,
                content_length=len(resp.content), content_type=content_type,
                tech=tech, forms=forms, links=links, params=params, depth=depth,
            )
            self.results.append(result)
            if callback:
                callback(result)

            # Add discovered links to queue
            for link in links:
                if link not in self.visited and depth < self.config.depth:
                    queue.append((link, depth + 1))

            # Add form actions to queue
            for form in forms:
                if form["action"] not in self.visited:
                    queue.append((form["action"], depth + 1))

        await self.client.close()
        return self.results

    def get_all_urls(self) -> list[str]:
        return [r.url for r in self.results]

    def get_all_forms(self) -> list[dict]:
        all_forms = []
        for r in self.results:
            all_forms.extend(r.forms)
        return all_forms

    def get_all_params(self) -> list[dict]:
        all_params = []
        for r in self.results:
            all_params.extend(r.params)
        return all_params

    def get_detected_tech(self) -> list[str]:
        all_tech = set()
        for r in self.results:
            all_tech.update(r.tech)
        return list(all_tech)

    def fingerprint(self, url: str) -> dict:
        """Quick tech fingerprint without full spider."""
        from .http_client import SyncHttpClient
        client = SyncHttpClient(self.config)
        resp = client.get(url)
        if not resp:
            return {"url": url, "tech": [], "status": "error"}
        html = resp.text
        tech = self._detect_tech(resp, html)
        return {
            "url": url,
            "status_code": resp.status_code,
            "tech": tech,
            "server": resp.headers.get("server", ""),
            "content_type": resp.headers.get("content-type", ""),
            "content_length": len(resp.content),
            "headers": dict(resp.headers),
        }