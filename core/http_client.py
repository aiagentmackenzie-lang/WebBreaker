"""Shared HTTP client with rate limiting, proxy support, scope enforcement, and retry logic."""

import time
import random
import asyncio
from typing import Optional
from urllib.parse import urlparse
import httpx
from rich.console import Console

console = Console()


class TokenBucket:
    """Token bucket rate limiter with jitter — actual req/sec throttle.

    Allows burst up to ``burst`` tokens, then refills at ``rate`` tokens/sec.
    Jitter is added to avoid thundering-herd synchronisation across concurrent scanners.
    """

    def __init__(self, rate: float, burst: int | None = None):
        """Create a bucket that refills at *rate* tokens/sec."""
        self.rate = rate  # tokens per second
        self.burst = burst or max(1, int(rate))  # allow short bursts
        self.tokens = float(self.burst)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available (with jitter)."""
        while True:
            async with self._lock:
                self._refill()
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    # Small random jitter: 0-50ms to desynchronise concurrent scanners
                    jitter = random.uniform(0, 0.05)
                    if jitter > 0:
                        await asyncio.sleep(jitter)
                    return
            # Not enough tokens — sleep until one is available + small jitter
            wait = (1.0 - self.tokens) / self.rate + random.uniform(0, 0.05)
            await asyncio.sleep(wait)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now

    @property
    def available(self) -> float:
        """Return approximate tokens available (no lock)."""
        self._refill()
        return self.tokens


class HttpClient:
    """Async HTTP client with token-bucket rate limiting and scope enforcement."""

    def __init__(self, config):
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None
        # Token bucket: rate_limit tokens/sec, burst = max(1, rate_limit)
        self._bucket = TokenBucket(
            rate=max(1, config.rate_limit),
            burst=max(1, config.rate_limit),
        )

    @property
    def scope_origin(self) -> str:
        """Return the origin (scheme://host:port) of the configured scope."""
        parsed = urlparse(self.config.scope or self.config.target)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return f"{parsed.scheme}://{parsed.hostname}:{port}"

    def _in_scope(self, url: str) -> bool:
        """Check whether *url* falls within the configured scope."""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        origin = f"{parsed.scheme}://{parsed.hostname}:{port}"
        return origin == self.scope_origin

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = {"User-Agent": self.config.user_agent}
            if self.config.auth_header:
                headers["Authorization"] = self.config.auth_header
            self._client = httpx.AsyncClient(
                timeout=self.config.timeout,
                proxy=self.config.proxy,
                headers=headers,
                cookies=self.config.cookies or {},
                follow_redirects=True,
                verify=not self.config.no_verify_tls,
            )
            if self.config.no_verify_tls:
                console.print("[dim yellow]⚠ TLS verification disabled — all certificate errors ignored[/dim yellow]")
        return self._client

    async def _enforce_scope(self, url: str) -> Optional[str]:
        """Return *url* if in scope, else None.  Logs a warning on rejection."""
        if self._in_scope(url):
            return url
        console.print(f"[dim yellow]⚠ Out-of-scope request blocked: {url}[/dim yellow]")
        return None

    async def get(self, url: str, *, cookies: dict = None, **kwargs) -> Optional[httpx.Response]:
        url = await self._enforce_scope(url)
        if url is None:
            return None
        await self._bucket.acquire()
        client = await self._get_client()
        try:
            req_cookies = dict(self.config.cookies or {})
            if cookies:
                req_cookies.update(cookies)
            resp = await client.get(url, cookies=req_cookies or None, **kwargs)
            # Warn if final URL is out of scope (redirect followed)
            if self._in_scope(str(resp.url)) is False:
                console.print(f"[dim yellow]⚠ Redirect landed outside scope: {resp.url}[/dim yellow]")
            return resp
        except httpx.TimeoutException as e:
            console.print(f"[dim]Request timeout: {e}[/dim]")
            return None
        except httpx.RequestError as e:
            console.print(f"[dim]Request error: {e}[/dim]")
            return None

    async def post(self, url: str, *, cookies: dict = None, **kwargs) -> Optional[httpx.Response]:
        url = await self._enforce_scope(url)
        if url is None:
            return None
        await self._bucket.acquire()
        client = await self._get_client()
        try:
            req_cookies = dict(self.config.cookies or {})
            if cookies:
                req_cookies.update(cookies)
            resp = await client.post(url, cookies=req_cookies or None, **kwargs)
            return resp
        except httpx.TimeoutException as e:
            console.print(f"[dim]Request timeout: {e}[/dim]")
            return None
        except httpx.RequestError as e:
            console.print(f"[dim]Request error: {e}[/dim]")
            return None

    async def request(self, method: str, url: str, *, cookies: dict = None, **kwargs) -> Optional[httpx.Response]:
        url = await self._enforce_scope(url)
        if url is None:
            return None
        await self._bucket.acquire()
        client = await self._get_client()
        try:
            req_cookies = dict(self.config.cookies or {})
            if cookies:
                req_cookies.update(cookies)
            resp = await client.request(method, url, cookies=req_cookies or None, **kwargs)
            return resp
        except httpx.TimeoutException as e:
            console.print(f"[dim]Request timeout: {e}[/dim]")
            return None
        except httpx.RequestError as e:
            console.print(f"[dim]Request error: {e}[/dim]")
            return None

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()


class SyncHttpClient:
    """Synchronous HTTP client for simpler modules."""

    def __init__(self, config):
        self.config = config

    def _in_scope(self, url: str) -> bool:
        """Check whether *url* falls within the configured scope."""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            return False
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        origin = f"{parsed.scheme}://{parsed.hostname}:{port}"
        # Compare against scope origin
        scope_parsed = urlparse(self.config.scope or self.config.target)
        scope_port = scope_parsed.port or (443 if scope_parsed.scheme == "https" else 80)
        scope_origin = f"{scope_parsed.scheme}://{scope_parsed.hostname}:{scope_port}"
        return origin == scope_origin

    def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        if not self._in_scope(url):
            console.print(f"[dim yellow]⚠ Out-of-scope request blocked: {url}[/dim yellow]")
            return None
        headers = {"User-Agent": self.config.user_agent}
        if self.config.auth_header:
            headers["Authorization"] = self.config.auth_header
        try:
            with httpx.Client(
                timeout=self.config.timeout,
                proxy=self.config.proxy,
                headers=headers,
                cookies=self.config.cookies or {},
                follow_redirects=True,
                verify=not self.config.no_verify_tls,
            ) as client:
                return client.get(url, **kwargs)
        except httpx.TimeoutException as e:
            console.print(f"[dim]Request timeout: {e}[/dim]")
            return None
        except httpx.RequestError as e:
            console.print(f"[dim]Request error: {e}[/dim]")
            return None

    def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        if not self._in_scope(url):
            console.print(f"[dim yellow]⚠ Out-of-scope request blocked: {url}[/dim yellow]")
            return None
        headers = {"User-Agent": self.config.user_agent}
        if self.config.auth_header:
            headers["Authorization"] = self.config.auth_header
        try:
            with httpx.Client(
                timeout=self.config.timeout,
                proxy=self.config.proxy,
                headers=headers,
                cookies=self.config.cookies or {},
                follow_redirects=True,
                verify=not self.config.no_verify_tls,
            ) as client:
                return client.post(url, **kwargs)
        except httpx.TimeoutException as e:
            console.print(f"[dim]Request timeout: {e}[/dim]")
            return None
        except httpx.RequestError as e:
            console.print(f"[dim]Request error: {e}[/dim]")
            return None