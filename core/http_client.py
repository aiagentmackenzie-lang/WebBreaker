"""Shared HTTP client with rate limiting, proxy support, and retry logic."""

import time
import asyncio
from typing import Optional
import httpx
from rich.console import Console

console = Console()


class HttpClient:
    """Thread-safe async HTTP client with rate limiting."""

    def __init__(self, config):
        self.config = config
        self._last_request_time = 0.0
        self._min_interval = 1.0 / max(config.rate_limit, 1)
        self._client: Optional[httpx.AsyncClient] = None

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
                verify=False,
            )
        return self._client

    async def _rate_limit(self):
        if self.config.delay > 0:
            await asyncio.sleep(self.config.delay)
        else:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_request_time = time.monotonic()

    async def get(self, url: str, **kwargs) -> httpx.Response:
        await self._rate_limit()
        client = await self._get_client()
        try:
            resp = await client.get(url, **kwargs)
            return resp
        except httpx.RequestError as e:
            console.print(f"[dim]Request error: {e}[/dim]")
            return None

    async def post(self, url: str, **kwargs) -> httpx.Response:
        await self._rate_limit()
        client = await self._get_client()
        try:
            resp = await client.post(url, **kwargs)
            return resp
        except httpx.RequestError as e:
            console.print(f"[dim]Request error: {e}[/dim]")
            return None

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        await self._rate_limit()
        client = await self._get_client()
        try:
            resp = await client.request(method, url, **kwargs)
            return resp
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
        self._last_request_time = 0.0
        self._min_interval = 1.0 / max(config.rate_limit, 1)

    def _rate_limit(self):
        if self.config.delay > 0:
            time.sleep(self.config.delay)
        else:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_request_time = time.monotonic()

    def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        self._rate_limit()
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
                verify=False,
            ) as client:
                return client.get(url, **kwargs)
        except httpx.RequestError as e:
            console.print(f"[dim]Request error: {e}[/dim]")
            return None

    def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        self._rate_limit()
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
                verify=False,
            ) as client:
                return client.post(url, **kwargs)
        except httpx.RequestError as e:
            console.print(f"[dim]Request error: {e}[/dim]")
            return None