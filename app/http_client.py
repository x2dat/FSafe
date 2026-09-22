"""Rate-limited async HTTP client wrapper (politeness is enforced globally)."""
from __future__ import annotations

import asyncio
import time

import httpx

USER_AGENT = "FSafe-Scanner/1.0 (authorized security testing; +https://localhost/fsafe)"


class RateLimitedClient:
    """Every request to the target passes a global rate limiter so the scan
    stays polite and never resembles a flood."""

    def __init__(self, delay: float = 0.35, timeout: float = 15.0, verify: bool = True):
        self.delay = max(0.0, delay)
        self.requests_sent = 0
        self.errors = 0
        self._client = httpx.AsyncClient(
            timeout=timeout,
            verify=verify,
            follow_redirects=False,  # engine follows manually to enforce scope
            trust_env=False,  # ignore system proxies for deterministic behavior
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        self._lock = asyncio.Lock()
        self._last_request = 0.0

    async def _throttle(self) -> None:
        async with self._lock:
            wait = self._last_request + self.delay - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        await self._throttle()
        try:
            resp = await self._client.request(method, url, **kwargs)
            self.requests_sent += 1
            return resp
        except httpx.HTTPError:
            self.errors += 1
            raise

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def options(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)

    async def trace(self, url: str, **kwargs) -> httpx.Response:
        return await self.request("TRACE", url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()


def normalize_url(raw: str) -> tuple[str, str]:
    """Return (normalized_url, error). Adds https:// scheme when missing."""
    raw = (raw or "").strip()
    if not raw:
        return "", "URL is empty"
    if "://" not in raw:
        raw = "https://" + raw
    parsed = httpx.URL(raw)
    if parsed.scheme not in ("http", "https"):
        return "", f"Unsupported scheme: {parsed.scheme}"
    if not parsed.host:
        return "", "URL has no host"
    # canonical origin key used for scope enforcement
    scope = f"{parsed.scheme}://{parsed.host}" + (
        f":{parsed.port}" if parsed.port not in (80, 443) else ""
    )
    return str(parsed), scope


def origin_of(url: str) -> str:
    p = httpx.URL(url)
    port = p.port
    default = {"http": 80, "https": 443}.get(p.scheme)
    if port is None or port == default:
        return f"{p.scheme}://{p.host}"
    return f"{p.scheme}://{p.host}:{port}"


def same_scope(url: str, scope: str) -> bool:
    return origin_of(url) == scope
