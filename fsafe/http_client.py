"""Rate-limited async HTTP client wrapper (politeness + scope are enforced globally).

Scope enforcement is defense-in-depth:
1. The crawler/checks filter URLs by origin before calling (fast path).
2. This client ALSO refuses any request whose origin is not on the allow-list
   (last line of defense — a bug in one check can never leak a request to a
   third party). Violations raise ScopeViolation and are reported through the
   optional ``on_violation`` hook so they surface in scan logs.
"""
from __future__ import annotations

import asyncio
import time

import httpx

USER_AGENT = "FSafe-Scanner/1.0 (authorized security testing; +https://localhost/fsafe)"


class ScopeViolation(RuntimeError):
    """A request was refused because its origin is outside the scan scope."""


class RateLimitedClient:
    """Every request to the target passes a global rate limiter and an origin
    allow-list so the scan stays polite and never touches anything else."""

    def __init__(self, delay: float = 0.35, timeout: float = 15.0, verify: bool = True,
                 scope: str | None = None, extra_origins: list[str] | None = None,
                 on_violation=None):
        """
        scope: canonical origin of the target (from ``normalize_url``).
            ``None`` disables enforcement (used only for recon's third-party
            API lookups, which never send target data beyond the hostname).
        extra_origins: additional allowed origins, e.g. the http→https twin of
            the target origin for the HTTP-redirect / TLS checks.
        on_violation: async or sync callable receiving the refused URL.
        """
        self.delay = max(0.0, delay)
        self.requests_sent = 0
        self.errors = 0
        self.scope = scope
        self._allowed: set[str] = set()
        if scope:
            self._allowed.add(scope)
        for o in (extra_origins or []):
            self._allowed.add(origin_of(o))
        self.on_violation = on_violation
        self.violations: list[str] = []
        self._client = httpx.AsyncClient(
            timeout=timeout,
            verify=verify,
            follow_redirects=False,  # engine follows manually to enforce scope
            trust_env=False,  # ignore system proxies for deterministic behavior
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        self._lock = asyncio.Lock()
        self._last_request = 0.0

    def _check_scope(self, url: str) -> None:
        if not self.scope:
            return
        if origin_of(url) not in self._allowed:
            self.violations.append(url)
            if self.on_violation:
                try:
                    r = self.on_violation(url)
                    if asyncio.iscoroutine(r):
                        r.close()  # fire-and-forget; do not block the refusal
                except Exception:
                    pass
            raise ScopeViolation(f"refused out-of-scope request: {url}")

    def allow_origin(self, url: str) -> None:
        """Add an extra allowed origin (e.g. the scheme twin of the target)."""
        self._allowed.add(origin_of(url))

    async def _throttle(self) -> None:
        async with self._lock:
            wait = self._last_request + self.delay - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        self._check_scope(url)  # refuse before any traffic leaves
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
    # canonical origin key used for scope enforcement — httpx returns None for
    # an unspecified port, so treat None/implicit defaults as no port suffix
    port = parsed.port
    default = {"http": 80, "https": 443}.get(parsed.scheme)
    scope = f"{parsed.scheme}://{parsed.host}" + (
        f":{port}" if port and port != default else ""
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
