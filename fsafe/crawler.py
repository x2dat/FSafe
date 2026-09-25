"""BFS crawler with scope enforcement, robots.txt support, and artifact capture."""
from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlparse, parse_qsl, urlunparse
from urllib.robotparser import RobotFileParser

import httpx

from .http_client import RateLimitedClient, same_scope, origin_of
from .models import CrawlResult, JobStats, PageData, ScanConfig
from .parser import parse_page, extract_get_links


COMMON_DIRS = [
    "admin", "administrator", "login", "signin", "wp-admin", "wp-login.php",
    "dashboard", "backup", "backups", ".git", ".env", ".svn", "config",
    "phpmyadmin", "db", "sql", "test", "tmp", "old", "api", "debug",
    "server-status", "actuator", "console", "panel", "cpanel", ".htaccess",
    "composer.json", "package.json", "web.config", "robots.txt", "sitemap.xml",
    "crossdomain.xml", ".DS_Store", "id_rsa", "dump.sql", "db.sql",
]


def _canon(url: str) -> str:
    """Canonical form for dedupe: strip fragment."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))


def _norm_body(text: str) -> str:
    """Collapse whitespace for content comparison."""
    return " ".join((text or "").split())


class Crawler:
    def __init__(self, cfg: ScanConfig, client: RateLimitedClient, stats: JobStats, log):
        self.cfg = cfg
        self.client = client
        self.stats = stats
        self.log = log
        self.scope = origin_of(cfg.url)
        self.result = CrawlResult()
        self._visited: set[str] = set()
        self._robots: RobotFileParser | None = None

    # ---------- robots ----------
    async def _load_robots(self) -> None:
        if not self.cfg.respect_robots:
            return
        rp = RobotFileParser()
        robots_url = urljoin(self.cfg.url, "/robots.txt")
        try:
            r = await self.client.get(robots_url)
            if r.status_code == 200 and "text" in r.headers.get("content-type", ""):
                rp.parse(r.text.splitlines())
                self._robots = rp
                for line in r.text.splitlines():
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            self.result.robots_disallows.append(path)
                # robots.txt content itself is interesting (hidden paths)
                self.result.js_texts[robots_url] = r.text
        except httpx.HTTPError:
            pass

    def _robots_allows(self, url: str) -> bool:
        if self._robots is None:
            return True
        try:
            return self._robots.can_fetch("*", url)
        except Exception:
            return True

    # ---------- fetching ----------
    async def _fetch(self, url: str) -> PageData | None:
        """GET with manual redirect following inside scope."""
        chain: list[str] = []
        current = url
        for _hop in range(6):
            try:
                r = await self.client.get(current)
            except httpx.HTTPError:
                self.stats.errors += 1
                return None
            self.stats.requests = self.client.requests_sent
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("location", "")
                if not loc:
                    break
                nxt = _canon(urljoin(current, loc))
                chain.append(f"{r.status_code} → {loc}")
                if not same_scope(nxt, self.scope):
                    # off-scope redirect is itself a finding-worthy artifact
                    self.result.off_scope_links.append(nxt)
                    break
                current = nxt
                continue
            ct = r.headers.get("content-type", "")
            page = PageData(
                url=current,
                status=r.status_code,
                headers={k.lower(): v for k, v in r.headers.items()},
                content=r.text if ("html" in ct or "text" in ct or ct == "" or "javascript" in ct) else "",
                set_cookies=[v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"],
                redirects=chain,
            )
            return page
        return None

    # ---------- main ----------
    async def run(self, progress_cb=None) -> CrawlResult:
        await self._load_robots()
        queue: asyncio.Queue[str] = asyncio.Queue()
        queue.put_nowait(_canon(self.cfg.url))
        self._visited.add(_canon(self.cfg.url))

        while not queue.empty() and self.stats.pages < self.cfg.max_pages:
            batch: list[str] = []
            for _ in range(min(queue.qsize(), 4)):  # small concurrency, still globally throttled
                try:
                    batch.append(queue.get_nowait())
                except asyncio.QueueEmpty:
                    break

            pages = await asyncio.gather(*[self._fetch(u) for u in batch])
            for page in pages:
                if page is None:
                    continue
                if not self._robots_allows(page.url):
                    self.log(f"robots.txt disallows {page.url} — skipped")
                    continue

                self.stats.pages += 1
                if progress_cb:
                    await progress_cb(f"crawled {page.url} ({page.status})")

                ct = page.headers.get("content-type", "")
                if "javascript" in ct:
                    if len(self.result.js_texts) < 25:
                        self.result.js_texts[page.url] = page.content
                    continue

                if "html" in ct or page.content:
                    parse_page(page)
                    self.result.pages.append(page)
                    self.result.forms.extend(page.forms)
                    self.result.get_params.extend(extract_get_links(page))

                    for link in page.links:
                        c = _canon(link)
                        if not same_scope(c, self.scope):
                            self.result.off_scope_links.append(c)
                            continue
                        if c in self._visited:
                            continue
                        self._visited.add(c)
                        if self.stats.pages + queue.qsize() < self.cfg.max_pages * 2:
                            queue.put_nowait(c)

                    for s in page.scripts_src:
                        c = _canon(s)
                        if same_scope(c, self.scope) and c not in self._visited and len(self.result.js_texts) < 25:
                            self._visited.add(c)
                            queue.put_nowait(c)

        self.stats.params = len({(u, p) for u, p in self.result.get_params})
        self.stats.forms = len(self.result.forms)
        self.stats.requests = self.client.requests_sent
        await self._probe_common_dirs()
        self.result.get_params = list({(u, p) for u, p in self.result.get_params})
        return self.result

    async def _probe_common_dirs(self) -> None:
        """Light one-shot GET of well-known sensitive paths with soft-404 filtering.

        Baseline strategy: fetch a guaranteed-nonexistent random path first.
        Many servers (SPA catch-alls, custom 404 handlers) return 200 for
        everything — any probe whose body matches the baseline is a soft-404
        and is discarded."""
        if not self.cfg.brute_dirs:
            return
        import hashlib
        import random

        base = self.cfg.url.rstrip("/")
        # 1) baseline: a path that cannot exist
        rnd = f"fsafe-{random.randbytes(6).hex()}"
        try:
            br = await self.client.get(f"{base}/{rnd}.html")
            self.stats.requests = self.client.requests_sent
            baseline = (br.status_code, _norm_body(br.text))
        except httpx.HTTPError:
            baseline = (404, "")
        if baseline[0] == 200:
            self.log(f"soft-404 baseline detected (server returns 200 for unknown paths) — filtering by content match")

        self.log(f"probing {len(COMMON_DIRS)} common sensitive paths…")
        found: dict[str, int] = {}
        for d in COMMON_DIRS:
            url = f"{base}/{d}"
            try:
                r = await self.client.get(url)
                self.stats.requests = self.client.requests_sent
                if r.status_code >= 400:
                    continue
                if r.status_code == baseline[0] and _norm_body(r.text) == baseline[1]:
                    continue  # identical to the not-found baseline → soft 404
                if r.status_code == 200 and "text/html" in r.headers.get("content-type", "") \
                        and baseline[0] == 200 and baseline[1] \
                        and _norm_body(r.text).startswith(baseline[1][:400]):
                    # SPA fallback often appends route metadata; treat prefix-match as soft 404 too
                    continue
                found[url] = r.status_code
            except httpx.HTTPError:
                self.stats.errors += 1
        self._probed = found

    @property
    def probed_paths(self) -> dict[str, int]:
        return getattr(self, "_probed", {})
