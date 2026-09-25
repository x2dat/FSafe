"""Scope-isolation proof: a scan of target A must never send a single request
to anything else — verified with a real second HTTP server as collateral."""
from __future__ import annotations

from conftest import FreePortServer, make_handler, run_scan, find


def test_scan_never_touches_collateral_host():
    counter: dict = {}
    collateral = FreePortServer(make_handler(
        [("robots.txt", 200, {"Content-Type": "text/plain"}, b"User-agent: *\nAllow: /\n")],
        counter, "collateral"))
    target = FreePortServer(make_handler(
        [("/", 200, {"Content-Type": "text/html"},
          (f"<html><title>T</title><body>"
           f"<a href='/about'>a</a>"
           f"<a href='http://127.0.0.1:{collateral.port}/hotlink'>ext link</a>"
           f"<a href='http://other-domain.example.com/'>other host</a>"
           f"<a href='http://127.0.0.1:{collateral.port}/redirect?to=/x'>rd</a>"
           f"<script src='/app.js'></script></body></html>").encode()),
         ("/about", 200, {"Content-Type": "text/html"}, b"<html><body>about</body></html>"),
         ("/app.js", 200, {"Content-Type": "application/javascript"}, b"var x=1;"),
         ("/redirect", 302, {"Location": f"http://127.0.0.1:{collateral.port}/landed"}, b""),
         ("/.env", 200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=supersecret\n")],
        counter, "target"))
    try:
        job = run_scan(target.base, max_pages=8)
        assert job.status == "done", job.error
        # the collateral server must have received ZERO requests
        assert counter.get("collateral", 0) == 0, \
            f"scope leak! collateral server got {counter.get('collateral', 0)} requests"
        assert counter.get("target", 0) > 0, "target was never scanned"
        # every crawled/analyzed page is on the target origin
        assert all(p["url"].startswith(target.base) for p in job.pages), \
            f"page list leaked off-scope URLs: {[p['url'] for p in job.pages]}"
    finally:
        target.stop()
        collateral.stop()


def test_client_refuses_out_of_scope_urls():
    import pytest
    from fsafe.http_client import RateLimitedClient, ScopeViolation

    async def _go():
        c = RateLimitedClient(delay=0, timeout=2, scope="http://127.0.0.1:1")
        try:
            await c.get("http://evil.example.com/x")
        except ScopeViolation:
            return True
        finally:
            await c.aclose()
        return False

    assert asyncio_run(_go()) is True


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)


def test_scheme_twin_is_allowed_but_nothing_else():
    """With a live server: the allowed origin answers; a second live server on a
    different origin raises ScopeViolation before any bytes are sent."""
    import asyncio
    import pytest
    from fsafe.http_client import RateLimitedClient, ScopeViolation
    counter: dict = {}
    ok_srv = FreePortServer(make_handler(
        [("/", 200, {"Content-Type": "text/plain"}, b"ok")], counter, "ok"))
    bad_srv = FreePortServer(make_handler(
        [("/", 200, {"Content-Type": "text/plain"}, b"never")], counter, "bad"))

    async def _go():
        c = RateLimitedClient(delay=0, timeout=3, scope=ok_srv.base)
        try:
            r = await c.get(f"{ok_srv.base}/")
            assert r.status_code == 200 and r.text == "ok"
            with pytest.raises(ScopeViolation):
                await c.get(f"{bad_srv.base}/")
            # violations are recorded for the log hook
            assert c.violations and c.violations[0] == f"{bad_srv.base}/"
            # but the disallowed server never saw anything
            assert counter.get("bad", 0) == 0
        finally:
            await c.aclose()

    try:
        asyncio.run(_go())
    finally:
        ok_srv.stop()
        bad_srv.stop()


def test_off_scope_links_are_reported_not_followed():
    counter: dict = {}
    collateral = FreePortServer(make_handler(
        [("/", 200, {"Content-Type": "text/html"}, b"<html>landed</html>")],
        counter, "collateral"))
    target = FreePortServer(make_handler(
        [("/", 200, {"Content-Type": "text/html"},
          (f"<html><body><a href='http://127.0.0.1:{collateral.port}/x'>ext</a>"
           f"</body></html>").encode())],
        counter, "target"))
    try:
        job = run_scan(target.base, max_pages=5)
        assert job.status == "done", job.error
        assert counter.get("collateral", 0) == 0
        links = [f for f in job.findings if "leave the scanned scope" in f["title"]]
        assert links, "off-scope observation should be reported"
        assert str(collateral.port) in links[0]["evidence"] or str(collateral.port) in links[0]["description"]
    finally:
        target.stop()
        collateral.stop()
