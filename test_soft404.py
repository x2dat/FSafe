"""Regression tests for the soft-404 / SPA catch-all false-positive fixes."""
from __future__ import annotations

from conftest import FreePortServer, make_handler, run_scan, find

SPA = b"<html><body><div id=app>My SPA</div></body></html>"


def test_catch_all_spa_yields_zero_sensitive_file_findings():
    counter: dict = {}
    # catch-all: every path returns the same 200 + HTML (SPA fallback)
    spa = FreePortServer(make_handler(
        [("", 200, {"Content-Type": "text/html"}, SPA)], counter, "spa"))
    try:
        job = run_scan(spa.base, max_pages=4)
        assert job.status == "done", job.error
        assert find(job.findings, "Sensitive file") == [], \
            "catch-all server must not produce sensitive-file criticals"
        assert find(job.findings, "management surface") == []
    finally:
        spa.stop()


def test_real_sensitive_files_still_detected_on_strict_404_server():
    counter: dict = {}
    strict = FreePortServer(make_handler(
        [("/", 200, {"Content-Type": "text/html"},
          b"<html><title>Site</title><body><a href='/about'>a</a></body></html>"),
         ("/about", 200, {"Content-Type": "text/html"}, b"<html><body>hi</body></html>"),
         ("/.env", 200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=supersecret\n"),
         ("/admin", 200, {"Content-Type": "text/html"}, b"<html><h1>Admin</h1></html>")],
        counter, "strict"))
    try:
        job = run_scan(strict.base, max_pages=4)
        assert job.status == "done", job.error
        crits = [f["url"] for f in job.findings if f["severity"] == "critical"]
        assert any(u.endswith("/.env") for u in crits), f"expected /.env critical, got {crits}"
        admins = find(job.findings, "management surface")
        assert any(u.endswith("/admin") for u in (f["url"] for f in admins))
    finally:
        strict.stop()


def test_crawled_admin_page_not_flagged_as_hidden_surface():
    counter: dict = {}
    site = FreePortServer(make_handler(
        [("/", 200, {"Content-Type": "text/html"},
          b"<html><title>S</title><body><a href='/dashboard'>dash</a></body></html>"),
         ("/dashboard", 200, {"Content-Type": "text/html"}, b"<html><body>app</body></html>")],
        counter, "site"))
    try:
        job = run_scan(site.base, max_pages=4)
        assert job.status == "done", job.error
        # /dashboard was crawled (a normal linked page) → not a "hidden" admin surface
        dash_findings = [f for f in find(job.findings, "management surface")
                         if f["url"].endswith("/dashboard")]
        assert dash_findings == []
    finally:
        site.stop()
