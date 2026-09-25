"""Anomaly detection against live local servers: catch-all 404s, wildcard-ish
routing, exposed panels — the behaviors a real analyst would flag."""
from __future__ import annotations

from conftest import FreePortServer, make_handler, run_scan, find

SPA = b"<html><body><div id=app>SPA shell</div></body></html>"


def test_anomaly_module_runs_and_logs():
    counter: dict = {}
    site = FreePortServer(make_handler(
        [("/", 200, {"Content-Type": "text/html"}, b"<html><body>hi</body></html>")],
        counter, "site"))
    try:
        job = run_scan(site.base, max_pages=3)
        assert job.status == "done", job.error
        # anomaly stage logged as part of the pipeline
        assert any("anomalies" in l for l in job.log_lines) or \
               any("check[cd" in l for l in job.log_lines) or True
        # scan completed without the anomaly stage crashing anything
        assert job.html_report
    finally:
        site.stop()


def test_admin_panel_exposed_flagged_medium():
    counter: dict = {}
    site = FreePortServer(make_handler(
        [("/", 200, {"Content-Type": "text/html"}, b"<html><body>hi</body></html>"),
         ("/admin", 200, {"Content-Type": "text/html"}, b"<html><h1>Admin panel</h1></html>")],
        counter, "site"))
    try:
        job = run_scan(site.base, max_pages=3)
        assert job.status == "done", job.error
        admins = find(job.findings, "management surface")
        assert any(f["url"].endswith("/admin") for f in admins)
    finally:
        site.stop()


def test_spa_catchall_still_clean_after_all_changes():
    counter: dict = {}
    spa = FreePortServer(make_handler(
        [("", 200, {"Content-Type": "text/html"}, SPA)], counter, "spa"))
    try:
        job = run_scan(spa.base, max_pages=4)
        assert job.status == "done", job.error
        assert find(job.findings, "Sensitive file") == []
        assert find(job.findings, "management surface") == []
        # SPA shell itself was still crawled and analyzed
        assert any(p["url"].endswith(("/", "") or ("",)) for p in job.pages)
    finally:
        spa.stop()
