"""End-to-end: full Engine scan against a deliberately vulnerable local site
covering reflection, cookies, headers, secrets, robots and anomaly signals."""
from __future__ import annotations

from conftest import FreePortServer, make_handler, run_scan, find


def _site_handler(counter: dict):
    routes = [
        ("/", 200, {"Content-Type": "text/html",
                    "Set-Cookie": "session=abc123",  # missing flags on purpose
                    "X-Powered-By": "Express/4.17.1"},
         b"<html><head><title>Demo Shop</title>"
         b"<script>var cfg = {apiKey: \"AIzaSyD-abc123abc123abc123abc123abc123\"};</script>"
         b"</head><body>"
         b"<a href='/about'>About</a> <a href='/login'>Login</a>"
         b"<a href='https://external.example.com/x'>ext</a>"
         b"<form action='/search' method='get'><input name='q'><input type='submit'></form>"
         b"</body></html>"),
        ("/about", 200, {"Content-Type": "text/html"}, b"<html><body>about</body></html>"),
        ("/login", 200, {"Content-Type": "text/html",
                         "Set-Cookie": "__Host-bad=1; Secure"},  # violates prefix rules
         b"<html><body>login</body></html>"),
        ("/search", 200, {"Content-Type": "text/html"},
         # reflect the q parameter back unencoded → XSS detection
         (lambda path: (
             b"<html>Results for " +
             (path.split("q=", 1)[1].split("&", 1)[0].encode() if "q=" in path else b"")
             + b"</html>"))),
        ("/robots.txt", 200, {"Content-Type": "text/plain"},
         b"User-agent: *\nDisallow: /admin\n"),
    ]
    return make_handler(routes, counter, "target")


def test_end_to_end_vulnerable_site():
    counter: dict = {}
    site = FreePortServer(_site_handler(counter))
    try:
        job = run_scan(site.base, max_pages=6)
        assert job.status == "done", f"scan failed: {job.error}"
        assert counter.get("target", 0) > 5, "scan barely touched the target"
        titles = [f["title"] for f in job.findings]

        # core checks fired
        assert find(job.findings, "Reflected input"), "XSS reflection not detected"
        assert find(job.findings, "session"), "insecure session cookie not detected"
        assert find(job.findings, "Possible secret in client-side source"), "secret not detected"
        assert any("HSTS" in t for t in titles), "missing-HSTS not detected"
        assert any("Content-Security-Policy" in t for t in titles), "missing CSP not detected"

        # anomaly module contributed findings on this site
        assert find(job.findings, "__Host-"), "__Host- prefix anomaly not detected"

        # reports were produced and are self-consistent
        assert job.html_report and job.json_report
        assert job.grade in list("ABCDEF")
        import json
        parsed = json.loads(job.json_report)
        assert len(parsed["findings"]) == len(job.findings)

        # log shows the full pipeline ran
        logtext = "\n".join(job.log_lines)
        assert "crawl done" in logtext
        assert "active checks complete" in logtext
        assert "scan complete" in logtext
    finally:
        site.stop()


def test_end_to_end_clean_site_low_grade():
    """A well-configured site should grade well and produce no criticals."""
    counter: dict = {}
    routes = [
        ("/", 200, {"Content-Type": "text/html",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                    "Set-Cookie": "sid=x; HttpOnly; Secure; SameSite=Lax"},
         b"<html><head><title>Clean</title></head><body>"
         b"<a href='/docs'>docs</a></body></html>"),
        ("/docs", 200, {"Content-Type": "text/html"}, b"<html><body>docs</body></html>"),
    ]
    site = FreePortServer(make_handler(routes, counter, "clean"))
    try:
        job = run_scan(site.base, max_pages=4)
        assert job.status == "done", job.error
        assert not [f for f in job.findings if f["severity"] in ("critical", "high")], \
            [f["title"] for f in job.findings]
    finally:
        site.stop()


def test_end_to_end_reports_are_written_by_cli(tmp_path):
    """CLI main() against the demo target writes HTML+JSON and exits 0."""
    import contextlib
    import io
    import sys
    from pathlib import Path

    from fsafe.demo_target import main as demo_main
    import threading

    # start demo target in-process on its fixed port
    t = threading.Thread(target=demo_main, daemon=True)
    t.start()
    import socket, time
    for _ in range(50):
        with socket.socket() as s:
            try:
                s.connect(("127.0.0.1", 9911))
                break
            except OSError:
                time.sleep(0.1)

    from fsafe.cli import main as cli_main
    out, json_out = tmp_path / "r.html", tmp_path / "r.json"
    argv_backup = sys.argv[1:]
    sys.argv[1:] = [f"http://127.0.0.1:9911", "--yes",
                    "--out", str(out), "--json-out", str(json_out),
                    "--no-recon", "--max-pages", "5"]
    try:
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            rc = cli_main()
    finally:
        sys.argv[1:] = argv_backup
    assert rc == 0
    assert out.exists() and out.stat().st_size > 1000
    import json
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["findings"], "demo target should produce findings"
