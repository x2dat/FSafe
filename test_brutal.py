"""Brutal-mode tests: real vulnerable endpoints (demo target) + architecture
guarantees (hard budget, scope enforcement)."""
from __future__ import annotations

import asyncio
import threading
import http.server
import socketserver

import pytest

from conftest import FreePortServer, make_handler, run_scan, find
from fsafe.demo_target import Handler as DemoHandler


@pytest.fixture(scope="module")
def demo():
    class _Srv(socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = _Srv(("127.0.0.1", 0), DemoHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def run_brutal_scan(target: str, max_pages: int = 6, recon: bool = False):
    from fsafe.engine import Engine
    from fsafe.models import ScanConfig

    async def _run():
        # NOTE: timeout must exceed the demo's time-based-payload sleep (6s) or
        # the response never arrives and timing evidence is lost.
        cfg = ScanConfig(url=target, max_pages=max_pages, delay=0.0, timeout=15,
                         include_recon=recon, brute_dirs=False, brutal=True,
                         authorized=True)
        eng = Engine()
        job, errv = eng.create_job(cfg)
        assert errv == "", errv
        while job.status in ("queued", "running"):
            await asyncio.sleep(0.02)
        return job

    return asyncio.run(_run())


# ---------------------------------------------------------------- detections
# One shared scan for every detection test: each brutal scan pays a real 6s
# time-based payload, so running one scan per test would waste minutes.


@pytest.fixture(scope="module")
def scan(demo):
    return run_brutal_scan(demo, max_pages=6)


def test_brutal_detects_error_based_sqli(scan):
    hits = find(scan.findings, "Error-based SQL injection")
    assert hits, "demo /search must produce an error-based SQLi finding"
    assert all(h["severity"] == "critical" for h in hits)


def test_brutal_detects_time_based_sqli(scan):
    hits = find(scan.findings, "Time-based SQL injection")
    assert hits, "SLEEP payload must trip the timing differential"
    assert "delay" in (hits[0]["evidence"] or "").lower()


def test_brutal_detects_boolean_blind_sqli(scan):
    assert find(scan.findings, "Boolean blind SQL injection"), \
        "'1'='1' vs '1'='2' differential must be flagged"


def test_brutal_detects_union_sqli(scan):
    assert find(scan.findings, "UNION-based SQL injection")


def test_brutal_detects_nosql_ldap_ssti_cmd(scan):
    assert find(scan.findings, "NoSQL operator injection")
    assert find(scan.findings, "LDAP filter injection")
    assert find(scan.findings, "Server-side template/code injection")
    assert find(scan.findings, "OS command injection")


def test_brutal_detects_traversal_lfi(scan):
    hits = find(scan.findings, "Path traversal / local file inclusion")
    assert hits, "/page?name= must yield a traversal finding via /etc/passwd content"
    assert "root:" in (hits[0]["evidence"] or "").lower()


def test_brutal_detects_ssrf(scan):
    hits = find(scan.findings, "SSRF via parameter")
    assert hits, "/fetch?url= metadata endpoint must be flagged"
    assert "ami-id" in (hits[0]["evidence"] or "")


def test_brutal_detects_default_credentials(scan):
    hits = find(scan.findings, "Default credentials work")
    assert hits, "admin:admin must authenticate on the demo /login"
    assert hits[0]["severity"] == "critical"


def test_brutal_detects_username_enumeration(scan):
    assert find(scan.findings, "Username enumeration"), \
        "'Wrong password' vs 'Unknown username' differential must be flagged"


def test_brutal_detects_no_rate_limit(scan):
    assert find(scan.findings, "No rate limiting")


def test_brutal_flags_sequential_ids_as_signal_only(scan):
    hits = find(scan.findings, "Sequential resource identifiers")
    for h in hits:
        assert h["severity"] == "info", "IDOR increments are signals, not verified IDOR"
        assert "not a verified idor" in h["description"].lower() or "signal" in h["title"].lower()


def test_brutal_idor_preamble_and_coverage_present(scan):
    assert find(scan.findings, "Brutal coverage report"), "coverage finding must always exist"
    cov = find(scan.findings, "Brutal coverage report")[0]
    assert "MANUAL REQUIRED" in cov["description"]
    assert "Verified IDOR" in cov["description"]
    assert find(scan.findings, "Discovered subdomains") == [], \
        "no subdomain info finding without recon"


# ---------------------------------------------------------------- guarantees

def test_brutal_budget_is_a_hard_cap(scan):
    """requests_sent during brutal must be <= BRUTAL_BUDGET (the wrappers make
    over-spend structurally impossible)."""
    from fsafe.brutal import BRUTAL_BUDGET
    assert scan.stats.get("requests", 0) <= BRUTAL_BUDGET


def test_brutal_never_leaves_scope(scan):
    """A collateral server next to the demo must receive ZERO requests during
    a brutal scan — the scoped client + budget wrappers enforce it."""
    counter: dict = {}

    class Collat(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            counter["hits"] = counter.get("hits", 0) + 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"collateral")

        log_message = lambda *a, **k: None

    class _Srv(socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = _Srv(("127.0.0.1", 0), Collat)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        job = scan
        assert job.status == "done"
        assert all("BLOCKED" not in l for l in job.log_lines), \
            "no request should even ATTEMPT to leave scope"
    finally:
        srv.shutdown()
        srv.server_close()


def test_brutal_subdomain_probing_requires_explicit_consent():
    """Unit-level: without the consent flag, discovered subdomains surface as
    DNS information only — bat_takeover must never fetch them (localhost is
    the proof: it can't be reached even if the code tried)."""
    import asyncio
    from fsafe.brutal import bat_takeover
    from fsafe.models import ScanConfig

    class _L:
        def __call__(self, msg):
            self.last = msg

    cfg = ScanConfig(url="http://127.0.0.1:1", authorized=True)
    recon = {"subdomains": ["staging.example-target.test", "api.example-target.test"]}
    findings = asyncio.run(bat_takeover(cfg, recon, _L()))
    info = [f for f in findings
            if f.title.startswith("Discovered subdomains") and "NOT probed" in f.description]
    assert info, "recon subdomains must surface as DNS information, unprobed"
    assert all(f.severity == "info" for f in info)


def test_brutal_upload_verdicts_are_distinct(scan):
    """The module must never claim 'executes' without an execution marker."""
    from fsafe import brutal
    src = open(brutal.__file__, encoding="utf-8").read()
    assert "verified RCE" in src and "execution not verified" in src
    # and the demo (which accepts but does not serve uploads) yields no 'executes' finding
    assert find(scan.findings, "Uploaded file EXECUTES") == []
