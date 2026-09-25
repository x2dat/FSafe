"""Unit tests: URL scope helpers, DER cert parser, swap_param, anomaly heuristics."""
from __future__ import annotations

from conftest import find


# ---------- origin / scope helpers ----------

def test_origin_of_default_and_custom_ports():
    from fsafe.http_client import origin_of
    assert origin_of("https://x.com/a?b=1") == "https://x.com"
    assert origin_of("http://x.com:8080/y") == "http://x.com:8080"
    assert origin_of("https://x.com:443/") == "https://x.com"
    assert origin_of("http://x.com:80/") == "http://x.com"


def test_normalize_url():
    from fsafe.http_client import normalize_url
    u, s = normalize_url("zstock.me")
    assert u.startswith("https://zstock.me") and s == "https://zstock.me"
    u, s = normalize_url("http://a.com:8080")
    assert s == "http://a.com:8080"
    assert normalize_url("ftp://x")[0] == ""
    assert normalize_url("  ")[0] == ""


# ---------- swap_param ----------

def test_swap_param_replaces_and_appends():
    from fsafe.checks import _swap_param
    u = _swap_param("http://h/p?a=1&b=2", "a", "X")
    assert "a=X" in u and "b=2" in u
    u2 = _swap_param("http://h/p", "new", "V")
    assert "new=V" in u2


# ---------- DER certificate parser ----------

def test_minider_parses_real_certificate():
    """Build a real self-signed cert with the stdlib and parse it."""
    import ssl
    import tempfile
    import subprocess
    import sys
    import os
    # openssl may not exist on all systems — generate cert via Python ssl? Not possible.
    # Fall back: parse a known-good hardcoded DER (tiny self-signed test cert is
    # awkward to hardcode; instead use hashlib-stable skip when openssl absent).
    openssl = None
    for cand in ("openssl", r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"):
        try:
            subprocess.run([cand, "version"], capture_output=True, check=True)
            openssl = cand
            break
        except (OSError, subprocess.CalledProcessError):
            continue
    if not openssl:
        print("openssl not available; skipping live cert parse")
        return
    with tempfile.TemporaryDirectory() as d:
        key, crt = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", crt, "-days", "1",
                        "-subj", "/CN=demo.example.com/O=FSafe Test",
                        "-addext", "subjectAltName=DNS:demo.example.com,DNS:alt.example.com"],
                       capture_output=True, check=True)
        der = ssl.PEM_cert_to_DER_cert(open(crt).read())
        from fsafe._minider import cert_fields
        f = cert_fields(der)
        assert f["subject_cn"] == "demo.example.com"
        assert f["issuer_cn"] == "demo.example.com"
        assert f["self_signed"] is True
        assert f["key_algo"] == "RSA" and f["key_bits"] == 2048
        assert f["sig_algo"].startswith("sha256")
        assert "demo.example.com" in f["san"] and "alt.example.com" in f["san"]
        assert "not_after" in f and "not_before" in f


# ---------- anomaly heuristics (pure functions, no network) ----------

def _recon(**over):
    base = {
        "dns": {"domain": "example.com", "records": {"A": [{"type": "A", "data": "1.2.3.4"}],
                                                     "NS": [{"type": "NS", "data": "ns1.example.com."}],
                                                     "MX": [{"type": "MX", "data": "10 mail.example.com."}]}},
        "geo": {"ip": "1.2.3.4", "org": "Example Hosting Inc", "isp": "Example Hosting Inc",
                "reverse": "host.example.com", "domain": "example.com"},
        "ports": {"open": [{"port": 80, "service": "HTTP", "banner": ""},
                            {"port": 443, "service": "HTTPS", "banner": ""}], "tested": 14},
        "whois": {"created": ["2020-01-01T00:00:00Z"], "expires": ["2030-01-01T00:00:00Z"]},
        "wildcard_dns": {"wildcard": False, "probes": ["x.example.com"], "resolved": []},
        "cert": {},
    }
    base.update(over)
    return base


def _crawl(pages=1):
    from fsafe.models import CrawlResult, PageData
    cr = CrawlResult()
    for i in range(pages):
        cr.pages.append(PageData(url=f"https://example.com/p{i}", status=200,
                                 headers={"content-type": "text/html",
                                          "server": "nginx",
                                          "x-powered-by": "PHP/8.1"}))
    return cr


def test_anomaly_baseline_produces_no_noise():
    """A boring, consistent infrastructure must produce zero anomaly findings."""
    from fsafe.anomalies import anomaly_findings
    import asyncio
    from fsafe.http_client import RateLimitedClient

    async def _go():
        c = RateLimitedClient(delay=0, timeout=2)  # no scope → recon-style client
        try:
            return await anomaly_findings(None, c, _crawl(), _recon(), lambda m: None)
        finally:
            await c.aclose()

    got = asyncio.run(_go())
    assert got == [], f"baseline infra produced anomalies: {[f['title'] for f in got]}"


def test_anomaly_datastore_ports_open():
    from fsafe.anomalies import anomaly_findings
    import asyncio
    from fsafe.http_client import RateLimitedClient
    r = _recon()
    r["ports"]["open"].append({"port": 3306, "service": "MySQL", "banner": "MySQL 8.0"})
    r["ports"]["open"].append({"port": 3389, "service": "RDP", "banner": ""})

    async def _go():
        c = RateLimitedClient(delay=0, timeout=2)
        try:
            return await anomaly_findings(None, c, _crawl(), r, lambda m: None)
        finally:
            await c.aclose()

    got = asyncio.run(_go())
    hits = find(got, "Datastore/remote-access")
    assert hits and hits[0]["severity"] == "medium" and "3306" in hits[0]["description"]


def test_anomaly_wildcard_dns_and_new_domain():
    from fsafe.anomalies import anomaly_findings
    import asyncio
    import datetime
    from fsafe.http_client import RateLimitedClient
    r = _recon()
    r["wildcard_dns"] = {"wildcard": True, "probes": ["fsafe-rand-0.example.com"],
                         "resolved": ["fsafe-rand-0.example.com"]}
    r["whois"]["created"] = [datetime.datetime.now(datetime.timezone.utc)
                             .strftime("%Y-%m-%dT%H:%M:%SZ")]

    async def _go():
        c = RateLimitedClient(delay=0, timeout=2)
        try:
            return await anomaly_findings(None, c, _crawl(), r, lambda m: None)
        finally:
            await c.aclose()

    got = asyncio.run(_go())
    assert find(got, "Wildcard DNS"), "wildcard DNS anomaly missing"
    assert find(got, "registered within the last 30 days"), "young-domain anomaly missing"


def test_anomaly_cert_hostname_mismatch():
    from fsafe.anomalies import anomaly_findings
    import asyncio
    from fsafe.http_client import RateLimitedClient
    r = _recon()
    r["cert"] = {"chain_valid": False, "hostname_mismatch": True,
                 "served_cert": {"san": ["other.example.net"], "self_signed": False,
                                 "subject_cn": "other.example.net"}}

    async def _go():
        c = RateLimitedClient(delay=0, timeout=2)
        try:
            return await anomaly_findings(None, c, _crawl(), r, lambda m: None)
        finally:
            await c.aclose()

    got = asyncio.run(_go())
    assert find(got, "does not cover this hostname")


# ---------- recon helpers ----------

def test_tech_fingerprint():
    from fsafe.recon import tech_section
    assert "Express" in tech_section({"X-Powered-By": "Express/4.17"}, "")
    assert "WordPress" in tech_section({}, "<html>wp-content/themes</html>")


def test_harvest_emails():
    from fsafe.recon import harvest_emails
    assert harvest_emails(["<a>bob@x.com</a>", "no emails"]) == ["bob@x.com"]


# ---------- report sanity ----------

def test_score_grades():
    from fsafe.report import score
    assert score([])[0] == "A"
    crit = [{"severity": "critical"}]
    g, r = score(crit)
    assert g in ("C", "D", "F") and r > 0


def test_cli_requires_authorization():
    """The authorization gate must refuse a wrong confirmation."""
    import io
    import builtins
    import contextlib
    import sys
    from fsafe import cli
    argv_backup = sys.argv[1:]
    sys.argv[1:] = ["http://127.0.0.1:9", "--no-recon"]
    real_input = builtins.input
    try:
        builtins.input = lambda *a, **k: "nope"  # simulate refusing the gate
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main()
    finally:
        sys.argv[1:], builtins.input = argv_backup, real_input
    assert rc == 2, f"wrong authorization must abort with rc=2, got {rc}"
