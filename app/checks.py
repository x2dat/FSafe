"""Security check modules — passive analysis + non-destructive active probing.

Design rules for every check:
- payloads are detection-only (harmless markers, arithmetic, benign HTML tags)
- no data exfiltration, no brute force, no DoS patterns
- each finding carries remediation guidance
"""
from __future__ import annotations

import re
import ssl
import socket
from urllib.parse import urlparse, urlencode

import httpx

from .models import CrawlResult, Finding, PageData, ScanConfig, JobStats
from .http_client import RateLimitedClient, same_scope, origin_of
from .parser import SCRIPT_SECRET_PATTERNS


def _f(title, severity, category, url, desc, remediation, cwe="", evidence="", confidence="high") -> Finding:
    return Finding(title, severity, category, url, desc, remediation, cwe, evidence, confidence)


# ============================ passive checks ============================

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS", "medium", "CWE-319",
     "Browsers can be downgraded to HTTP without Strict-Transport-Security.",
     'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'),
    ("content-security-policy", "Content-Security-Policy", "high", "CWE-79",
     "No CSP means injected scripts (XSS) execute without restriction.",
     "Add a Content-Security-Policy header, starting in report-only mode then enforcing."),
    ("x-content-type-options", "X-Content-Type-Options", "low", "CWE-430",
     "Browsers may MIME-sniff responses and execute uploaded content.",
     "Add: X-Content-Type-Options: nosniff"),
    ("x-frame-options", "X-Frame-Options", "medium", "CWE-1021",
     "Page can be framed, enabling clickjacking.",
     "Add: X-Frame-Options: DENY (or CSP frame-ancestors 'none')."),
    ("referrer-policy", "Referrer-Policy", "low", "CWE-200",
     "Full URLs (with tokens in query strings) may leak via Referer.",
     "Add: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer)."),
    ("permissions-policy", "Permissions-Policy", "info", "CWE-1021",
     "Browser features (camera, geolocation…) are not explicitly restricted.",
     "Add a Permissions-Policy header limiting powerful features."),
]

VERSIONED = [
    ("server", "Server header discloses version", re.compile(r"([\w\-]+/[\d.]+)")),
    ("x-powered-by", "X-Powered-By discloses stack", re.compile(r"(.+)")),
]

def check_security_headers(pages: list[PageData]) -> list[Finding]:
    out: list[Finding] = []
    if not pages:
        return out
    home = pages[0]
    h = home.headers
    for key, nice, sev, cwe, desc, fix in SECURITY_HEADERS:
        if key not in h:
            out.append(_f(f"Missing security header: {nice}", sev, "Headers", home.url,
                          desc, fix, cwe))
        elif key == "strict-transport-security" and "max-age=0" in h[key]:
            out.append(_f("HSTS disabled (max-age=0)", "medium", "Headers", home.url,
                          "HSTS is present but explicitly disabled.", fix, "CWE-319",
                          h[key]))
    # CSP weakness
    csp = h.get("content-security-policy", "")
    if csp and ("unsafe-inline" in csp or "*" in csp.split()):
        out.append(_f("Weak Content-Security-Policy", "medium", "Headers", home.url,
                      "CSP allows inline scripts or wildcards, sharply reducing XSS protection.",
                      "Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources; use nonces or hashes.",
                      "CWE-79", csp[:200]))
    # version disclosure
    for key, title, rx in VERSIONED:
        if key in h:
            m = rx.search(h[key])
            if m and re.search(r"\d", h[key]):
                out.append(_f(title, "info", "Headers", home.url,
                              "Versioned banner helps attackers match known exploits.",
                              "Suppress or genericize the banner.", "CWE-200", h[key]))
    return out


def check_cookies(pages: list[PageData]) -> list[Finding]:
    out: list[Finding] = []
    for page in pages:
        for raw in page.set_cookies:
            low = raw.lower()
            name = raw.split("=", 1)[0]
            flags = []
            if "httponly" not in low:
                flags.append("HttpOnly")
            if "secure" not in low:
                flags.append("Secure")
            if "samesite" not in low:
                flags.append("SameSite")
            if not flags:
                continue
            sev = "medium" if ("sess" in name.lower() or "auth" in name.lower() or "token" in name.lower()) else "low"
            out.append(_f(
                f"Cookie '{name}' missing: {', '.join(flags)}", sev, "Cookies", page.url,
                "Cookie is readable/exposable in ways modern browsers would otherwise prevent.",
                f"Set the {', '.join(flags)} attribute(s) on this cookie.",
                "CWE-1004", raw[:200], confidence="high"))
    return out


def check_mixed_content(pages: list[PageData]) -> list[Finding]:
    out: list[Finding] = []
    for page in pages:
        for u in page.mixed_content[:10]:
            out.append(_f("Mixed content on HTTPS page", "medium", "Transport", page.url,
                          "HTTP subresources on an HTTPS page can be intercepted/modified (script injection).",
                          "Serve all subresources over HTTPS.", "CWE-311", u))
    return out


def check_form_security(forms) -> list[Finding]:
    out: list[Finding] = []
    for fd in forms:
        if fd.method == "GET" and any(f.ftype == "password" for f in fd.fields):
            out.append(_f("Login form submitted via GET", "high", "Authentication", fd.page_url,
                          "Credentials in the query string leak into history, logs, and Referer.",
                          "Use POST over HTTPS for credential forms.", "CWE-598", fd.action))
        if not fd.has_csrf_token and fd.method == "POST":
            out.append(_f("Form lacks CSRF token", "medium", "CSRF", fd.page_url,
                          "No CSRF token field detected; state-changing POST may be forgeable.",
                          "Add a per-session CSRF token and verify it server-side.", "CWE-352",
                          fd.action, confidence="medium"))
        if fd.page_url.startswith("http://"):
            out.append(_f("Form posts over plaintext HTTP", "high", "Transport", fd.page_url,
                          "Submitted data (potentially credentials) travels unencrypted.",
                          "Serve the page and action over HTTPS.", "CWE-319", fd.action))
    return out


def check_secrets_in_source(js_texts: dict[str, str], pages: list[PageData]) -> list[Finding]:
    out: list[Finding] = []
    sources = dict(js_texts)
    for p in pages:
        for i, s in enumerate(p.inline_scripts):
            sources[f"{p.url}#inline-{i}"] = s
    for url, src in sources.items():
        for name, rx in SCRIPT_SECRET_PATTERNS:
            m = rx.search(src)
            if m:
                sev = "critical" if name in ("AWS Access Key", "Private key block") else "high"
                if name == "Generic secret assignment":
                    sev = "medium"  # often false positives from template docs
                snippet = m.group(0)
                if name == "Generic secret assignment":
                    snippet = snippet[:60] + "…"
                out.append(_f(f"Possible secret in client-side source: {name}", sev, "Information Disclosure", url,
                              "Hardcoded credentials/keys shipped to the browser are public.",
                              "Remove secrets from client code; rotate any exposed key immediately.",
                              "CWE-798", snippet, confidence="medium" if sev == "medium" else "high"))
    return out


def check_info_disclosure(result: CrawlResult) -> list[Finding]:
    out: list[Finding] = []
    # directory listing
    for page in result.pages:
        body = page.content[:2000].lower()
        if page.status == 200 and ("index of /" in body or "<title>directory listing" in body):
            out.append(_f("Directory listing enabled", "high", "Information Disclosure", page.url,
                          "Server exposes a browsable file index.",
                          "Disable autoindex; remove listing from sensitive dirs.", "CWE-548"))
        if page.status == 200 and re.search(r"<\?php|warning: |fatal error|stack trace", body):
            m = re.search(r"(warning: .*|fatal error.*)", body)
            out.append(_f("Server error details exposed", "low", "Information Disclosure", page.url,
                          "Verbose error output leaks paths/stack details.",
                          "Disable display_errors in production; log server-side.", "CWE-209",
                          (m.group(0)[:120] if m else "")))
    # source maps
    for url in list(result.js_texts):
        if url.endswith(".js") and not url.endswith(".min.js"):
            pass
    for page in result.pages:
        for m in re.finditer(r"//[#@]\s*sourceMappingURL=(\S+\.map)", page.content or ""):
            out.append(_f("Source map exposed in production JS", "low", "Information Disclosure", page.url,
                          "Source maps reveal original source code, comments, and possibly secrets.",
                          "Do not deploy .map files to production.", "CWE-540", m.group(1)))
    # robots-hidden paths become light findings only as info
    if result.robots_disallows:
        out.append(_f("robots.txt reveals hidden paths", "info", "Information Disclosure",
                      result.pages[0].url if result.pages else "",
                      f"{len(result.robots_disallows)} Disallow entries hint at unlinked endpoints.",
                      "Rely on authentication, not obscurity.", "CWE-200",
                      "; ".join(result.robots_disallows[:10])))
    return out


def check_outgoing_links(result: CrawlResult, scope: str) -> list[Finding]:
    out: list[Finding] = []
    off = list(dict.fromkeys(result.off_scope_links))
    if off:
        out.append(_f("Links/redirects leave the scanned scope", "info", "Recon",
                      scope, f"{len(off)} unique external/redirect targets observed (first few: "
                      + ", ".join(u[:80] for u in off[:5]) + ").",
                      "Review whether these redirects are intended (open-redirect sink candidates).",
                      "CWE-601", confidence="info"))
    return out


def check_tech_fingerprint(result: CrawlResult) -> list[Finding]:
    out: list[Finding] = []
    if not result.pages:
        return out
    home = result.pages[0]
    gen = home.meta_generator
    if gen:
        out.append(_f("Technology disclosed via meta generator", "info", "Recon", home.url,
                      "Generator meta tag discloses the CMS/framework and often its version.",
                      "Remove the generator meta tag.", "CWE-200", gen))
    return out


# ============================ active (non-destructive) checks ============================

XSS_PAYLOAD = 'fsx"\'()<>fsx9'
XSS_MARKER = "fsx9"

SQLI_PAYLOADS = [
    ("'", ["sql", "syntax", "mysql", "postgres", "sqlite", "odbc", "jdbc", "unclosed quotation"]),
    ("1' OR '1'='1", ["sql", "syntax", "mysql", "odbc"]),
    ("1 UNION SELECT NULL--", ["sql", "syntax", "union"]),
    ("'; SELECT NULL--", ["sql", "syntax", "query"]),
]
ERROR_RX = re.compile(
    r"(you have an error in your sql syntax|unclosed quotation mark|quoted string not properly terminated"
    r"|warning: mysql|pg_query\(|sqlite3?::query|ora-\d{5}|microsoft ole db|odbc.*driver|sqlstate\s*\d+)",
    re.I)

OPEN_REDIRECT_PARAMS = ("next", "redirect", "url", "return", "returnurl", "goto", "dest", "continue", "target", "rurl")
REDIRECT_MARK = "fsafe-redirect-check.example"

CRLF_PROBE = "fsafe%0d%0aX-Injected-Header:%20fsafe"


async def active_checks(cfg: ScanConfig, client: RateLimitedClient, result: CrawlResult,
                        stats: JobStats, log, progress_cb=None) -> list[Finding]:
    out: list[Finding] = []
    tested = 0
    # scope lock: only ever probe parameters on the target origin itself
    scope = origin_of(cfg.url)
    in_scope_params = [(u, p) for u, p in result.get_params if origin_of(u) == scope]

    # ---- reflected XSS in GET params ----
    seen_pairs: set[tuple[str, str]] = set()
    for url, param in in_scope_params[:60]:
        key = (url.split("?")[0], param)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        tested += 1
        probe = _swap_param(url, param, XSS_PAYLOAD)
        try:
            r = await client.get(probe)
            stats.requests = client.requests_sent
        except httpx.HTTPError:
            continue
        if XSS_MARKER in (r.text or "") and XSS_PAYLOAD.split('"')[0] in (r.text or ""):
            # marker came back un-encoded → likely reflection
            ctx = _reflected_context(r.text or "", XSS_MARKER)
            sev = "high" if ctx in ("html-body", "attribute") else "medium"
            out.append(_f(f"Reflected input in parameter '{param}'", sev, "XSS", probe,
                          f"Parameter value is reflected {ctx} without apparent encoding — classic reflected XSS sink.",
                          "HTML-encode output per context; add CSP; validate input.", "CWE-79",
                          f"payload: {XSS_PAYLOAD}", confidence="medium"))
        if progress_cb and tested % 5 == 0:
            await progress_cb(f"XSS probe {tested}")

    # ---- SQLi error-based in GET params ----
    sqli_seen: set[tuple[str, str]] = set()
    for url, param in in_scope_params[:40]:
        key = (url.split("?")[0], param)
        if key in sqli_seen:
            continue
        sqli_seen.add(key)
        for payload, _hints in SQLI_PAYLOADS[:2]:
            probe = _swap_param(url, param, payload)
            try:
                r = await client.get(probe)
                stats.requests = client.requests_sent
            except httpx.HTTPError:
                break
            m = ERROR_RX.search(r.text or "")
            if m:
                out.append(_f(f"SQL error on parameter '{param}'", "high", "SQL Injection", probe,
                              "Database error surfaced in response to a malformed value — likely injectable or at minimum error-disclosing.",
                              "Use parameterized queries; disable verbose DB errors.", "CWE-89",
                              m.group(0)[:120], confidence="medium"))
                break

    # ---- open redirect heuristic ----
    for url, param in in_scope_params:
        if param.lower() in OPEN_REDIRECT_PARAMS:
            probe = _swap_param(url, param, f"https://{REDIRECT_MARK}/x")
            try:
                r = await client.get(probe)
                stats.requests = client.requests_sent
                loc = r.headers.get("location", "")
                if r.status_code in (301, 302, 303, 307, 308) and REDIRECT_MARK in loc:
                    out.append(_f(f"Open redirect via parameter '{param}'", "high", "Open Redirect", probe,
                                  "Server redirects to an arbitrary external URL from user input.",
                                  "Validate redirect targets against an allow-list.", "CWE-601",
                                  f"Location: {loc[:150]}"))
            except httpx.HTTPError:
                continue
            break

    # ---- CRLF injection in path-derived params ----
    for url, param in in_scope_params[:20]:
        probe = _swap_param(url, param, CRLF_PROBE.replace("%0d%0a", "\r\n"))
        try:
            r = await client.get(probe)
            stats.requests = client.requests_sent
            if "x-injected-header" in {k.lower() for k in r.headers}:
                out.append(_f(f"CRLF injection in parameter '{param}'", "high", "Injection", probe,
                              "Response header injection via CRLF — enables session fixing/XSS.",
                              "Reject CR/LF in user input before placing in headers.", "CWE-113",
                              "X-Injected-Header echoed back"))
        except (httpx.HTTPError, ValueError):
            continue
        break

    # ---- TRACE method (XST) ----
    try:
        r = await client.trace(cfg.url)
        stats.requests = client.requests_sent
        if r.status_code == 200 and "TRACE" in (r.text or "")[:500].upper():
            out.append(_f("HTTP TRACE method enabled", "low", "Configuration", cfg.url,
                          "TRACE echoes requests (cross-site tracing risk with cookies).",
                          "Disable TRACE method on the web server.", "CWE-650"))
    except (httpx.HTTPError, ValueError):
        pass

    # ---- HTTP→HTTPS redirect & TLS ----
    if cfg.url.startswith("https://"):
        http_url = "http://" + urlparse(cfg.url).netloc + "/"
        try:
            r = await client.get(http_url, headers={"User-Agent": "FSafe-Scanner/1.0"})
            stats.requests = client.requests_sent
            if r.status_code < 300 or (r.status_code in (301, 302) and not r.headers.get("location", "").startswith("https")):
                out.append(_f("HTTP does not redirect to HTTPS", "medium", "Transport", http_url,
                              "Plain-HTTP requests are served instead of being redirected.",
                              "301-redirect all HTTP traffic to HTTPS.", "CWE-319",
                              f"status {r.status_code}"))
        except httpx.HTTPError:
            pass
        tls = await _tls_info(urlparse(cfg.url).hostname, urlparse(cfg.url).port or 443)
        if tls:
            if tls.get("proto") in ("TLSv1", "TLSv1.1"):
                out.append(_f("Outdated TLS version offered", "medium", "Transport", cfg.url,
                              f"Server negotiates {tls['proto']}, deprecated by modern standards.",
                              "Disable TLS 1.0/1.1; require TLS 1.2+.", "CWE-327", tls["proto"]))
            days = tls.get("days_left", 999)
            if days < 14:
                out.append(_f("TLS certificate expiring", "high" if days < 0 else "medium", "Transport", cfg.url,
                              f"Certificate has {days} day(s) left or is expired.",
                              "Renew the certificate.", "CWE-324", f"{days} days"))

    log(f"active checks complete: {tested} parameter probes")
    return out


def _swap_param(url: str, param: str, value: str) -> str:
    """Replace one query param's value, keeping everything else."""
    from urllib.parse import parse_qsl, urlsplit, urlunsplit
    s = urlsplit(url)
    q = [(k, value if k == param else v) for k, v in parse_qsl(s.query, keep_blank_values=True)]
    if not any(k == param for k, _ in q):
        q.append((param, value))
    return urlunsplit((s.scheme, s.netloc, s.path, urlencode(q), s.fragment))


def _reflected_context(html: str, marker: str) -> str:
    """Rough classification of where the marker landed."""
    i = html.find(marker)
    if i == -1:
        return "nowhere"
    before = html[max(0, i - 40):i]
    if re.search(r"<script[^>]*$", before, re.I):
        return "script"
    if re.search(r"<!--[^>]*$", before):
        return "comment"
    if re.search(r"<[a-zA-Z][^>]*$", before):
        return "attribute" if '"' in before or "'" in before else "tag"
    return "html-body"


async def _tls_info(host: str, port: int) -> dict | None:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        r, w = await asyncio_wait_for_ssl(host, port, ctx)
        proto = r.version() or ""
        import datetime
        not_after = r.getpeercert()["notAfter"] if r.getpeercert() else None
        w.close()
        days_left = 999
        if not_after:
            try:
                import time as _t
                exp = ssl.cert_time_to_seconds(not_after)
                days_left = int((exp - _t.time()) // 86400)
            except Exception:
                pass
        return {"proto": proto, "days_left": days_left}
    except Exception:
        return None


async def asyncio_wait_for_ssl(host: str, port: int, ctx: ssl.SSLContext):
    import asyncio

    async def _conn():
        r, w = await asyncio.open_connection(host, port, ssl=ctx)
        return r, w

    return await asyncio.wait_for(_conn(), timeout=8)


# ============================ orchestrator ============================

async def run_all_checks(cfg: ScanConfig, client: RateLimitedClient, result: CrawlResult,
                         stats: JobStats, log, progress_cb=None) -> list[Finding]:
    findings: list[Finding] = []
    steps = [
        ("headers", lambda: check_security_headers(result.pages)),
        ("cookies", lambda: check_cookies(result.pages)),
        ("mixed content", lambda: check_mixed_content(result.pages)),
        ("forms", lambda: check_form_security(result.forms)),
        ("secrets", lambda: check_secrets_in_source(result.js_texts, result.pages)),
        ("info disclosure", lambda: check_info_disclosure(result)),
        ("links", lambda: check_outgoing_links(result, origin_of(cfg.url))),
        ("fingerprint", lambda: check_tech_fingerprint(result)),
    ]
    for name, fn in steps:
        got = fn()
        log(f"check[{name}] → {len(got)} finding(s)")
        findings.extend(got)
        if progress_cb:
            await progress_cb(f"check: {name}")

    active = await active_checks(cfg, client, result, stats, log, progress_cb)
    findings.extend(active)

    # probed sensitive paths → findings
    crawler_paths = getattr(result, "_probed_paths_cache", None)
    return findings


def attach_probed_paths_findings(probed: dict[str, int]) -> list[Finding]:
    """Called by the engine with the crawler's sensitive-path probe results."""
    out: list[Finding] = []
    sensitive_hits = [u for u in probed if any(
        s in u for s in ("/.git", "/.env", "/backup", "/id_rsa", "/dump.sql", "/db.sql",
                         "/.htaccess", "/.svn", "/.DS_Store", "/web.config"))]
    for u in sensitive_hits:
        out.append(_f("Sensitive file/directory exposed", "critical", "Information Disclosure", u,
                      "A well-known sensitive path is publicly reachable (source control, env files, backups, or keys).",
                      "Remove the file from the web root and block access (deny rules); rotate any exposed secrets.",
                      "CWE-538", f"HTTP {probed[u]}"))
    admin_hits = [u for u in probed if any(s in u for s in ("/admin", "/wp-admin", "/phpmyadmin", "/cpanel", "/console", "/actuator", "/panel", "/dashboard"))
                  ]
    for u in admin_hits:
        out.append(_f("Admin/management surface reachable", "medium", "Authentication", u,
                      "A management endpoint is reachable without authentication from the scanner.",
                      "Restrict by IP/VPN, enforce strong auth + rate limiting.", "CWE-425",
                      f"HTTP {probed[u]}", confidence="medium"))
    return out
