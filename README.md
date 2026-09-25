<div align="center">

# 🛡 FSafe

**A web application vulnerability scanner — crawl the site, probe everything, get a full report.**

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![FastAPI](https://img.shields.io/badge/backend-FastAPI-009485)](https://fastapi.tiangolo.com/)

FastAPI server · asyncio crawler · 20+ security checks · HTML + JSON reports · web dashboard & CLI

</div>

> ⚠️ **Authorized testing only.** Scanning systems you don't own or lack written permission to test is illegal in most jurisdictions (CFAA, Computer Misuse Act, etc.). FSafe enforces this with an authorization gate, is scope-locked to the exact target host, rate-limited, and uses non-destructive detection payloads only.

---

## Features

- **Recursive crawler** — breadth-first, follows same-site links, parses JS files, honors `robots.txt`, extracts forms & URL parameters
- **Web dashboard** — live streaming log, animated progress, letter grade, severity breakdown, downloadable HTML/JSON reports
- **CLI** — fully standalone, no server needed, prints findings to the terminal
- **Non-destructive** — detection-only payloads (no data destruction, brute force, or DoS patterns)
- **Brutal mode** (`--brutal`) — deep active payload battery: SQLi (error/boolean/time/UNION), NoSQL, LDAP, XPath, command injection, SSTI, traversal, SSRF, smuggling, cache, CORS, DOM XSS, auth probing, JWT, IDOR signals, API/GraphQL, debug surface, upload execution, XXE — budget-capped and scope-locked
- **Global rate limiter** — every request is throttled; polite by default
- **Color-coded CLI** — severity badges, grades and statuses in ANSI color
- **Authorization gate** — the CLI requires typing `I am authorized` (or `--yes` for CI); the agreement and timestamp are recorded in every report

### Checks included

| Category | Checks |
|---|---|
| **Headers** | Missing CSP / HSTS / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy, weak CSP, versioned banners |
| **Injection** | Reflected XSS per parameter (with context classification), error-based SQLi, CRLF header injection |
| **Transport** | Mixed content, plaintext forms, HTTP→HTTPS redirect, TLS version, certificate expiry |
| **Auth & sessions** | Cookie flags (HttpOnly/Secure/SameSite), GET-submitted passwords, missing CSRF tokens, exposed admin panels |
| **Info disclosure** | Secrets/API keys in client-side source, exposed `.env` / `.git` / backups / source maps, directory listings, verbose errors, robots.txt intel |
| **Other** | Open redirect heuristics, TRACE method, technology fingerprinting |
| **Recon** | DNS (all record types, DNSSEC, DoH with fallback), WHOIS (registrar/dates/status), subdomains via Certificate Transparency, hosting IP/geo/ASN, light common-port check with banners, tech-stack fingerprinting, email harvesting, `security.txt` / `sitemap.xml` / `humans.txt`, SPF/CAA checks |

---

## Install

```bash
pip install fsafe
```

This installs three commands:

| Command | What it does |
|---|---|
| `fsafe` | CLI scanner — no server needed |
| `fsafe-dashboard` | Web dashboard at http://127.0.0.1:8787 |
| `fsafe-demo` | Deliberately vulnerable local test target on 127.0.0.1:9911 |

Prefer module syntax? `python -m fsafe`, `python -m fsafe.main` and `python -m fsafe.demo_target` do the same thing.

### From source

```bash
git clone https://github.com/x2dat/fsafe.git
cd fsafe
pip install .
```

### Web dashboard

```bash
fsafe-dashboard
# → http://127.0.0.1:8787
```

Enter the target URL, confirm authorization, hit **Start scan**. You get a live log, progress bar, grade (A–F), risk score, and findings with fixes — plus HTML/JSON report links per scan.

### CLI

```bash
fsafe https://your-target.com --yes --out report.html --json-out report.json
```

| Flag | Default | Description |
|---|---|---|
| `--max-pages N` | `30` | Crawl depth cap (1–300) |
| `--delay S` | `0.35` | Minimum seconds between requests |
| `--timeout S` | `15` | Per-request timeout |
| `--brutal` | off | Deep active payload battery (see below) |
| `--brutal-probe-subdomains` | off | With `--brutal`: fetch DNS-discovered subdomains (out-of-scope hosts!) |
| `--out FILE` | `fsafe_report.html` | HTML report path |
| `--json-out FILE` | — | Also write JSON report |

---

## Brutal mode

`fsafe <url> --brutal` runs a deep, active payload battery — hundreds of attack
probes organized into 15 families, on top of every normal check:

| Battery | What it does |
|---|---|
| **SQL injection** | error-based, boolean-blind differential, time-based (SLEEP/WAITFOR/pg_sleep), UNION column errors |
| **NoSQL / LDAP / XPath** | operator injection (`$ne`/`$gt`), filter injection, predicate injection |
| **OS command / SSTI** | `id` evidence + time-based; template math evaluation across Jinja/JSP/ERB/Vue engines |
| **Traversal / LFI / RFI** | `../etc/passwd` variants incl. encoding & null-byte; remote-include error signals |
| **SSRF** | cloud metadata + `file://` targets with in-band evidence; optional blind-SSRF canary via `FSAFE_CANARY_DOMAIN` |
| **Request smuggling** | CL.TE / TE.CL desync on one raw connection (transport anomalies never reported) |
| **Cache / headers** | unkeyed `X-Forwarded-Host` / `X-Forwarded-Scheme` reflection |
| **CORS** | arbitrary-origin reflection with/without credentials, preflight |
| **DOM XSS** | source→sink dataflow (location.* → innerHTML/eval/…) in page JS |
| **Auth** | username enumeration, rate-limit/lockout detection, default-credential verification |
| **JWT** | `alg=none` and unusual algorithms in client assets, token exposure |
| **Access control / IDOR** | unauthenticated object endpoints (provable) + sequential-id signals (info, manual follow-up) |
| **API security** | GraphQL introspection, sensitive-field exposure, unbounded pagination, method override |
| **Debug surface** | phpinfo, pprof, actuator/env, adminer, laravel logs, `.git/config`, web.xml |
| **File upload** | acceptance vs **verified execution** — a `.php` upload only becomes critical when the marker actually executes |
| **XXE** | external-entity file read on XML endpoints |

### Hard guarantees (architecture, not discipline)

- **Hard request budget** — the ONLY way brutal can make an HTTP request is
  through budget-aware wrappers that spend exactly one unit *before* any traffic
  leaves. Requests are mathematically capped at 400.
- **Scope-locked** — every brutal request goes through the scoped client; a
  collateral server placed next to the target receives zero requests (tested).
- **Discovered subdomains are DNS information** — never auto-fetched. Active
  subdomain probing requires the explicit `--brutal-probe-subdomains` consent
  flag, and is reported clearly as out-of-scope.
- **Findings require evidence** — heuristics ship as info/low/medium with honest
  titles; signals are never conflated with verified vulnerabilities.

### Honest coverage

Every brutal report ends with a coverage finding listing exactly what was
automated versus what **requires manual testing** (stored XSS, second-order
injection, race conditions, business logic, OAuth/SAML, MFA bypass, verified
IDOR with two accounts, deserialization chains, cloud IAM, supply chain…).
"0 findings" from automation is NOT "0 vulnerabilities" — work the manual list.
| `--no-brute` | — | Skip common sensitive-path probing |
| `--no-recon` | — | Skip DNS/WHOIS/subdomains/ports/tech recon |
| `--ignore-robots` | — | Ignore robots.txt |
| `--yes` | — | Skip authorization prompt |

### Try it safely

Ship with a deliberately vulnerable local target:

```bash
fsafe-demo                         # serves http://127.0.0.1:9911
fsafe http://127.0.0.1:9911 --yes
```

---

## Scope isolation (guaranteed)

FSafe **never sends requests to any host other than the exact target origin**. This is enforced twice:

1. Every crawler/check filters URLs by origin before requesting (fast path).
2. The HTTP client itself carries an **origin allow-list** — any out-of-scope request raises and is refused *before a single byte leaves the process*, and the refusal is logged (`BLOCKED out-of-scope request: …`).

Off-scope links found in pages, and redirects pointing outside the target, are recorded as report observations — never followed. The TLS/geo/recon providers (DNS-over-HTTPS, WHOIS, ipwho.is) only ever receive the target **hostname or IP**, never crawled content. A pytest suite proves this with a live "collateral" server that must receive zero requests while the scan runs.

## Infrastructure anomaly detection

Beyond per-request checks, FSafe reasons over the collected facts (DNS, WHOIS, TLS cert, geo/ASN, ports, headers, cookies) the way an analyst would:

| Anomaly | Signal |
|---|---|
| IP identity drift | CDN/ISP org vs unrelated reverse-DNS (PTR) record |
| Multi-homed /24 | Several A records for the domain inside one IPv4 /24 |
| NS on suspicious TLDs | Authoritative DNS on free TLDs (.tk/.ml/.ga/.cf/.gq) |
| Mail-only domain | MX records but no A/AAAA web records |
| Very young domain | WHOIS creation < 30 days (phishing indicator) |
| Short registration | Registered lifetime < 13 months |
| Certificate anomalies | Expired / self-signed / hostname-not-in-SAN / weak key or signature |
| Exposed datastores | MySQL/MSSQL/RDP/SMB/POP3/IMAP reachable from the internet |
| Header conflicts | `Server` vs meta-generator disagreement; fully stripped stack |
| `__Host-` cookie violations | Prefix rules broken — browsers silently drop the cookie |
| JS-readable session cookies | `Secure` but no `HttpOnly` — XSS can steal the session |
| Wildcard DNS | Random subdomains resolve — takeover findings become noise |
| Origin shielding | CDN detected; warns about origin-IP leaks via mail/SSH subdomains |

---

## Testing

```bash
pip install -e .[dev]
pytest -v
```

The suite spins up real local HTTP servers (no mocks): a vulnerable target, a clean target, an SPA catch-all, and a collateral host for the scope-isolation proofs.

---

## Scoring

Findings are weighted (critical 12 · high 7 · medium 3 · low 1) into a 0–100 **risk score** and a letter **grade**:

| Grade | Risk score |
|---|---|
| A | 0–2 |
| B | 3–7 |
| C | 8–14 |
| D | 15–24 |
| F | 25+ |

Findings marked *medium/low confidence* are heuristic and should be verified manually.

## Architecture

```
fsafe/
├── main.py         FastAPI server + REST API (POST /api/scan, GET /api/scan/{id}, reports)
├── engine.py       Job orchestration: crawl → checks → dedupe → score → report
├── crawler.py      Async BFS crawler, robots.txt, redirect chains, artifact capture
├── checks.py       Passive + active check modules (all non-destructive)
├── http_client.py  Global rate-limited HTTP client with scope helpers
├── parser.py       HTML/JS parsing, link/form/secret extraction
├── report.py       HTML + JSON report generation, grading
├── recon.py        Passive recon: DNS, WHOIS, CT subdomains, geo, ports, tech, emails
├── cli.py          Standalone CLI runner
├── demo_target.py  Intentionally vulnerable local test server
├── models.py       Data models (Findings, ScanConfig, PageData…)
└── frontend/
    └── index.html  Zero-dependency dashboard (vanilla JS)
```

**API:** `POST /api/scan` · `GET /api/scan/{id}` · `POST /api/scan/{id}/cancel` · `GET /api/scan/{id}/report.html` · `GET /api/scan/{id}/report.json` — interactive docs at `/api/docs`.

## Safety model

- **Scope lock** — only URLs on the exact target origin are requested; off-scope links are logged, never followed
- **Authorization gate** — both UI and CLI require explicit confirmation
- **Rate limit** — global throttle on every request (default ~3 req/s)
- **Non-destructive payloads** — benign markers, arithmetic and error-based probes only; no exfiltration, brute force, or flooding

## License

[MIT](LICENSE)
