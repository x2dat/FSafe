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
- **Global rate limiter** — every request is throttled; polite by default
- **Color-coded CLI** — severity badges, grades and statuses in ANSI color
- **Tamper-evident authorization audit trail** — every scan records *who confirmed authorization, when, and for which target* into `.fsafe_auth/authorization_log.jsonl`, a hash-chained, hidden, read-only log. Editing or deleting it triggers loud tamper alerts that are themselves permanently recorded. Inspect with `python -m app.cli <url> --auth-log` (view mode).

### Checks included

| Category | Checks |
|---|---|
| **Headers** | Missing CSP / HSTS / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy, weak CSP, versioned banners |
| **Injection** | Reflected XSS per parameter (with context classification), error-based SQLi, CRLF header injection |
| **Transport** | Mixed content, plaintext forms, HTTP→HTTPS redirect, TLS version, certificate expiry |
| **Auth & sessions** | Cookie flags (HttpOnly/Secure/SameSite), GET-submitted passwords, missing CSRF tokens, exposed admin panels |
| **Info disclosure** | Secrets/API keys in client-side source, exposed `.env` / `.git` / backups / source maps, directory listings, verbose errors, robots.txt intel |
| **Other** | Open redirect heuristics, TRACE method, technology fingerprinting |

---

## Quick start

```bash
git clone https://github.com/x2dat/fsafe.git
cd fsafe
pip install -r requirements.txt
```

### Web dashboard

```bash
python -m app.main
# → http://127.0.0.1:8787
```

Enter the target URL, confirm authorization, hit **Start scan**. You get a live log, progress bar, grade (A–F), risk score, and findings with fixes — plus HTML/JSON report links per scan.

### CLI

```bash
python -m app.cli https://your-target.com --yes --out report.html --json-out report.json
```

| Flag | Default | Description |
|---|---|---|
| `--max-pages N` | `30` | Crawl depth cap (1–300) |
| `--delay S` | `0.35` | Minimum seconds between requests |
| `--timeout S` | `15` | Per-request timeout |
| `--out FILE` | `fsafe_report.html` | HTML report path |
| `--json-out FILE` | — | Also write JSON report |
| `--no-brute` | — | Skip common sensitive-path probing |
| `--ignore-robots` | — | Ignore robots.txt |
| `--yes` | — | Skip authorization prompt |

### Try it safely

Ship with a deliberately vulnerable local target:

```bash
python -m app.demo_target          # serves http://127.0.0.1:9911
python -m app.cli http://127.0.0.1:9911 --yes
```

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
app/
├── main.py         FastAPI server + REST API (POST /api/scan, GET /api/scan/{id}, reports)
├── engine.py       Job orchestration: crawl → checks → dedupe → score → report
├── crawler.py      Async BFS crawler, robots.txt, redirect chains, artifact capture
├── checks.py       Passive + active check modules (all non-destructive)
├── http_client.py  Global rate-limited HTTP client with scope helpers
├── parser.py       HTML/JS parsing, link/form/secret extraction
├── report.py       HTML + JSON report generation, grading
├── cli.py          Standalone CLI runner
├── demo_target.py  Intentionally vulnerable local test server
└── models.py       Data models (Findings, ScanConfig, PageData…)
frontend/
└── index.html      Zero-dependency dashboard (vanilla JS)
```

**API:** `POST /api/scan` · `GET /api/scan/{id}` · `POST /api/scan/{id}/cancel` · `GET /api/scan/{id}/report.html` · `GET /api/scan/{id}/report.json` — interactive docs at `/api/docs`.

## Safety model

- **Scope lock** — only URLs on the exact target origin are requested; off-scope links are logged, never followed
- **Authorization gate** — both UI and CLI require explicit confirmation
- **Rate limit** — global throttle on every request (default ~3 req/s)
- **Non-destructive payloads** — benign markers, arithmetic and error-based probes only; no exfiltration, brute force, or flooding

## License

[MIT](LICENSE)
