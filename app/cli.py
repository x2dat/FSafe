"""CLI runner — no server needed.

Usage:
    python -m app.cli https://example.com
    python -m app.cli https://example.com --max-pages 50 --delay 0.5 --out report.html
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from . import authlog
from .colors import (BOLD, RESET, dim, err, grade as gcolor, head, ok,
                     finding_line, warn)
from .models import ScanConfig
from .engine import Engine

BANNER = f"""
{head('🛡 FSafe — web vulnerability scanner')}{dim('  (authorized testing only)')}
"""


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="fsafe",
        description="FSafe — web vulnerability scanner for AUTHORIZED security testing only.")
    ap.add_argument("url", help="target URL (must be one you are authorized to test)")
    ap.add_argument("--max-pages", type=int, default=30, help="max pages to crawl (default 30)")
    ap.add_argument("--delay", type=float, default=0.35, help="seconds between requests (default 0.35)")
    ap.add_argument("--timeout", type=float, default=15.0, help="request timeout seconds")
    ap.add_argument("--no-brute", action="store_true", help="skip common sensitive-path probing")
    ap.add_argument("--ignore-robots", action="store_true", help="ignore robots.txt (still stay legal!)")
    ap.add_argument("--out", default="fsafe_report.html", help="output HTML report path")
    ap.add_argument("--json-out", default=None, help="optional JSON report path")
    ap.add_argument("--auth-log", action="store_true", help="show the authorization audit log and exit")
    ap.add_argument("--yes", action="store_true", help="assert authorization non-interactively (CI use)")
    args = ap.parse_args()

    print(BANNER)

    # ---- audit-log viewer mode ----
    if args.auth_log:
        state = authlog.verify()
        if state["ok"] and state["entries"]:
            print(ok(f"✓ audit trail intact — {state['entries']} entries, chain verified"))
        elif state["entries"] == 0:
            print(warn("no authorization entries recorded yet"))
        for issue in state["issues"]:
            print(err(f"⚠ TAMPER EVIDENCE: {issue}"))
        entries = authlog._read_log()
        for e in entries:
            icon = "✓" if e["kind"] == "AUTHORIZATION" else "•"
            line = f"  {icon} {e['time_local']}  {e['kind']:14} {e['user']}@{e['host']}  {e['target']}"
            if e["kind"] == "AUTHORIZATION":
                print(ok(line))
            else:
                print(dim(line))
        return 0

    # ---- authorization gate ----
    print(f"Before scanning, confirm your authorization for {BOLD}{args.url}{RESET}:")
    print(dim("  You must own this target OR have written permission from its owner to"))
    print(dim("  security-test it. Unauthorized scanning is illegal in most jurisdictions."))
    if args.yes:
        method = "asserted via --yes flag"
        print(warn("\nAuthorization ASSERTED via --yes — you are responsible for this claim."))
    else:
        ans = input(f"\n{BOLD}Type exactly:{RESET} I am authorized\n> ").strip()
        if not authlog.phrase_matches(ans):
            print(err("✖ Aborted — authorization not confirmed. Scanning without permission is illegal."))
            return 2
        method = f"typed confirmation '{authlog.PHRASE}'"
        print(ok("✓ Authorization statement received."))

    # ---- tamper-evident audit trail ----
    rec = authlog.verify_and_record_authorization(args.url, method)
    if not rec["verified"]["ok"]:
        for issue in rec["verified"]["issues"]:
            print(err(f"⚠⚠ TAMPER ALERT: {issue}"))
        print(err("  The authorization trail for this tool was modified or deleted."))
        print(err("  This event has been permanently recorded in the audit log."))
    e = rec["entry"]
    print(ok(f"✓ Authorization logged: {e['time_local']} · {e['user']}@{e['host']} · "
             f"chain hash {e['hash'][:12]}…"))

    cfg = ScanConfig(
        url=args.url, max_pages=args.max_pages, delay=args.delay, timeout=args.timeout,
        brute_dirs=not args.no_brute, respect_robots=not args.ignore_robots, authorized=True)

    engine = Engine()
    engine.authorization_record = (
        f"{method} · audit entry {e['hash'][:12]} · "
        + ("chain verified" if rec["verified"]["ok"] else "TAMPER DETECTED (see audit log)"))

    async def wait():
        job, jerr = engine.create_job(cfg)
        if jerr:
            print(err(f"error: {jerr}"))
            return 2
        while job.status in ("queued", "running"):
            await asyncio.sleep(0.5)
        return 0

    rc = asyncio.run(wait())
    if rc:
        return rc
    job = next(iter(engine.jobs.values()))

    # ---- summary ----
    print("\n" + head("═" * 62))
    if job.status == "error":
        print(err(f"✖ SCAN FAILED: {job.error}"))
        return 1
    authlog.record_scan_result(cfg.url, len(job.findings), job.grade)
    print(f" {head('Target ')} {job.cfg.url}")
    print(f" {head('Grade  ')} {gcolor(job.grade)}{dim(f'  (risk {job.risk}/100)')}")
    print(f" {head('Pages  ')} {job.stats.get('pages')}   "
          f"{head('Requests')} {job.stats.get('requests')}   "
          f"{head('Time')} {job.stats.get('elapsed')}s")
    print(f" {head('Findings')} {warn(str(len(job.findings))) if job.findings else ok('0')}")
    for f in job.findings:
        print(finding_line(f["severity"], f["title"], f["url"]))
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(job.html_report)
    print(f"\n {ok('HTML report:')} {args.out}")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(job.json_report)
        print(f" {ok('JSON report:')} {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
