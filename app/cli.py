"""CLI runner — no server needed.

Usage:
    python -m app.cli https://example.com
    python -m app.cli https://example.com --max-pages 50 --delay 0.5 --out report.html
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from .models import ScanConfig
from .engine import Engine


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
    ap.add_argument("--yes", action="store_true", help="skip authorization prompt (implies you are authorized)")
    args = ap.parse_args()

    print(__doc__.strip())
    print("\nBefore scanning, confirm your authorization:")
    print(f"  You must own {args.url} OR have written permission from its owner")
    print("  to perform security testing on it. Unauthorized scanning is illegal")
    print("  in most jurisdictions (CFAA, Computer Misuse Act, etc.).")
    auth_record = None
    if args.yes:
        # --yes asserts authorization non-interactively (CI / scripted use)
        auth_record = "asserted via --yes flag"
        print("\nAuthorization ASSERTED via --yes — you are responsible for this claim.")
    else:
        ans = input("\nType exactly: I am authorized\n> ").strip().lower()
        if ans != "i am authorized":
            print("Aborted — authorization not confirmed. Scanning without permission is illegal.")
            return 2
        auth_record = f"typed confirmation at {__import__('time').strftime('%Y-%m-%d %H:%M:%S')}"
        print("Authorization recorded.")

    cfg = ScanConfig(
        url=args.url, max_pages=args.max_pages, delay=args.delay, timeout=args.timeout,
        brute_dirs=not args.no_brute, respect_robots=not args.ignore_robots, authorized=True)

    engine = Engine()
    engine.authorization_record = auth_record

    async def wait():
        job, err = engine.create_job(cfg)
        if err:
            print(f"error: {err}")
            return 2
        while job.status in ("queued", "running"):
            await asyncio.sleep(0.5)
        return 0

    rc = asyncio.run(wait())
    if rc:
        return rc
    job = next(iter(engine.jobs.values()))

    print("\n" + "=" * 60)
    if job.status == "error":
        print(f"SCAN FAILED: {job.error}")
        return 1
    print(f"Target : {job.cfg.url}")
    print(f"Grade  : {job.grade}  (risk {job.risk}/100)")
    print(f"Pages  : {job.stats.get('pages')}   Requests: {job.stats.get('requests')}   "
          f"Time: {job.stats.get('elapsed')}s")
    print(f"Findings: {len(job.findings)}")
    from .models import SEV_COLOR
    for f in job.findings:
        print(f"  [{f['severity'].upper():8}] {f['title']}  →  {f['url'][:70]}")
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(job.html_report)
    print(f"\nHTML report: {args.out}")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(job.json_report)
        print(f"JSON report: {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
