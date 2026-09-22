"""Scan engine: orchestrates crawl → checks → report, as a background job."""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field

from .http_client import RateLimitedClient, normalize_url, same_scope, origin_of
from .crawler import Crawler
from .checks import run_all_checks, attach_probed_paths_findings
from .models import JobStats, ScanConfig
from .report import report_html, report_json, score


@dataclass
class Job:
    id: str
    cfg: ScanConfig
    status: str = "queued"  # queued | running | done | error | cancelled
    log_lines: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    pages: list[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    error: str = ""
    grade: str = ""
    risk: int = 0
    html_report: str = ""
    json_report: str = ""
    task: asyncio.Task | None = None

    def public(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "target": self.cfg.url,
            "error": self.error,
            "grade": self.grade,
            "risk": self.risk,
            "stats": self.stats,
            "findings": self.findings,
            "pages": self.pages,
            "log": self.log_lines[-200:],
        }


class Engine:
    def __init__(self):
        self.jobs: dict[str, Job] = {}

    def create_job(self, cfg: ScanConfig) -> tuple[Job, str]:
        url, scope = normalize_url(cfg.url)
        if not url:
            return None, scope
        if not cfg.authorized:
            return None, "You must confirm you are authorized to test this target."
        cfg.url = url
        job = Job(id=uuid.uuid4().hex[:10], cfg=cfg)
        self.jobs[job.id] = job
        job.task = asyncio.create_task(self._run(job))
        return job, ""

    async def _run(self, job: Job) -> None:
        cfg, stats = job.cfg, JobStats()
        stats.started_at = time.time()

        def log(msg: str) -> None:
            line = f"[{time.strftime('%H:%M:%S')}] {msg}"
            job.log_lines.append(line)
            print(f"  {line}")

        client = RateLimitedClient(delay=cfg.delay, timeout=cfg.timeout)
        try:
            job.status = "running"
            log(f"scan started → {cfg.url} (max_pages={cfg.max_pages}, delay={cfg.delay}s)")

            async def progress(msg: str) -> None:
                log(msg)

            crawler = Crawler(cfg, client, stats, log)
            crawl = await crawler.run(progress_cb=progress)
            log(f"crawl done: {len(crawl.pages)} pages, {len(crawl.forms)} forms, "
                f"{len(crawl.get_params)} unique params")

            # GET forms give us testable params even without query-string links
            from .http_client import same_scope as _ss  # noqa: local use below
            for fd in crawl.forms:
                if fd.method == "GET" and same_scope(fd.action, origin_of(cfg.url)):
                    for fld in fd.fields[:6]:
                        crawl.get_params.append((fd.action, fld.name))

            findings = await run_all_checks(cfg, client, crawl, stats, log, progress)
            findings.extend(attach_probed_paths_findings(crawler.probed_paths))

            # dedupe
            seen: set[tuple] = set()
            unique: list = []
            for f in findings:
                k = f.dedupe_key()
                if k not in seen:
                    seen.add(k)
                    unique.append(f)
            unique.sort(key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity))

            stats.finished_at = time.time()
            job.findings = [f.to_dict() for f in unique]
            job.pages = [{"url": p.url, "status": p.status} for p in crawl.pages]
            job.stats = stats.to_dict()
            job.grade, job.risk = score(job.findings)
            job.html_report = report_html(cfg.url, cfg, job.stats, job.findings, job.pages, job.grade, job.risk)
            job.json_report = report_json(cfg.url, cfg, job.stats, job.findings, job.pages)
            job.status = "done"
            log(f"scan complete: {len(job.findings)} findings · grade {job.grade} (risk {job.risk}/100)")
        except asyncio.CancelledError:
            job.status = "cancelled"
        except Exception as e:
            import traceback
            job.status = "error"
            job.error = f"{type(e).__name__}: {e}"
            log("scan failed: " + traceback.format_exc(limit=6))
        finally:
            await client.aclose()
            stats.finished_at = stats.finished_at or time.time()

    def cancel(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        if job and job.status == "running" and job.task:
            job.task.cancel()
            return True
        return False


ENGINE = Engine()
