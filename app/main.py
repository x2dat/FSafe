"""FSafe web server: dashboard UI + JSON API.

Run:  python -m app.main      → http://127.0.0.1:8787
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel

from .engine import ENGINE
from .models import ScanConfig

app = FastAPI(title="FSafe", docs_url="/api/docs")
STATIC = Path(__file__).resolve().parent.parent / "frontend"


class ScanRequest(BaseModel):
    url: str
    max_pages: int = 30
    delay: float = 0.35
    brute_dirs: bool = True
    respect_robots: bool = True
    include_recon: bool = True
    authorized: bool = False


@app.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(STATIC / "index.html")


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    if req.max_pages < 1 or req.max_pages > 300:
        raise HTTPException(400, "max_pages must be 1-300")
    if req.delay < 0:
        raise HTTPException(400, "delay must be >= 0")
    cfg = ScanConfig(
        url=req.url, max_pages=req.max_pages, delay=req.delay,
        brute_dirs=req.brute_dirs, respect_robots=req.respect_robots,
        include_recon=req.include_recon, authorized=req.authorized)
    job, err = ENGINE.create_job(cfg)
    if err:
        raise HTTPException(400, err)
    return {"id": job.id, "status": job.status}


@app.get("/api/scan/{job_id}")
async def job_status(job_id: str):
    job = ENGINE.jobs.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")
    return job.public()


@app.post("/api/scan/{job_id}/cancel")
async def job_cancel(job_id: str):
    if not ENGINE.cancel(job_id):
        raise HTTPException(400, "job not running")
    return {"ok": True}


@app.get("/api/scan/{job_id}/report.html")
async def job_report(job_id: str):
    job = ENGINE.jobs.get(job_id)
    if not job or not job.html_report:
        raise HTTPException(404, "report not ready")
    return HTMLResponse(job.html_report)


@app.get("/api/scan/{job_id}/report.json")
async def job_json(job_id: str):
    job = ENGINE.jobs.get(job_id)
    if not job or not job.json_report:
        raise HTTPException(404, "report not ready")
    return JSONResponse(content=__import__("json").loads(job.json_report))


def run():
    import uvicorn
    port = int(os.environ.get("FSAFE_PORT", "8787"))
    print(f"🛡 FSafe dashboard → http://127.0.0.1:{port}")
    print("   Authorized testing only. Scope-locked, rate-limited, non-destructive.")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    run()
