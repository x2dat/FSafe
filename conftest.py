"""Shared test fixtures: local HTTP servers with hit counters + sync scan runner."""
from __future__ import annotations

import asyncio
import http.server
import socketserver
import threading


class _Srv(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class FreePortServer:
    """Real HTTP server on an OS-assigned 127.0.0.1 port, with a hit counter."""

    def __init__(self, handler, counter: dict | None = None):
        self.counter = counter if counter is not None else {}
        self._srv = _Srv(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._srv.server_address[1]

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()


def make_handler(routes: list[tuple], counter: dict, counter_key: str):
    """routes: list of (prefix, status, headers, body). First prefix match wins;
    body may be a callable(path) -> bytes for dynamic responses; anything else
    gets a proper 404. Every request bumps counter[counter_key]."""

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            counter[counter_key] = counter.get(counter_key, 0) + 1
            # longest prefix wins so "/admin" is not swallowed by the "/" route
            for prefix, status, headers, body in sorted(routes, key=lambda r: -len(r[0])):
                if self.path.startswith(prefix):
                    payload = body(self.path) if callable(body) else body
                    self.send_response(status)
                    for k, v in headers.items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(payload)
                    return
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")

        do_POST = do_GET
        do_HEAD = do_GET

        def log_message(self, *a):
            pass

    return H


def run_scan(target: str, *, max_pages: int = 12, delay: float = 0.0,
             include_recon: bool = False, brute_dirs: bool = True):
    """Run a full Engine scan synchronously; returns the finished Job."""
    from fsafe.engine import Engine
    from fsafe.models import ScanConfig

    async def _run():
        cfg = ScanConfig(url=target, max_pages=max_pages, delay=delay, timeout=5,
                         include_recon=include_recon, brute_dirs=brute_dirs,
                         authorized=True)
        eng = Engine()
        job, errv = eng.create_job(cfg)
        assert errv == "", errv
        while job.status in ("queued", "running"):
            await asyncio.sleep(0.02)
        return job

    return asyncio.run(_run())


def find(findings, substr: str) -> list[dict]:
    out = []
    for f in findings:
        title = f["title"] if isinstance(f, dict) else f.title
        if substr.lower() in title.lower():
            out.append(f)
    return out
