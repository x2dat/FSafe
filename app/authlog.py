"""Tamper-evident authorization audit log.

Layout (inside <project>/.fsafe_auth/):
  authorization_log.jsonl   append-only entries, each chained to the previous via sha256
  manifest.json             hidden + read-only: entry count, last chain hash
  .receipt                  hidden + read-only: redundant copy of last chain hash

Tamper properties:
- editing/removing a log line breaks the chain → detected on next scan
- deleting the log leaves manifest + .receipt behind → detected
- deleting everything leaves nothing, but all three files are hidden+read-only
  (removal on Windows requires `attrib` changes / admin-ish intent)

Every scan appends one AUTH entry and one SCAN entry; verification failures are
recorded permanently as TAMPER events.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

AUTH_DIR = Path(__file__).resolve().parent.parent / ".fsafe_auth"
LOG = AUTH_DIR / "authorization_log.jsonl"
MANIFEST = AUTH_DIR / "manifest.json"
RECEIPT = AUTH_DIR / ".receipt"

PHRASE = "i am authorized"


# ---------------- file protection helpers ----------------

def _unprotect(p: Path) -> None:
    if not p.exists():
        return
    os.chmod(p, 0o644)
    if platform.system() == "Windows":
        subprocess.run(["attrib", "-R", "-H", str(p)], capture_output=True)


def _protect(p: Path) -> None:
    if not p.exists():
        return
    if platform.system() == "Windows":
        subprocess.run(["attrib", "+R", "+H", str(p)], capture_output=True)
    os.chmod(p, 0o444)


def _entry_hash(entry: dict) -> str:
    core = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()


# ---------------- core operations ----------------

def _read_log() -> list[dict]:
    if not LOG.exists():
        return []
    out = []
    for line in LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"hash": "CORRUPT-LINE", "_raw": line[:80]})
    return out


def verify() -> dict:
    """Check chain integrity and cross-file consistency. Never raises."""
    issues: list[str] = []
    entries = _read_log()

    if MANIFEST.exists() and not LOG.exists():
        issues.append("authorization log is MISSING but manifest exists (log deleted)")
    if RECEIPT.exists() and not LOG.exists():
        issues.append("authorization log is MISSING but tamper receipt exists (log deleted)")

    prev = "GENESIS"
    for i, e in enumerate(entries):
        expected = _entry_hash({k: v for k, v in e.items() if k != "hash"})
        if e.get("hash") != expected:
            issues.append(f"entry #{i + 1} hash mismatch (line modified)")
        if e.get("prev") != prev:
            issues.append(f"entry #{i + 1} chain link broken (entries inserted/removed)")
        prev = e.get("hash", prev)

    if MANIFEST.exists() and LOG.exists():
        try:
            m = json.loads(MANIFEST.read_text())
            if m.get("last_hash") != prev:
                issues.append("manifest last-hash disagrees with log (log truncated/replaced)")
            if m.get("count") != len(entries):
                issues.append(f"manifest count {m.get('count')} != log count {len(entries)}")
        except Exception:
            issues.append("manifest unreadable")

    if RECEIPT.exists() and LOG.exists():
        try:
            r = RECEIPT.read_text().strip()
            if r and r != prev:
                issues.append("hidden receipt disagrees with log (log truncated/replaced)")
        except Exception:
            issues.append("receipt unreadable")

    return {"ok": not issues, "issues": issues, "entries": len(entries), "last_hash": prev}


def _append(kind: str, target: str, detail: dict) -> dict:
    AUTH_DIR.mkdir(exist_ok=True)
    state = verify()
    prev = state["last_hash"] if state["ok"] or state["entries"] else "GENESIS"
    entry = {
        "kind": kind,
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "time_local": time.strftime("%Y-%m-%d %H:%M:%S"),
        "user": getpass.getuser(),
        "host": socket.gethostname(),
        "target": target,
        **detail,
        "chain_ok_before": state["ok"],
        "tamper_issues_before": state["issues"],
        "prev": prev,
    }
    entry["hash"] = _entry_hash(entry)

    for p in (LOG, MANIFEST, RECEIPT):
        _unprotect(p)

    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")

    MANIFEST.write_text(json.dumps({
        "count": len(_read_log()),
        "last_hash": entry["hash"],
        "last_updated": entry["time_utc"],
        "note": "FSafe tamper-evident authorization manifest",
    }, indent=2))
    RECEIPT.write_text(entry["hash"])

    for p in (LOG, MANIFEST, RECEIPT):
        _protect(p)
    return entry


def verify_and_record_authorization(target: str, method: str) -> dict:
    """Called before a scan: verify trail, then permanently record consent."""
    pre = verify()
    entry = _append("AUTHORIZATION", target, {
        "method": method,
        "statement": "operator confirmed ownership or written permission to test target",
    })
    return {"verified": pre, "entry": entry}


def record_scan_result(target: str, findings: int, grade: str) -> dict:
    return _append("SCAN", target, {"findings": findings, "grade": grade})


def phrase_matches(typed: str) -> bool:
    return typed.strip().lower() == PHRASE
