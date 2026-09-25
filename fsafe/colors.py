"""ANSI color helpers for the CLI (Windows Terminal / VT-enabled consoles)."""
from __future__ import annotations

import os
import platform
import sys


def force_utf8_stdio() -> None:
    """Force UTF-8 on stdout/stderr so emoji/box-drawing survive piped or
    redirected output (Windows defaults to the legacy code page, e.g. cp1252,
    when stdout is not a TTY — which previously crashed with UnicodeEncodeError)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass  # non-standard stream wrapper (IDE capture, tests) — best effort


force_utf8_stdio()

# enables ANSI on legacy Windows consoles
if platform.system() == "Windows":
    os.system("")

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GRAY = "\033[90m"

SEV_COLOR = {
    "critical": RED,
    "high": "\033[38;5;208m",
    "medium": YELLOW,
    "low": GREEN,
    "info": BLUE,
}
SEV_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH    ",
    "medium": "MEDIUM  ",
    "low": "LOW     ",
    "info": "INFO    ",
}

GRADE_COLOR = {"A": GREEN, "B": GREEN, "C": YELLOW, "D": "\033[38;5;208m", "F": RED}


def sev_badge(severity: str) -> str:
    color = SEV_COLOR.get(severity, GRAY)
    return f"{color}{BOLD}[{SEV_LABEL.get(severity, severity.upper()):9}]{RESET}"


def grade(g: str) -> str:
    return f"{GRADE_COLOR.get(g, WHITE)}{BOLD}{g}{RESET}"


def ok(msg: str) -> str:
    return f"{GREEN}{msg}{RESET}"


def warn(msg: str) -> str:
    return f"{YELLOW}{msg}{RESET}"


def err(msg: str) -> str:
    return f"{RED}{BOLD}{msg}{RESET}"


def dim(msg: str) -> str:
    return f"{GRAY}{msg}{RESET}"


def head(msg: str) -> str:
    return f"{CYAN}{BOLD}{msg}{RESET}"


def finding_line(severity: str, title: str, url: str) -> str:
    return f"  {sev_badge(severity)} {WHITE}{title}{RESET}\n              {dim(url)}"
