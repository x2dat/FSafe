"""Core data models: findings, scan configuration, crawl artifacts."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
SEV_COLOR = {
    "critical": "#e5484d",
    "high": "#f76b15",
    "medium": "#ffb224",
    "low": "#46a758",
    "info": "#3e63dd",
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single detected issue."""

    title: str
    severity: str  # one of SEV_ORDER
    category: str
    url: str
    description: str
    remediation: str
    cwe: str = ""
    evidence: str = ""
    confidence: str = "high"  # high | medium | low (heuristic)

    def to_dict(self) -> dict:
        return {
            "id": uuid.uuid4().hex[:12],
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "url": self.url,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }

    def dedupe_key(self) -> tuple:
        return (self.category, self.title.split("(")[0].strip(), self.url)


@dataclass
class ScanConfig:
    """User-controlled scan parameters."""

    url: str = ""
    max_pages: int = 30
    delay: float = 0.35  # seconds between requests (politeness)
    timeout: float = 15.0
    brute_dirs: bool = True
    respect_robots: bool = True
    authorized: bool = False  # must be True to start a scan

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "max_pages": self.max_pages,
            "delay": self.delay,
            "timeout": self.timeout,
            "brute_dirs": self.brute_dirs,
            "respect_robots": self.respect_robots,
        }


@dataclass
class FormField:
    name: str
    ftype: str  # input type / textarea / select
    value: str = ""


@dataclass
class FormData:
    """An HTML form discovered during crawling."""

    page_url: str
    action: str  # absolute
    method: str  # GET / POST
    fields: list[FormField] = field(default_factory=list)
    has_password: bool = False
    has_csrf_token: bool = False
    enctype: str = ""


@dataclass
class PageData:
    """Artifacts extracted from one crawled HTML page."""

    url: str
    status: int
    headers: dict
    content: str = ""
    links: list[str] = field(default_factory=list)
    scripts_src: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    mixed_content: list[str] = field(default_factory=list)  # http:// resources on https page
    meta_generator: str = ""
    title: str = ""
    forms: list[FormData] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    set_cookies: list[str] = field(default_factory=list)
    redirects: list[str] = field(default_factory=list)  # redirect chain to this page


@dataclass
class CrawlResult:
    pages: list[PageData] = field(default_factory=list)
    forms: list[FormData] = field(default_factory=list)
    get_params: list[tuple[str, str]] = field(default_factory=list)  # (url, param_name)
    js_texts: dict[str, str] = field(default_factory=dict)  # url -> js source
    tech_signals: dict[str, str] = field(default_factory=dict)
    off_scope_links: list[str] = field(default_factory=list)
    robots_disallows: list[str] = field(default_factory=list)


@dataclass
class JobStats:
    requests: int = 0
    pages: int = 0
    forms: int = 0
    params: int = 0
    js_files: int = 0
    errors: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0

    @property
    def elapsed(self) -> float:
        if not self.started_at:
            return 0.0
        return (self.finished_at or time.time()) - self.started_at

    def to_dict(self) -> dict:
        return {
            "requests": self.requests,
            "pages": self.pages,
            "forms": self.forms,
            "params": self.params,
            "js_files": self.js_files,
            "errors": self.errors,
            "elapsed": round(self.elapsed, 1),
        }
