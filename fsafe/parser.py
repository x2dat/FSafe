"""HTML parsing: extract links, scripts, forms, params, mixed content."""
from __future__ import annotations

import re
from html import unescape
from urllib.parse import urljoin, urlparse, parse_qsl

from bs4 import BeautifulSoup

from .models import FormData, FormField, PageData


def _abs(base: str, href: str) -> str | None:
    try:
        if not href:
            return None
        href = href.strip()
        if href.startswith(("javascript:", "mailto:", "tel:", "data:", "#", "about:")):
            return None
        return urljoin(base, href)
    except ValueError:
        return None


def parse_page(page: PageData) -> None:
    """Populate PageData artifacts in place from its HTML content."""
    html = page.content or ""
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return

    if soup.title and soup.title.string:
        page.title = unescape(soup.title.string.strip())[:200]

    gen = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    if gen:
        page.meta_generator = (gen.get("content") or "")[:200]

    for a in soup.find_all("a", href=True):
        u = _abs(page.url, a["href"])
        if u:
            page.links.append(u)

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            u = _abs(page.url, src)
            if u:
                page.scripts_src.append(u)
        elif tag.string and len(tag.string) > 10:
            page.inline_scripts.append(str(tag.string))

    # external subresources for mixed-content + SRI checks
    if page.url.startswith("https://"):
        for tag in soup.find_all(True, src=True):
            u = _abs(page.url, tag.get("src") or "")
            if u and u.startswith("http://"):
                page.mixed_content.append(u)
        for tag in soup.find_all(True, href=True):
            u = _abs(page.url, tag.get("href") or "")
            if u and u.startswith("http://") and "stylesheet" in (tag.get("rel") or []):
                if u not in page.mixed_content:
                    page.mixed_content.append(u)

    # forms
    for f in soup.find_all("form"):
        action = _abs(page.url, f.get("action") or page.url) or page.url
        fd = FormData(
            page_url=page.url,
            action=action,
            method=(f.get("method") or "get").upper(),
            enctype=f.get("enctype", ""),
        )
        for inp in f.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or inp.name).lower()
            val = inp.get("value") or ""
            fd.fields.append(FormField(name=name, ftype=itype, value=val))
            if itype in ("password",):
                fd.has_password = True
            low = name.lower()
            if "csrf" in low or "token" in low or "_token" in low or "authenticity" in low:
                fd.has_csrf_token = True
        if fd.fields:
            page.forms.append(fd)

    # query params on this page's URL
    try:
        page.query_params = sorted({k for k, _ in parse_qsl(urlparse(page.url).query)})
    except ValueError:
        pass


def extract_get_links(page: PageData) -> list[tuple[str, str]]:
    """(url, param) pairs from links/urls carrying a query string."""
    out: list[tuple[str, str]] = []
    seen_urls = {page.url, *page.links}
    for u in seen_urls:
        try:
            q = parse_qsl(urlparse(u).query, keep_blank_values=True)
        except ValueError:
            continue
        for k, _v in q:
            out.append((u.split("?")[0] + "?" + urlparse(u).query, k))
    return out


SCRIPT_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("JWT in source", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}")),
    ("Generic secret assignment", re.compile(r"""(?i)(api[_\-]?key|secret|passwd|password|pwd|auth[_\-]?token)\s*[:=]\s*["'][^"']{8,}["']""")),
]
