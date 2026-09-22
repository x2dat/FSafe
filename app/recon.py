"""Recon module — map everything about a target without touching it hard.

All sources are passive or extremely light:
- DNS: DNS-over-HTTPS (dns.google JSON API)
- WHOIS: plain whois protocol (whois.iana.org + referrals)
- Subdomains: Certificate Transparency logs (crt.sh) — passive, no guesses
- IP / geo / ASN: ip-api.com free endpoint
- Ports: single connect() to 14 common ports with banner grab — not a port scan sweep
- Tech fingerprint: header + HTML signatures
- Emails/contacts: regex harvest from crawled pages
- security.txt / sitemap.xml: direct fetches
"""
from __future__ import annotations

import asyncio
import json
import re
import socket
from urllib.parse import urlparse

import httpx

from .models import ScanConfig

DOH_ENDPOINTS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
]
RTYPES = {1: "A", 5: "CNAME", 15: "MX", 2: "NS", 16: "TXT", 28: "AAAA", 6: "SOA", 257: "CAA"}
WANT_RECORDS = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]

COMMON_PORTS = [
    (21, "FTP"), (22, "SSH"), (25, "SMTP"), (53, "DNS"), (80, "HTTP"), (110, "POP3"),
    (143, "IMAP"), (443, "HTTPS"), (445, "SMB"), (1433, "MSSQL"), (3306, "MySQL"),
    (3389, "RDP"), (8080, "HTTP-alt"), (8443, "HTTPS-alt"),
]

TECH_SIGNATURES = [
    ("WordPress", ["wp-content", "wp-includes"], ["html"]),
    ("Next.js", ["__NEXT_DATA__", "/_next/"], ["html"]),
    ("Nuxt", ["__NUXT__"], ["html"]),
    ("React", ["react", "data-reactroot"], ["html", "headers"]),
    ("Vue.js", ["vue.runtime", "data-v-"], ["html"]),
    ("Angular", ["ng-version", "angular"], ["html"]),
    ("jQuery", ["jquery"], ["html"]),
    ("Bootstrap", ["bootstrap"], ["html"]),
    ("Shopify", ["cdn.shopify.com", "shopify"], ["html"]),
    ("Squarespace", ["squarespace"], ["html"]),
    ("Wix", ["wix.com", "static.wixstatic"], ["html"]),
    ("Cloudflare", ["cf-ray", "cloudflare"], ["headers"]),
    ("CloudFront", ["x-amz-cf-id", "cloudfront"], ["headers"]),
    ("PHP", ["x-powered-by: php", ".php"], ["headers", "html"]),
    ("ASP.NET", ["x-aspnet", "asp.net", "__viewstate"], ["headers", "html"]),
    ("Laravel", ["laravel", "xsrf-token"], ["headers", "html"]),
    ("Django", ["csrfmiddlewaretoken"], ["html"]),
    ("Rails", ["csrf-param", "x-request-id"], ["headers"]),
    ("Express", ["x-powered-by: express"], ["headers"]),
    ("Google Analytics", ["googletagmanager", "google-analytics"], ["html"]),
    ("Font Awesome", ["font-awesome", "fontawesome"], ["html"]),
]

EMAIL_RX = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
IP_RX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# ---------------- DNS over HTTPS ----------------

async def _doh(client: httpx.AsyncClient, name: str, rtype: str) -> list[dict]:
    for ep in DOH_ENDPOINTS:
        try:
            r = await client.get(ep, params={"name": name, "type": rtype}, timeout=12,
                                 headers={"Accept": "application/dns-json"})
            j = r.json()
            out = []
            for a in j.get("Answer", []) or []:
                tname = RTYPES.get(a.get("type"), str(a.get("type")))
                out.append({"type": tname, "data": a.get("data", "")})
            if out or j.get("Status") == 0:
                return out
        except Exception:
            continue
    # last-resort fallback: plain socket A resolution
    if rtype == "A":
        try:
            loop = asyncio.get_running_loop()
            ips = await loop.run_in_executor(
                None, lambda: socket.gethostbyname_ex(name)[2])
            return [{"type": "A", "data": ip} for ip in ips[:6]]
        except Exception:
            pass
    return []


async def dns_section(client: httpx.AsyncClient, domain: str) -> dict:
    results = await asyncio.gather(*[_doh(client, domain, t) for t in WANT_RECORDS])
    records = {}
    for t, lst in zip(WANT_RECORDS, results):
        if lst:
            records[t] = lst[:12]
    dnssec = False
    try:
        for ep in DOH_ENDPOINTS:
            r = await client.get(ep, params={"name": domain, "type": "A"}, timeout=12,
                                 headers={"Accept": "application/dns-json"})
            j = r.json()
            dnssec = bool(j.get("AD"))
            break
    except Exception:
        pass
    return {"domain": domain, "records": records, "dnssec": dnssec}


# ---------------- WHOIS (socket protocol) ----------------

def _whois_query(server: str, query: str, timeout: float = 8.0) -> str:
    try:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall((query + "\r\n").encode())
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except Exception:
        return ""


def whois_section(domain: str) -> dict:
    tld = domain.rsplit(".", 1)[-1]
    raw = _whois_query("whois.iana.org", domain)
    m = re.search(r"whois:\s*(\S+)", raw)
    server = m.group(1) if m else f"whois.{tld}"
    detail = _whois_query(server, domain)
    text = detail or raw
    interesting = {}
    for key, rx in [
        ("registrar", r"Registrar:\s*(.+)"),
        ("created", r"(?:Creation Date|Registered On|created):\s*(.+)"),
        ("expires", r"(?:Registry Expiry Date|Expiration Date|Expiry Date|expires):\s*(.+)"),
        ("updated", r"(?:Updated Date|Last Updated|changed):\s*(.+)"),
        ("status", r"(?:Domain Status|status):\s*(.+)"),
        ("name_servers", r"(?:Name Server|nserver):\s*(.+)"),
    ]:
        hits = re.findall(rx, text, re.I)
        if hits:
            interesting[key] = [h.strip() for h in hits[:6]]
    return {"server": server, "available_fields": list(interesting), **interesting,
            "raw_excerpt": text[:1500] if not interesting else ""}


# ---------------- subdomains via Certificate Transparency ----------------

async def subdomain_section(client: httpx.AsyncClient, domain: str) -> list[str]:
    try:
        r = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=25)
        names = set()
        for row in r.json():
            for n in str(row.get("name_value", "")).split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(domain) and n != domain and "*" not in n:
                    names.add(n)
        return sorted(names)[:60]
    except Exception:
        return []


# ---------------- IP / geo / ASN ----------------

async def geo_section(client: httpx.AsyncClient, hostname: str) -> dict:
    try:
        loop = asyncio.get_running_loop()
        ips = await loop.run_in_executor(None, lambda: socket.gethostbyname_ex(hostname)[2])
        ip = ips[0] if ips else None
        geo = {}
        if ip:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,reverse,query", timeout=10)
            j = r.json()
            if j.get("status") == "success":
                geo = {k: j.get(k) for k in ("country", "regionName", "city", "isp", "org", "as", "reverse")}
        return {"ip": ip, "all_ips": ips[:8], **geo}
    except Exception:
        return {"ip": None}


# ---------------- light port check ----------------

async def _probe_port(host: str, port: int, label: str) -> dict | None:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.5)
        banner = b""
        if port not in (80, 443):
            try:
                banner = await asyncio.wait_for(w.reader.read(128), timeout=1.5) if hasattr(w, "reader") else b""
            except Exception:
                pass
        w.close()
        return {"port": port, "service": label, "banner": banner.decode("utf-8", "replace").strip()[:80]}
    except Exception:
        return None


async def ports_section(hostname: str) -> dict:
    host = hostname
    if IP_RX.match(host) is None:
        try:
            host = socket.gethostbyname(hostname)
        except Exception:
            return {"open": [], "note": "could not resolve host"}
    results = await asyncio.gather(*[_probe_port(host, p, l) for p, l in COMMON_PORTS])
    open_ports = [r for r in results if r]
    return {"open": open_ports, "tested": len(COMMON_PORTS)}


# ---------------- tech fingerprint ----------------

def tech_section(home_headers: dict, home_html: str) -> list[str]:
    found = []
    hay_h = " ".join(f"{k}: {v}" for k, v in home_headers.items()).lower()
    hay_b = (home_html or "").lower()
    for name, sigs, where in TECH_SIGNATURES:
        for s in sigs:
            if ("headers" in where and s in hay_h) or ("html" in where and s in hay_b):
                found.append(name)
                break
    return sorted(set(found))


# ---------------- content harvest ----------------

def harvest_emails(pages_html: list[str]) -> list[str]:
    emails = set()
    for html in pages_html:
        for e in EMAIL_RX.findall(html or ""):
            if not e.lower().endswith((".png", ".jpg", ".gif", ".webp")) and len(e) < 60:
                emails.add(e.lower())
    return sorted(emails)[:25]


# ---------------- well-known files ----------------

async def wellknown_section(client: httpx.AsyncClient, base_url: str) -> dict:
    out = {}
    try:
        r = await client.get(base_url.rstrip("/") + "/.well-known/security.txt", timeout=10)
        if r.status_code == 200 and "contact" in r.text.lower():
            out["security_txt"] = r.text[:600]
    except Exception:
        pass
    try:
        r = await client.get(base_url.rstrip("/") + "/sitemap.xml", timeout=12)
        if r.status_code == 200 and "<urlset" in r.text.lower():
            out["sitemap_urls"] = len(re.findall(r"<loc>", r.text, re.I))
            out["sitemap_sample"] = re.findall(r"<loc>(.*?)</loc>", r.text, re.I)[:10]
    except Exception:
        pass
    try:
        r = await client.get(base_url.rstrip("/") + "/humans.txt", timeout=10)
        if r.status_code == 200 and len(r.text) < 5000:
            out["humans_txt"] = r.text[:400]
    except Exception:
        pass
    return out


# ---------------- orchestrator ----------------

async def run_recon(cfg: ScanConfig, client: httpx.AsyncClient, home_headers: dict,
                    pages_html: list[str], log, progress_cb=None) -> dict:
    """All recon sections; each is independent and failure-tolerant."""
    p = urlparse(cfg.url)
    hostname = p.hostname or ""
    domain = hostname.removeprefix("www.")

    async def step(name, coro):
        if progress_cb:
            await progress_cb(f"recon: {name}")
        try:
            return name, await coro
        except Exception as e:
            log(f"recon[{name}] failed: {type(e).__name__}: {e}")
            return name, {}

    out = {}
    steps = [
        ("dns", dns_section(client, domain)),
        ("geo", geo_section(client, hostname)),
        ("subdomains", subdomain_section(client, domain)),
        ("ports", ports_section(hostname)),
        ("whois", asyncio.to_thread(whois_section, domain)),
        ("wellknown", wellknown_section(client, cfg.url)),
    ]
    done = await asyncio.gather(*[step(n, c) for n, c in steps])
    for name, value in done:
        out[name] = value

    out["tech"] = tech_section(home_headers, pages_html[0] if pages_html else "")
    out["emails"] = harvest_emails(pages_html)
    log(f"recon complete: dns={'ok' if out['dns'] else '—'}, whois={'ok' if out['whois'].get('registrar') else '—'}, "
        f"{len(out['subdomains'])} subdomains, {len(out['ports'].get('open', []))}/{out['ports'].get('tested', 0)} ports open, "
        f"{len(out['tech'])} technologies, {len(out['emails'])} emails")
    return out


def recon_findings(recon: dict, domain: str) -> list[dict]:
    """Turn recon facts into low-key findings where relevant."""
    from .models import Finding
    out: list[Finding] = []

    def add(title, severity, desc, remediation, cwe="", evidence=""):
        out.append(Finding(title, severity, "Recon", f"https://{domain}", desc,
                           remediation, cwe, evidence).to_dict())

    dns = recon.get("dns", {})
    txt = " ".join(r["data"] for r in dns.get("records", {}).get("TXT", []))
    if dns.get("records", {}).get("MX") and "v=spf1" not in txt:
        add("No SPF record despite active mail (MX)", "low",
            "Without SPF, anyone can send email spoofing your domain.",
            "Publish a v=spf1 TXT record listing authorized senders.", "CWE-290")
    if not dns.get("records", {}).get("CAA"):
        add("No CAA record", "info",
            "Any CA may issue certificates for this domain.",
            "Publish CAA records limiting issuance to your CAs.", "CWE-295")
    if dns and not dns.get("dnssec"):
        add("DNSSEC not enabled", "info",
            "DNS answers can be spoofed in transit (cache poisoning).",
            "Enable DNSSEC signing at your registrar.", "CWE-350")
    open_ports = recon.get("ports", {}).get("open", [])
    unexpected = [p for p in open_ports if p["service"] not in ("HTTP", "HTTPS")]
    if unexpected:
        add(f"Unexpected open ports: {', '.join(str(p['port']) + ' (' + p['service'] + ')' for p in unexpected)}",
            "low", "Services other than web are reachable on this host.",
            "Close ports not needed publicly or firewall them.", "CWE-284",
            "; ".join(p.get("banner", "") for p in unexpected if p.get("banner")))
    if not recon.get("wellknown", {}).get("security_txt"):
        add("No security.txt", "info",
            "Researchers have no published channel to report vulnerabilities.",
            "Publish /.well-known/security.txt with a Contact field.", "CWE-1059")
    return out
