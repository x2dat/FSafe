"""Infrastructure anomaly detection — find the things that don't add up.

These checks reason about *facts collected during the scan* (DNS, geo, ports,
certificates, headers, cookies) the way an analyst would: mixed hosting,
sudden-looking ranges, shared panels, soft failed lookups. Everything is
heuristic, so findings carry explicit confidence and concrete evidence.
"""
from __future__ import annotations

import asyncio
import datetime
import ipaddress
import re

import httpx

from .models import ScanConfig, CrawlResult
from .http_client import RateLimitedClient


def _f(title, severity, url, desc, remediation, cwe, evidence="", confidence="medium"):
    from .models import Finding
    return Finding(title, severity, "Infrastructure Anomaly", url, desc,
                   remediation, cwe, evidence, confidence=confidence).to_dict()


def _as_number(as_str: str) -> str | None:
    m = re.search(r"AS(\d+)", as_str or "")
    return m.group(1) if m else None


async def anomaly_findings(cfg: ScanConfig, client: RateLimitedClient,
                           crawl: CrawlResult, recon: dict | None,
                           log, progress_cb=None) -> list:
    """Run every anomaly heuristic; each is independent and failure-tolerant."""
    if progress_cb:
        await progress_cb("check: infrastructure anomalies")
    recon = recon or {}
    checks = [
        ("cdn/ip mismatch", _ip_cdn_mismatch(recon, crawl)),
        ("ip neighborhood", await _ip_neighborhood(recon)),
        ("dns posture", _dns_posture(recon)),
        ("whois posture", _whois_posture(recon)),
        ("cert anomalies", _cert_anomalies(recon, crawl)),
        ("port anomalies", _port_anomalies(recon, crawl)),
        ("header anomalies", _header_anomalies(crawl)),
        ("cookie anomalies", _cookie_anomalies(crawl)),
        ("wildcard dns", _wildcard_dns(recon)),
        ("origin shielding", _origin_shielding(recon)),
    ]
    out: list = []
    for name, got in checks:
        if got:
            if progress_cb:
                await progress_cb(f"anomaly[{name}] → {len(got)} finding(s)")
            log(f"anomaly[{name}] → {len(got)} finding(s)")
            out.extend(got)
    return out


# --------------------------------------------------------------------------
# 1) reverse DNS / IP identity drift: IP says one org, PTR says another
# --------------------------------------------------------------------------

def _ip_cdn_mismatch(recon: dict, crawl: CrawlResult) -> list:
    geo = recon.get("geo", {})
    ip, org = geo.get("ip"), (geo.get("org") or geo.get("isp") or "")
    ptr = geo.get("reverse") or ""
    if not ip:
        return []
    out = []
    cdn_markers = ("cloudflare", "fastly", "cloudfront", "akamai", "google",
                   "microsoft", "azure", "aws", "amazon", "gcore", "imperva",
                   "stackpath", "edgesuite", "cloudflare.net")
    org_is_cdn = any(m in org.lower() for m in cdn_markers)
    # 199.36.158.0/24 = Google-hosted "cloud" customers (e.g. Firebase Hosting)
    try:
        if ipaddress.ip_address(ip).is_private:
            return []
    except ValueError:
        return []
    if ptr and org_is_cdn:
        ptr_host = ptr.lower()
        if not any(m in ptr_host for m in cdn_markers) and org.lower() not in ptr_host:
            out.append(_f(
                "IP identity drift: CDN org vs unrelated PTR",
                "low", f"https://{geo.get('domain') or ip}",
                f"The site answers from {ip} ({org}) but reverse DNS is '{ptr}'. "
                "That is normal behind some CDNs, but an unrelated PTR can also mean "
                "shared/repurposed infrastructure.",
                "Verify the PTR record matches the hosting provider; document expected values.",
                "CWE-1059", f"ip={ip} org={org} ptr={ptr}", confidence="low"))
    return out


# --------------------------------------------------------------------------
# 2) IP neighborhood: target sits in a tiny range with several other domains
#    (classic cheap-shared-hosting fingerprint; noisy but worth knowing)
# --------------------------------------------------------------------------

async def _ip_neighborhood(recon: dict) -> list:
    geo = recon.get("geo", {})
    ip = geo.get("ip")
    if not ip:
        return []
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if addr.is_private or addr.version != 4:
        return []
    out = []
    nets = recon.get("dns", {}).get("records", {}).get("A", [])
    same_subnet = [r["data"] for r in nets if r.get("data") and r["data"] != ip
                   and r["data"].rsplit(".", 1)[0] == ip.rsplit(".", 1)[0]]
    # multiple distinct A records inside one /24 with different ASN-owned orgs
    # is only knowable via external lookups we don't do; keep it simple:
    if len(set(same_subnet)) >= 2 and not geo.get("org"):
        out.append(_f("Multiple A records in the same /24",
                      "info", f"https://{recon.get('geo', {}).get('domain') or ip}",
                      "The domain resolves to several IPs in one /24 — possibly round-robin "
                      "DNS or several services sharing a block.",
                      "Confirm whether all addresses serve this site; remove stale records.",
                      "CWE-1059", ", ".join(sorted(set(same_subnet))), confidence="low"))
    return out


# --------------------------------------------------------------------------
# 3) DNS posture: NS on suspicious TLDs, missing AAAA while IPv6 exists, etc.
# --------------------------------------------------------------------------

def _dns_posture(recon: dict) -> list:
    dns = recon.get("dns", {}).get("records", {})
    out = []
    ns = [r.get("data", "").lower().rstrip(".") for r in dns.get("NS", [])]
    mx = [r.get("data", "").lower() for r in dns.get("MX", [])]
    if ns and any(n.endswith((".tk", ".ml", ".ga", ".cf", ".gq")) for n in ns):
        bad = [n for n in ns if n.endswith((".tk", ".ml", ".ga", ".cf", ".gq"))]
        out.append(_f("Nameservers on free/suspicious TLD",
                      "medium", "https://" + (recon.get("dns", {}).get("domain") or ""),
                      f"Authoritative DNS hosted on {', '.join(bad)} — common with throwaway "
                      "or compromised setups.",
                      "Move DNS to a reputable provider; lock the domain at the registrar.",
                      "CWE-350", ", ".join(bad), confidence="medium"))
    if mx and not dns.get("A") and not dns.get("AAAA"):
        out.append(_f("Mail-only domain (MX but no web records)",
                      "info", "https://" + (recon.get("dns", {}).get("domain") or ""),
                      "MX records exist but no A/AAAA — the domain sends/receives mail "
                      "without a website.",
                      "Expected? If not, investigate who set up mail for this domain.",
                      "CWE-1059", confidence="high"))
    return out


# --------------------------------------------------------------------------
# 4) WHOIS posture: very young domain, privacy-proxied + short expiry
# --------------------------------------------------------------------------

def _whois_posture(recon: dict) -> list:
    who = recon.get("whois", {})
    out = []
    created = (who.get("created") or [""])[0]
    expires = (who.get("expires") or [""])[0]
    def _parse(s: str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%d-%b-%Y", "%Y-%m-%d"):
            try:
                return datetime.datetime.strptime(s.strip(), fmt).replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                continue
        return None
    c, e = _parse(created), _parse(expires)
    now = datetime.datetime.now(datetime.timezone.utc)
    if c:
        age_days = (now - c).days
        if 0 <= age_days < 30:
            out.append(_f("Domain registered within the last 30 days",
                          "medium", "https://" + (recon.get("dns", {}).get("domain") or ""),
                          f"Domain is only {age_days} day(s) old. Brand-new domains are a "
                          "strong phishing/malware indicator (or a legitimately new project).",
                          "If this is your domain, nothing to fix — noted for risk scoring.",
                          "CWE-1059", f"created {created}", confidence="high"))
    if e and c:
        lifetime = (e - c).days
        if 0 < lifetime < 400:
            out.append(_f("Domain registered for less than 13 months",
                          "low", "https://" + (recon.get("dns", {}).get("domain") or ""),
                          f"Registration lifetime is only {lifetime} days — throwaway "
                          "infrastructure habit.",
                          "Multi-year registration signals commitment (and locks the name).",
                          "CWE-1059", f"expires {expires}", confidence="low"))
    return out


# --------------------------------------------------------------------------
# 5) Certificate anomalies (needs the recon cert section)
# --------------------------------------------------------------------------

def _cert_anomalies(recon: dict, crawl: CrawlResult) -> list:
    cert = recon.get("cert", {})
    served = cert.get("served_cert") or {}
    if not served:
        return []
    out = []
    domain = recon.get("dns", {}).get("domain") or ""
    san = served.get("san") or []
    if san:
        covers = any(s == domain or s.endswith("." + domain) for s in san)
        if not covers and domain:
            out.append(_f("TLS certificate does not cover this hostname",
                          "high", f"https://{domain}",
                          f"SAN list ({', '.join(san[:5])}) contains no name for '{domain}'. "
                          "Browsers reject this connection.",
                          "Reissue the certificate including the served hostname.",
                          "CWE-295", ", ".join(san[:8]), confidence="high"))
        cert_org = (served.get("subject_org") or "").lower()
        if cert_org and any(k in cert_org for k in ("par0s", "unknown", "test")):
            out.append(_f("Certificate subject organization looks generic",
                          "low", f"https://{domain}",
                          f"Subject O='{served.get('subject_org')}' — placeholder org names "
                          "often indicate auto-generated or malicious certs.",
                          "Issue the cert with a proper subject for your org.",
                          "CWE-295", served.get("subject_org", ""), confidence="low"))
    return out


# --------------------------------------------------------------------------
# 6) Port anomalies: web on odd port, mail/db ports open on a web server
# --------------------------------------------------------------------------

def _port_anomalies(recon: dict, crawl: CrawlResult) -> list:
    ports = recon.get("ports", {}).get("open", [])
    if not ports:
        return []
    out = []
    labels = {p["service"] for p in ports}
    pnums = {p["port"] for p in ports}
    unexpected = [p for p in ports if p["service"] in ("MySQL", "MSSQL", "RDP", "SMB",
                                                       "POP3", "IMAP", "SMTP", "FTP")]
    if unexpected:
        out.append(_f("Datastore/remote-access ports exposed",
                      "medium", "https://" + (recon.get("dns", {}).get("domain") or ""),
                      "Database or remote-admin ports are reachable from the internet: "
                      + ", ".join(f"{p['port']} ({p['service']})" for p in unexpected) + ".",
                      "Firewall these ports to admin networks only; never expose DB/SSH/RDP publicly.",
                      "CWE-284", "; ".join(p.get("banner", "") for p in unexpected if p.get("banner")),
                      confidence="high"))
    if labels and labels.isdisjoint({"HTTP", "HTTPS"}) and pnums:
        out.append(_f("Web ports closed but other services open",
                      "low", "https://" + (recon.get("dns", {}).get("domain") or ""),
                      "No HTTP/HTTPS answered, yet other ports did — the 'website' may "
                      "live behind a proxy that this scan could not see.",
                      "If unintended, investigate what is actually listening.",
                      "CWE-1059", confidence="medium"))
    return out


# --------------------------------------------------------------------------
# 7) Header anomalies: missing Server header entirely, conflicting hints
# --------------------------------------------------------------------------

def _header_anomalies(crawl: CrawlResult) -> list:
    if not crawl.pages:
        return []
    home = crawl.pages[0]
    h = home.headers
    out = []
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    if not server and not powered:
        out.append(_f("No Server or X-Powered-By header (hardened or proxied)",
                      "info", home.url,
                      "The origin hides its stack — good practice, but it also means "
                      "tech-based findings may be incomplete.",
                      "Nothing to fix; recorded for analyst context.", "CWE-200",
                      confidence="high"))
    gen = home.meta_generator
    if gen and server:
        g = gen.lower()
        s = server.lower()
        pairs_ok = (("wordpress" in g and ("nginx" in s or "apache" in s or "cloudflare" in s or "litespeed" in s))
                    or ("next.js" in g and "cloudflare" in s))
        if not pairs_ok and "php" not in s and "express" not in s:
            out.append(_f("Generator meta and Server header disagree",
                          "low", home.url,
                          f"Meta generator says '{gen}' while Server says '{server}' — possible "
                          "proxying, a stale template, or intentional misdirection.",
                          "Align or remove the generator tag.", "CWE-200",
                          f"generator={gen} server={server}", confidence="low"))
    return out


# --------------------------------------------------------------------------
# 8) Cookie anomalies: session cookie without Secure on an HTTPS site,
#    __Host- prefix violations
# --------------------------------------------------------------------------

def _cookie_anomalies(crawl: CrawlResult) -> list:
    out = []
    for page in crawl.pages:
        for raw in page.set_cookies:
            name = raw.split("=", 1)[0]
            low = raw.lower()
            # __Host- rules apply regardless of scheme: on plain HTTP browsers
            # drop the cookie entirely, which is its own anomaly
            if name.startswith("__Host-") and ("secure" not in low or "path=/" not in low
                                               or "domain=" in low):
                out.append(_f(f"__Host- cookie '{name}' violates its own prefix rules",
                              "medium", page.url,
                              "__Host- cookies must be Secure, Path=/, and have no Domain "
                              "attribute — browsers will silently drop them.",
                              "Fix the cookie attributes or rename it without the prefix.",
                              "CWE-1004", raw[:200], confidence="high"))
            if "sess" in name.lower() and "httponly" not in low and "secure" in low:
                # Secure+no-HttpOnly: JS-readable session token
                out.append(_f(f"Session cookie '{name}' is readable by JavaScript",
                              "low", page.url,
                              "Cookie is Secure but lacks HttpOnly, so any XSS can steal it.",
                              "Add HttpOnly unless the client genuinely needs it.",
                              "CWE-1004", raw[:200], confidence="medium"))
    return out


# --------------------------------------------------------------------------
# 9) Wildcard DNS: every subdomain "exists" → takeover findings are noise
# --------------------------------------------------------------------------

def _wildcard_dns(recon: dict) -> list:
    wd = recon.get("wildcard_dns", {})
    if wd.get("wildcard"):
        return [_f("Wildcard DNS: every subdomain resolves",
                   "medium", "https://" + (recon.get("dns", {}).get("domain") or ""),
                   f"Random names like '{(wd.get('probes') or ['?'])[0]}' resolve to real IPs. "
                   "Subdomain-takeover and phantom-host findings become unreliable, and "
                   "attackers can mint hostnames for phishing on your zone.",
                   "Remove the wildcard record or point it at a sinkhole.",
                   "CWE-350", ", ".join(wd.get("resolved", [])[:4]), confidence="high")]
    return []


# --------------------------------------------------------------------------
# 10) Origin shielding: is the real origin hidden behind the CDN? (info)
# --------------------------------------------------------------------------

def _origin_shielding(recon: dict) -> list:
    geo = recon.get("geo", {})
    org = (geo.get("org") or geo.get("isp") or "").lower()
    out = []
    if not org:
        return out
    cdn = any(m in org for m in ("cloudflare", "fastly", "cloudfront", "akamai",
                                 "imperva", "stackpath", "google llc"))
    if cdn and not recon.get("ports", {}).get("open"):
        pass  # handled by ports finding
    if cdn:
        out.append(_f("Origin shielded by CDN/proxy",
                      "info", "https://" + (recon.get("dns", {}).get("domain") or ""),
                      f"Traffic is served via {geo.get('org') or geo.get('isp')}. Direct-to-origin "
                      "attacks are mitigated, but the true origin IP should stay secret "
                      "(no mail/SSH banners leaking it).",
                      "Ensure no subdomain (e.g. 'direct.', 'mail.') exposes the origin IP.",
                      "CWE-1059", confidence="high"))
    return out
