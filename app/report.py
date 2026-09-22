"""Report generation: HTML dashboard report + JSON export."""
from __future__ import annotations

import html
import json
from collections import Counter

from .models import SEV_COLOR, SEV_ORDER, Finding, ScanConfig, JobStats

GRADES = {"A": 0, "B": 3, "C": 8, "D": 15, "F": 25}


def score(findings: list[dict]) -> tuple[str, int]:
    """Letter grade + numeric risk score (0 best, 100 worst)."""
    pts = sum({"critical": 12, "high": 7, "medium": 3, "low": 1, "info": 0}[f["severity"]] for f in findings)
    pts = min(100, pts)
    grade = "A"
    for g, threshold in GRADES.items():
        if pts >= threshold:
            grade = g
    return grade, pts


def _recon_html(recon: dict) -> str:
    if not recon:
        return ""
    import html as _h

    def esc(s):
        return _h.escape(str(s))

    parts = [f"<div class='card'><h2>🌐 Recon & footprint</h2>"]

    dns = recon.get("dns", {})
    if dns.get("records"):
        rows = "".join(
            f"<tr><td>{esc(r['type'])}</td><td class='url'>{esc(r['data'])}</td></tr>"
            for recs in dns["records"].values() for r in recs[:8])
        parts.append(f"<h3>DNS records {('<span class=\"cwe\">DNSSEC: ' + ('on' if dns.get('dnssec') else 'off') + '</span>')}</h3>"
                     f"<table>{rows}</table>")
    geo = recon.get("geo", {})
    if geo.get("ip"):
        parts.append(f"<h3>Hosting</h3><p>{esc(geo.get('ip'))} — {esc(geo.get('org') or geo.get('isp') or '')}, "
                     f"{esc(geo.get('city') or '')} {esc(geo.get('country') or '')}<br>"
                     f"<span class='url'>{esc(geo.get('as') or '')} {esc(geo.get('reverse') or '')}</span></p>")
    ports = recon.get("ports", {}).get("open", [])
    if ports:
        pills = " ".join(f"<span class='pill' style='display:inline-block;margin:2px'>{p['port']} · {esc(p['service'])}</span>"
                         for p in ports)
        parts.append(f"<h3>Open ports ({len(ports)}/{recon.get('ports', {}).get('tested', '?')} common)</h3><p>{pills}</p>")
    tech = recon.get("tech", [])
    if tech:
        parts.append("<h3>Technology stack</h3><p>" + " · ".join(esc(t) for t in tech) + "</p>")
    subs = recon.get("subdomains", [])
    if subs:
        parts.append(f"<h3>Subdomains ({len(subs)}, via Certificate Transparency)</h3><p class='url'>"
                     + esc(", ".join(subs[:30])) + "</p>")
    emails = recon.get("emails", [])
    if emails:
        parts.append("<h3>Emails found in pages</h3><p class='url'>" + esc(", ".join(emails)) + "</p>")
    whois = recon.get("whois", {})
    if whois.get("registrar"):
        fields = " · ".join(f"{k}: {esc(', '.join(v) if isinstance(v, list) else esc(v))}"
                            for k, v in whois.items()
                            if k in ("registrar", "created", "expires", "updated", "status") and v)
        parts.append(f"<h3>WHOIS</h3><p>{fields}</p>")
    wk = recon.get("wellknown", {})
    if wk.get("sitemap_urls"):
        parts.append(f"<p>sitemap.xml: {wk['sitemap_urls']} URLs · security.txt: "
                     f"{'present' if wk.get('security_txt') else 'missing'}</p>")
    parts.append("</div>")
    return "".join(parts)


def report_html(target: str, cfg: ScanConfig, stats: dict, findings: list[dict],
                pages: list[dict], grade: str, risk: int, recon: dict | None = None) -> str:
    counts = Counter(f["severity"] for f in findings)
    rows = []
    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
    for f in sorted(findings, key=lambda x: sev_rank.get(x["severity"], 9)):
        c = SEV_COLOR.get(f["severity"], "#888")
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{c}">{f['severity'].upper()}</span></td>
          <td><b>{html.escape(f['title'])}</b><br>
              <span class="url">{html.escape(f['url'])}</span><br>
              <small>{html.escape(f['description'])}</small><br>
              <small><i>Fix: {html.escape(f['remediation'])}</i> {('<small class="cwe">'+html.escape(f['cwe'])+'</small>') if f['cwe'] else ''}</small>
          </td>
          <td>{html.escape(f['category'])}<br><small>{f['confidence']} conf.</small></td>
        </tr>""")
    page_rows = "".join(
        f"<tr><td>{p['status']}</td><td class='url'>{html.escape(p['url'])}</td></tr>"
        for p in pages[:200])
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>FSafe Report — {html.escape(target)}</title>
<style>
 body{{font-family:Segoe UI,system-ui,sans-serif;background:#0b0e14;color:#e6e6e6;margin:0}}
 .wrap{{max-width:1000px;margin:0 auto;padding:32px}}
 h1{{color:#fff}} .grade{{font-size:64px;font-weight:800}}
 .card{{background:#131722;border-radius:12px;padding:20px;margin:16px 0}}
 table{{width:100%;border-collapse:collapse}} td,th{{padding:10px;border-bottom:1px solid #232a3a;vertical-align:top;text-align:left}}
 .badge{{color:#fff;border-radius:6px;padding:2px 10px;font-size:12px;font-weight:700}}
 .url{{color:#6ea8fe;font-size:12px;word-break:break-all}} .cwe{{color:#8b93a7}}
 .grid{{display:flex;gap:12px;flex-wrap:wrap}}
 .pill{{background:#1b2233;border-radius:8px;padding:10px 16px;text-align:center}}
</style></head><body><div class="wrap">
<h1>🛡 FSafe Vulnerability Report</h1>
<p>Target: <b>{html.escape(target)}</b> · {stats.get('pages',0)} pages · {stats.get('requests',0)} requests · {stats.get('elapsed',0)}s</p>
<div class="card"><span class="grade" style="color:{'green' if grade in 'AB' else 'orange' if grade=='C' else 'red'}">{grade}</span>
 <span style="font-size:20px">risk score {risk}/100</span>
 <div class="grid" style="margin-top:10px">
  {''.join(f'<div class="pill"><b style="color:{SEV_COLOR[s]}">{counts.get(s,0)}</b><br>{s}</div>' for s in SEV_ORDER)}
 </div></div>
<div class="card"><h2>Findings ({len(findings)})</h2>
 <table><tr><th>Severity</th><th>Detail</th><th>Category</th></tr>{''.join(rows) or '<tr><td colspan=3>🎉 No findings</td></tr>'}</table></div>
{_recon_html(recon or {})}
<div class="card"><h2>Crawled pages</h2><table>{page_rows}</table></div>
<p><small>Generated by FSafe — for authorized security testing only. Findings marked "medium/low confidence" need manual verification.</small></p>
</div></body></html>"""


def report_json(target: str, cfg: ScanConfig, stats: dict, findings: list[dict], pages: list[dict],
                authorization: str = "", recon: dict | None = None) -> str:
    grade, risk = score(findings)
    return json.dumps({
        "tool": "FSafe 1.0",
        "target": target,
        "grade": grade,
        "risk_score": risk,
        "authorization_record": authorization,
        "recon": recon or {},
        "config": cfg.to_dict(),
        "stats": stats,
        "findings": findings,
        "pages": [{"url": p["url"], "status": p["status"]} for p in pages],
    }, indent=2)
