
from typing import Any, Dict
import json

REPORT_CSS = """
:root{--bg:#0b1220;--card:#0f1b33;--muted:#9fb3d1;--txt:#e8f0ff;--accent:#2f6fed;
--crit:#ff2e63;--high:#ff5d5d;--med:#ff9f43;--low:#3ddc97;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font-family:Arial,Helvetica,sans-serif}
.container{max-width:1200px;margin:0 auto;padding:24px}
.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,var(--accent),#1dd3b0)}
h1{font-size:22px;margin:0}
.small{color:var(--muted);font-size:12px;line-height:1.5}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.card{background:var(--card);border:1px solid rgba(255,255,255,.06);border-radius:16px;padding:16px}
.card h2{font-size:16px;margin:0 0 10px 0}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px}
.badge.crit{background:rgba(255,46,99,.18);border:1px solid rgba(255,46,99,.55)}
.badge.high{background:rgba(255,93,93,.2);border:1px solid rgba(255,93,93,.5)}
.badge.med{background:rgba(255,159,67,.2);border:1px solid rgba(255,159,67,.5)}
.badge.low{background:rgba(61,220,151,.2);border:1px solid rgba(61,220,151,.5)}
.badge.info{background:rgba(47,111,237,.2);border:1px solid rgba(47,111,237,.5)}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
th,td{padding:8px;border-bottom:1px solid rgba(255,255,255,.06);text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600}
pre{white-space:pre-wrap;background:rgba(0,0,0,.25);padding:10px;border-radius:12px;border:1px solid rgba(255,255,255,.06);color:#dbe7ff}
.footer{margin-top:18px;color:var(--muted);font-size:12px}
@media (max-width:900px){.grid{grid-template-columns:1fr}}
"""

def html_escape(s: str) -> str:
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def badge(sev: str) -> str:
    sev = sev or "Info"
    cls = "info"
    if sev == "Critical": cls="crit"
    elif sev == "High": cls="high"
    elif sev == "Medium": cls="med"
    elif sev == "Low": cls="low"
    return f"<span class='badge {cls}'>{sev}</span>"

def _cvss_text(nvd_item: Dict[str, Any]) -> str:
    cvss = (nvd_item or {}).get("cvss") or {}
    base = cvss.get("baseScore")
    sev = cvss.get("severity")
    if base is None and sev is None:
        return ""
    if base is None:
        return str(sev)
    if sev:
        return f"{base} ({sev})"
    return str(base)

def build_html_report(scan: Dict[str, Any]) -> str:
    target = scan.get("target_url","")
    host = scan.get("host","")
    ip = scan.get("ip","")
    generated = scan.get("generated_at","")

    services = scan.get("services", []) or []
    zm_hits = scan.get("zoomeye_hits", []) or []
    webcheck = scan.get("webcheck_raw", {}) or {}
    cves = scan.get("cves", []) or []
    exp = scan.get("exploit_intel", {}) or {}
    risk_summary = scan.get("risk_summary", {}) or {}
    nvd = scan.get("nvd", {}) or {}
    nvd_by_cve = (nvd.get("by_cve") or {}) if isinstance(nvd.get("by_cve"), dict) else {}

    
    overall = "Info"
    top_sorted = sorted(
        cves,
        key=lambda c: int((exp.get(c) or {}).get("risk_score") or 0),
        reverse=True
    )
    if top_sorted:
        overall = (exp.get(top_sorted[0]) or {}).get("severity") or "Info"

    ai = scan.get("ai_analysis") or {}
    ai_text = (ai.get("text_ar") or "").strip()
    ai_error = ai.get("_error")

    html = []
    html.append("<!doctype html><html><head><meta charset='utf-8'>")
    html.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    html.append(f"<style>{REPORT_CSS}</style></head><body><div class='container'>")

    html.append("<div class='header'><div class='brand'><div class='logo'></div><div>")
    html.append("<h1>AmanScan Security Exposure Report</h1>")
    html.append(f"<div class='small'>Generated: {html_escape(generated)}</div>")
    html.append("</div></div>")
    html.append(f"<div>{badge(overall)}</div></div>")

    html.append("<div class='card'><h2>Target</h2>")
    html.append(f"<div class='small'><b>URL:</b> {html_escape(target)}<br><b>Host:</b> {html_escape(host)}<br><b>IP:</b> {html_escape(ip)}</div>")
    html.append("</div>")

    
    counts = (risk_summary.get("counts") or {})
    exposure_hint = risk_summary.get("exposure_hint_0_15")
    html.append("<div class='grid' style='margin-top:14px'>")
    html.append("<div class='card'><h2>Risk Summary</h2>")
    html.append("<div class='small'>This score is based on EPSS likelihood + KEV known exploitation + public exploit evidence + exposure.</div>")
    html.append("<table><thead><tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Exposure</th></tr></thead><tbody><tr>")
    html.append(f"<td>{counts.get('Critical',0)}</td><td>{counts.get('High',0)}</td><td>{counts.get('Medium',0)}</td><td>{counts.get('Low',0)}</td><td>{counts.get('Info',0)}</td>")
    html.append(f"<td>{html_escape(str(exposure_hint))}</td>")
    html.append("</tr></tbody></table>")
    html.append("</div>")

    html.append("<div class='card'><h2>AI Analysis (Post-Scan)</h2>")
    if ai_text:
        html.append("<div class='small'>AI-generated defensive narrative. No exploitation instructions included.</div>")
        html.append(f"<pre>{html_escape(ai_text[:120000])}</pre>")
    else:
        html.append("<div class='small'>AI analysis not available.</div>")
        if ai_error:
            html.append(f"<div class='small'>Reason: {html_escape(str(ai_error))}</div>")
    html.append("</div></div>")

    
    cpe_used = nvd.get("cpe_used") or []
    if cpe_used:
        html.append("<div class='card' style='margin-top:14px'><h2>NVD Enrichment (CPE-based)</h2>")
        html.append("<div class='small'>Some CVEs are derived by mapping observed services (CPE fingerprints) to NVD. This often matches what Shodan website shows.</div>")
        html.append("<div class='small'><b>CPEs queried (sample):</b><br>")
        html.append("<pre>" + html_escape("\n".join(cpe_used[:15])) + "</pre></div>")
        errs = nvd.get("errors") or []
        if errs:
            html.append("<div class='small'><b>NVD errors (sample):</b></div><pre>")
            html.append(html_escape(json.dumps(errs[:3], indent=2)[:5000]))
            html.append("</pre>")
        html.append("</div>")

    
    html.append("<div class='card' style='margin-top:14px'><h2>Vulnerabilities (Scored & Explained)</h2>")
    if not cves:
        html.append("<div class='small'>No CVE IDs returned by passive sources.</div>")
    else:
        html.append("<table><thead><tr>"
                    "<th>CVE</th><th>CVSS (NVD)</th><th>Severity</th><th>Risk</th>"
                    "<th>EPSS</th><th>KEV</th><th>Public Exploit</th>"
                    "<th>NVD Summary</th><th>Source</th>"
                    "</tr></thead><tbody>")
        for c in top_sorted[:250]:
            e = exp.get(c, {}) or {}
            epss = e.get("epss")
            kev = "Yes" if e.get("cisa_kev") else "No"
            pe = "Yes" if e.get("public_exploit_evidence") else "No"

            nvd_item = nvd_by_cve.get(c) or {}
            cvss_txt = _cvss_text(nvd_item)
            desc = (nvd_item.get("description") or "")
            source = "Shodan"
            if nvd_item.get("derived_from_cpe"):
                source = "NVD (CPE-derived)"

            html.append("<tr>")
            html.append(f"<td><b>{html_escape(c)}</b></td>")
            html.append(f"<td>{html_escape(cvss_txt)}</td>")
            html.append(f"<td>{badge(e.get('severity') or 'Info')}</td>")
            html.append(f"<td>{html_escape(str(e.get('risk_score',0)))}</td>")
            html.append(f"<td>{html_escape('' if epss is None else f'{epss:.4f}')}</td>")
            html.append(f"<td>{kev}</td>")
            html.append(f"<td>{pe}</td>")
            html.append(f"<td class='small'>{html_escape(desc[:260])}</td>")
            html.append(f"<td class='small'>{html_escape(source)}</td>")
            html.append("</tr>")
        html.append("</tbody></table>")
    html.append("</div>")

    
    html.append("<div class='card' style='margin-top:14px'><h2>Observed Services (Shodan)</h2>")
    if services:
        html.append("<table><thead><tr><th>Port</th><th>Transport</th><th>Product</th><th>Version</th><th>CPE</th><th>Banner</th></tr></thead><tbody>")
        for s in services[:40]:
            cpe = s.get("cpe") or []
            if isinstance(cpe, list):
                cpe_txt = ", ".join([x for x in cpe if isinstance(x, str)])[:140]
            else:
                cpe_txt = str(cpe)[:140]
            html.append("<tr>")
            html.append(f"<td>{html_escape(str(s.get('port','')))}</td>")
            html.append(f"<td>{html_escape(str(s.get('transport','')))}</td>")
            html.append(f"<td>{html_escape(str(s.get('product','')))}</td>")
            html.append(f"<td>{html_escape(str(s.get('version','')))}</td>")
            html.append(f"<td class='small'>{html_escape(cpe_txt)}</td>")
            html.append(f"<td>{html_escape(str(s.get('banner_sample','')))}</td>")
            html.append("</tr>")
        html.append("</tbody></table>")
    else:
        html.append("<div class='small'>No service banners returned (missing key or no data).</div>")
    html.append("</div>")

    html.append("<div class='card' style='margin-top:14px'><h2>ZoomEye Findings (Summary)</h2>")
    if zm_hits:
        html.append("<table><thead><tr><th>IP</th><th>Port</th><th>Service</th><th>App</th><th>Banner</th></tr></thead><tbody>")
        for z in zm_hits[:30]:
            html.append("<tr>")
            html.append(f"<td>{html_escape(str(z.get('ip','')))}</td>")
            html.append(f"<td>{html_escape(str(z.get('port','')))}</td>")
            html.append(f"<td>{html_escape(str(z.get('service','')))}</td>")
            html.append(f"<td>{html_escape(str(z.get('app','')))}</td>")
            html.append(f"<td>{html_escape(str(z.get('banner_sample','')))}</td>")
            html.append("</tr>")
        html.append("</tbody></table>")
    else:
        html.append("<div class='small'>No ZoomEye results (missing key / blocked / no hits).</div>")
    html.append("</div>")

    
    html.append("<div class='card' style='margin-top:14px'><h2>Web-Check Output (Full, Separate)</h2>")
    html.append("<div class='small'>Included as-is for auditability.</div>")
    html.append("<pre>")
    html.append(html_escape(json.dumps(webcheck, indent=2)[:160000]))
    html.append("</pre></div>")

    html.append("<div class='footer'>Notes: NVD enrichment is CPE-based and may include inferred CVEs matching what Shodan web UI shows.</div>")
    html.append("</div></body></html>")
    return "".join(html)
