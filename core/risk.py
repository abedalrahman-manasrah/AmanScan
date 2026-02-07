
from __future__ import annotations
from typing import Any, Dict, List, Tuple, Optional

SENSITIVE_PORTS = {22, 23, 3389, 3306, 5432, 6379, 9200, 27017}

def confidence_for_cve(cve: str, exp: Dict[str, Any], nvd: Dict[str, Any]) -> str:
  
    kev = bool(exp.get("cisa_kev"))
    public = bool(exp.get("public_exploit_evidence"))
    epss = exp.get("epss") or 0.0
    cvss = ((nvd.get("cvss") or {}).get("baseScore") or 0.0) if nvd else 0.0

    evidence_count = 0
    if exp.get("exploitdb_searchsploit"): evidence_count += 1
    if exp.get("github_poc") is True: evidence_count += 1
    sh = exp.get("shodan_exploits") or {}
    if (sh.get("available") == "yes"): evidence_count += 1

    if kev or evidence_count >= 2:
        return "High"
    if public or (cvss >= 7.0 and epss >= 0.1):
        return "Medium"
    return "Low"

def profile_services(services: List[Dict[str, Any]], zoomeye_hits: List[Dict[str, Any]]) -> Dict[str, Any]:
    
    ports = set()
    banners = []
    for s in (services or []):
        p = s.get("port")
        if isinstance(p, int): ports.add(p)
        elif isinstance(p, str) and p.isdigit(): ports.add(int(p))
        if s.get("product"): banners.append(str(s.get("product")))
    for z in (zoomeye_hits or []):
        p = z.get("port")
        if isinstance(p, int): ports.add(p)
        elif isinstance(p, str) and p.isdigit(): ports.add(int(p))
        if z.get("app"): banners.append(str(z.get("app")))

    profiles = {
        "web": False,
        "remote_access": False,
        "databases": False,
        "email_dns": False,
        "admin_panels": False,
        "sensitive_ports_present": False,
        "sensitive_ports": []
    }

    if any(p in {80, 443, 8080, 8443} for p in ports):
        profiles["web"] = True
    if any(p in {22, 23, 3389, 5900, 1194, 51820} for p in ports):
        profiles["remote_access"] = True
    if any(p in {3306, 5432, 27017, 6379, 9200, 1433, 1521} for p in ports):
        profiles["databases"] = True
    if any(p in {25, 53, 110, 143, 465, 587, 993, 995} for p in ports):
        profiles["email_dns"] = True


    admin_words = ("admin", "panel", "dashboard", "phpmyadmin", "grafana", "jenkins")
    if any(any(w in (b or "").lower() for w in admin_words) for b in banners):
        profiles["admin_panels"] = True

    sens = sorted([p for p in ports if p in SENSITIVE_PORTS])
    profiles["sensitive_ports_present"] = bool(sens)
    profiles["sensitive_ports"] = sens
    profiles["ports_total"] = len(ports)
    return profiles

def remediation_playbooks(profiles: Dict[str, Any]) -> List[Dict[str, Any]]:
   
    out: List[Dict[str, Any]] = []

    if profiles.get("remote_access"):
        out.append({
            "title": "Remote Access Hardening",
            "items": [
                "Restrict administrative access by IP allowlist/VPN.",
                "Enforce MFA for remote admin accounts.",
                "Disable legacy protocols and weak authentication methods.",
                "Enable brute-force protections and account lockout policies.",
                "Centralize logs and monitor authentication anomalies."
            ]
        })

    if profiles.get("web"):
        out.append({
            "title": "Web Server Hardening",
            "items": [
                "Apply security updates for the web stack promptly.",
                "Enable HSTS where appropriate and ensure HTTPS-only access.",
                "Implement security headers (CSP, X-Frame-Options, etc.) where applicable.",
                "Use WAF / rate limiting to reduce abuse and scanning impact.",
                "Review exposed endpoints and remove unused services."
            ]
        })

    if profiles.get("databases"):
        out.append({
            "title": "Database Exposure Reduction",
            "items": [
                "Remove direct internet exposure; place databases behind private networks.",
                "Enforce strong authentication and least privilege.",
                "Rotate credentials and review access lists regularly.",
                "Enable backups and test restore procedures.",
                "Encrypt data at rest and in transit."
            ]
        })

    if profiles.get("email_dns"):
        out.append({
            "title": "DNS / Email Hygiene",
            "items": [
                "Harden DNS configuration and review zone exposure.",
                "Implement SPF/DKIM/DMARC for email domains.",
                "Monitor DNS changes and unauthorized records.",
                "Keep mail server software patched and restrict admin access."
            ]
        })


    out.append({
        "title": "Baseline Security Controls",
        "items": [
            "Maintain an asset inventory and patch cadence.",
            "Use backups, segmentation, and least privilege access.",
            "Set incident response contacts and escalation workflow.",
            "Review firewall rules and close unnecessary ports."
        ]
    })

    return out

def risk_score(
    cvss_base: Optional[float],
    epss: Optional[float],
    exposure_hint_0_15: int,
    kev: bool,
    public_exploit: bool
) -> int:
   
    impact = float(cvss_base or 0.0)
    likelihood = float(epss or 0.0)
    exposure = max(0.0, min(1.0, float(exposure_hint_0_15) / 15.0))

    base = (impact / 10.0) * likelihood * exposure * 100.0


    if public_exploit:
        base += 8.0
    if kev:
        base += 20.0


    if base < 0: base = 0
    if base > 100: base = 100
    return int(round(base))

def severity_from_score(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 15:
        return "Low"
    return "Info"
