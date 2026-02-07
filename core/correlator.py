
from __future__ import annotations

from typing import Any, Dict, Optional, Callable, List
import re
import socket
from datetime import datetime

from config.config_manager import AppConfig
from core.webcheck_client import run_webcheck

from core.shodan_client import (
    shodan_host_lookup,
    shodan_search_ips,
    internetdb_lookup,
    extract_cves,
    summarize_services,
    summarize_services_from_internetdb,
)

from core.zoomeye_client import zoomeye_search_ip, summarize_zoomeye
from core.exploit_intel import kev_catalog, build_exploit_intel


from core.nvd_client import nvd_query_by_cpe, parse_nvd_cves, cpe_uri_to_cpe23

from core.risk import (
    risk_score,
    severity_from_score,
    confidence_for_cve,
    profile_services,
)
from core.telemetry import log_scan_summary


from ai.analyzer import analyze_with_openai


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_target(t: str) -> str:
    t = (t or "").strip()
    if not t:
        return t
    if not re.match(r"^[a-zA-Z]+://", t):
        t = "https://" + t
    return t


def host_from_url(url: str) -> str:
    url = (url or "").strip()
    url = re.sub(r"^[a-zA-Z]+://", "", url)
    url = url.split("/")[0]
    url = url.split("@")[-1]
    url = url.split(":")[0]
    return url.strip()


def is_ip(s: str) -> bool:
    try:
        socket.inet_aton(s)
        return True
    except Exception:
        return False


def resolve_ip(host: str) -> Optional[str]:
    host = (host or "").strip()
    if not host:
        return None
    if is_ip(host):
        return host
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _exposure_hint(services: List[Dict[str, Any]], zm_hits: List[Dict[str, Any]]) -> int:
   
    score = 0
    ports = set()

    for s in (services or [])[:120]:
        try:
            p = int(s.get("port") or 0)
            if p:
                ports.add(p)
        except Exception:
            pass

    for z in (zm_hits or [])[:80]:
        try:
            p = int(z.get("port") or 0)
            if p:
                ports.add(p)
        except Exception:
            pass

    # Remote access
    if 22 in ports or 3389 in ports:
        score += 4

    # Databases / data stores
    if 3306 in ports or 5432 in ports or 27017 in ports or 6379 in ports:
        score += 5

    # Elasticsearch
    if 9200 in ports:
        score += 4

    # Web
    if 80 in ports or 443 in ports:
        score += 2

    # Broad exposure
    if len(ports) >= 10:
        score += 3

    return max(0, min(15, score))


def _collect_raw_cpes_from_services(services: List[Dict[str, Any]]) -> List[str]:
    
    out: List[str] = []
    for s in (services or [])[:160]:
        cpe = s.get("cpe") or []
        if isinstance(cpe, list):
            for x in cpe:
                if isinstance(x, str) and x.strip():
                    out.append(x.strip())
        elif isinstance(cpe, str) and cpe.strip():
            out.append(cpe.strip())
    return out


def run_full_scan(cfg: AppConfig, target: str, progress_cb: Optional[Callable[[int, str], None]] = None) -> Dict[str, Any]:
    def step(p: int, msg: str):
        if progress_cb:
            progress_cb(p, msg)

    target_url = normalize_target(target)
    host = host_from_url(target_url)
    ip = resolve_ip(host)

    result: Dict[str, Any] = {
        "tool": "AmanScan",
        "generated_at": now_str(),
        "target_url": target_url,
        "host": host,
        "ip": ip,

        "services": [],
        "zoomeye_hits": [],
        "cves": [],

        "profiles": {},
        "webcheck_raw": {},

        "shodan_raw": {},
        "shodan_search": {},
        "shodan_internetdb": [],

        "zoomeye_raw": {},

        "nvd": {
            "cpe_used": [],
            "by_cve": {},
            "errors": [],

            "cpe_convert_debug": [],
        },

        "exploit_intel": {},
        "ai_analysis": {},

        "risk_summary": {},
    }

    step(5, "Resolving target")
    if not ip:
        result["error"] = "could_not_resolve_ip"
        step(100, "Failed: could not resolve IP")
        return result


    if getattr(cfg, "enable_webcheck", True):
        step(15, "Running Web-Check API")
        result["webcheck_raw"] = run_webcheck(cfg.webcheck_base_url, target_url)


    services_acc: List[Dict[str, Any]] = []
    cves_acc: set = set()

    if getattr(cfg, "enable_shodan", True) and (cfg.shodan_api_key or "").strip():
        step(30, "Shodan: discovering related IPs (search)")
        ips: List[str] = [ip]


        if host and not is_ip(host):
            q = f'hostname:"{host}"'
            sr = shodan_search_ips(q, cfg.shodan_api_key, limit=50)
            result["shodan_search"] = sr
            if not sr.get("_error") and sr.get("ips"):
                ips = sr["ips"]


        step(40, "Shodan: InternetDB enrichment")
        idb_results = []
        for ipx in ips[:25]:
            idb = internetdb_lookup(ipx)
            idb_results.append({"ip": ipx, "internetdb": idb})

            vulns = (idb or {}).get("vulns") or []
            if isinstance(vulns, list):
                for v in vulns:
                    if isinstance(v, str) and v.upper().startswith("CVE-"):
                        cves_acc.add(v.upper())

            services_acc.extend(summarize_services_from_internetdb(ipx, idb))

        result["shodan_internetdb"] = idb_results


        step(48, "Shodan: host lookup (best-effort)")
        shodan = shodan_host_lookup(ip, cfg.shodan_api_key)
        result["shodan_raw"] = shodan
        if not shodan.get("_error"):
            sh_services = summarize_services(shodan)
            services_acc = sh_services + services_acc
            for c in extract_cves(shodan):
                cves_acc.add(c)
    else:
        result["shodan_raw"] = {"_error": "missing_or_disabled_shodan"}


    seen = set()
    uniq_services = []
    for s in services_acc:
        key = (s.get("port"), s.get("transport"), s.get("banner_sample"))
        if key in seen:
            continue
        seen.add(key)
        uniq_services.append(s)

    result["services"] = uniq_services[:140]
    result["cves"] = sorted(cves_acc)


    if getattr(cfg, "enable_zoomeye", True) and (cfg.zoomeye_api_key or "").strip():
        step(60, "Querying ZoomEye")
        zoomeye = zoomeye_search_ip(ip, cfg.zoomeye_api_key)
        result["zoomeye_raw"] = zoomeye
        if not zoomeye.get("_error"):
            result["zoomeye_hits"] = summarize_zoomeye(zoomeye)
    else:
        result["zoomeye_raw"] = {"_error": "missing_or_disabled_zoomeye"}


    result["profiles"] = profile_services(result.get("services") or [], result.get("zoomeye_hits") or [])
    exposure = _exposure_hint(result.get("services") or [], result.get("zoomeye_hits") or [])
    result["risk_summary"]["exposure_hint_0_15"] = exposure


    if getattr(cfg, "enable_nvd", True):
        step(70, "NVD enrichment (CPE 2.3)")

        raw_cpes = _collect_raw_cpes_from_services(result.get("services") or [])

        cpe23_list: List[str] = []
        conv_debug: List[Dict[str, Any]] = []

        for rc in raw_cpes:
            c23 = cpe_uri_to_cpe23(rc)
            ok = bool(c23 and isinstance(c23, str) and c23.startswith("cpe:2.3:"))
            conv_debug.append({"raw": rc, "cpe23": c23 if ok else None})
            if ok:
                cpe23_list.append(c23)


        cpe23_list = sorted(set(cpe23_list))[:25]
        result["nvd"]["cpe_used"] = cpe23_list
        result["nvd"]["cpe_convert_debug"] = conv_debug[:40]

        nvd_by_cve: Dict[str, Any] = {}
        derived_from: Dict[str, List[str]] = {}

        for idx, cpe23 in enumerate(cpe23_list, start=1):
            step(70 + int(idx / max(1, len(cpe23_list)) * 10), f"NVD: {idx}/{len(cpe23_list)}")
            raw = nvd_query_by_cpe(cpe23, api_key=(getattr(cfg, "nvd_api_key", "") or ""))

            if raw.get("_error"):
                result["nvd"]["errors"].append({
                    "cpe": cpe23,
                    "error": raw.get("_error"),
                    "url": raw.get("_url"),
                    "body": raw.get("_body"),
                })
                continue

            parsed = parse_nvd_cves(raw, limit=200)
            for item in parsed:
                cve_id = item.get("cve")
                if not cve_id:
                    continue

                if cve_id not in nvd_by_cve:
                    nvd_by_cve[cve_id] = {
                        "cvss": item.get("cvss") or {},
                        "description": item.get("description") or "",
                        "weaknesses": item.get("weaknesses") or [],
                        "references": item.get("references") or [],
                        "derived_from_cpe": True,
                    }
                derived_from.setdefault(cve_id, []).append(cpe23)

        for cve_id, lst in derived_from.items():
            if cve_id in nvd_by_cve:
                nvd_by_cve[cve_id]["cpe_sources"] = sorted(set(lst))[:10]

        result["nvd"]["by_cve"] = nvd_by_cve

        merged = set(result.get("cves") or [])
        merged.update(nvd_by_cve.keys())
        result["cves"] = sorted(merged)


    step(82, "Loading KEV catalog")
    kev_json = kev_catalog()

    step(88, "Exploit intelligence + scoring")
    exp_map: Dict[str, Any] = {}
    nvd_by_cve = (result.get("nvd") or {}).get("by_cve") or {}
    cves = (result.get("cves") or [])[:140]

    for cve in cves:
        intel = build_exploit_intel(
            cve,
            shodan_api_key=cfg.shodan_api_key,
            github_token=cfg.github_token,
            kev_json=kev_json,
            metasploit_path=getattr(cfg, "metasploit_path", None),
            exposure_hint=exposure,
        )

        nvd_item = nvd_by_cve.get(cve) or {}
        cvss = float(((nvd_item.get("cvss") or {}).get("baseScore") or 0.0))
        epss = intel.get("epss")
        kev = bool(intel.get("cisa_kev"))
        public = bool(intel.get("public_exploit_evidence"))

        score = risk_score(cvss, epss, exposure, kev, public)
        sev = severity_from_score(score)
        conf = confidence_for_cve(cve, intel, nvd_item)

        intel["risk_score"] = score
        intel["severity"] = sev
        intel["confidence"] = conf

        exp_map[cve] = intel

    result["exploit_intel"] = exp_map


    severities = [exp_map[c].get("severity") for c in cves if exp_map.get(c)]
    counts = {
        "Critical": sum(1 for s in severities if s == "Critical"),
        "High": sum(1 for s in severities if s == "High"),
        "Medium": sum(1 for s in severities if s == "Medium"),
        "Low": sum(1 for s in severities if s == "Low"),
        "Info": sum(1 for s in severities if s == "Info"),
    }
    result["risk_summary"]["counts"] = counts

    top_score = 0
    if cves:
        top_score = max(int(exp_map[c].get("risk_score") or 0) for c in cves if exp_map.get(c))
    result["risk_summary"]["overall_risk_0_100"] = top_score


    step(94, "AI analysis (post-scan)")
    if getattr(cfg, "enable_ai", True) and (cfg.openai_api_key or "").strip():
        try:
            ai = analyze_with_openai(cfg.openai_api_key, result, model=(cfg.openai_model or "gpt-5"))
            result["ai_analysis"] = ai
        except Exception as e:

            result["ai_analysis"] = {"_error": f"ai_error: {e}"}
    else:
        result["ai_analysis"] = {"_error": "missing_or_disabled_openai_key"}


    try:
        top_cvss = 0.0
        if nvd_by_cve:
            vals = []
            for c in cves:
                n = nvd_by_cve.get(c) or {}
                vals.append(float((n.get("cvss") or {}).get("baseScore") or 0.0))
            if vals:
                top_cvss = max(vals)

        kev_count = sum(1 for c in cves if bool((exp_map.get(c) or {}).get("cisa_kev")))
        summary = {
            "target": target,
            "host": host,
            "ip": ip,
            "exposure_hint": exposure,
            "risk_overall": top_score,
            "top_cvss": top_cvss,
            "kev_count": kev_count,
            **counts,
        }
        log_scan_summary(cfg.history_db_path, summary)
    except Exception:
        pass

    step(100, "Done")
    return result
