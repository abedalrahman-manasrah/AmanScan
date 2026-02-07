
from __future__ import annotations

from typing import Any, Dict, List, Set, Optional
import requests

SHODAN_BASE = "https://api.shodan.io"
INTERNETDB_BASE = "https://internetdb.shodan.io"


def _safe_text(r: requests.Response, limit: int = 800) -> str:
    try:
        t = r.text or ""
    except Exception:
        t = ""
    t = t.strip()
    return t[:limit] + ("..." if len(t) > limit else "")


def shodan_api_info(api_key: str, timeout: int = 12) -> Dict[str, Any]:
    api_key = (api_key or "").strip()
    if not api_key:
        return {"_error": "missing_shodan_key"}

    url = f"{SHODAN_BASE}/api-info"
    try:
        r = requests.get(url, params={"key": api_key}, timeout=timeout)
        if r.status_code != 200:
            return {"_error": f"http_{r.status_code}", "_body": _safe_text(r), "_url": r.url}
        return r.json() or {}
    except Exception as e:
        return {"_error": str(e)}


def shodan_host_lookup(ip: str, api_key: str, timeout: int = 18) -> Dict[str, Any]:
    ip = (ip or "").strip()
    api_key = (api_key or "").strip()
    if not ip:
        return {"_error": "missing_ip"}
    if not api_key:
        return {"_error": "missing_shodan_key"}

    url = f"{SHODAN_BASE}/shodan/host/{ip}"
    try:
        r = requests.get(url, params={"key": api_key}, timeout=timeout)
        if r.status_code != 200:
            return {"_error": f"http_{r.status_code}", "_body": _safe_text(r), "_url": r.url}
        return r.json() or {}
    except Exception as e:
        return {"_error": str(e)}


def shodan_search_ips(query: str, api_key: str, limit: int = 50, timeout: int = 20) -> Dict[str, Any]:
   
    api_key = (api_key or "").strip()
    query = (query or "").strip()
    if not api_key:
        return {"_error": "missing_shodan_key"}
    if not query:
        return {"_error": "missing_query"}

    url = f"{SHODAN_BASE}/shodan/host/search"
    ips: Set[str] = set()

    try:
        r = requests.get(url, params={"key": api_key, "query": query, "page": 1}, timeout=timeout)
        if r.status_code != 200:
            return {"_error": f"http_{r.status_code}", "_body": _safe_text(r), "_url": r.url, "query": query}

        j = r.json() or {}
        matches = j.get("matches") or []
        for m in matches:
            if isinstance(m, dict):
                ip = m.get("ip_str") or m.get("ip")
                if isinstance(ip, str) and ip.strip():
                    ips.add(ip.strip())

        return {"ips": sorted(ips)[:limit], "total": j.get("total"), "query": query}
    except Exception as e:
        return {"_error": str(e), "query": query}


def internetdb_lookup(ip: str, timeout: int = 12) -> Dict[str, Any]:
   
    ip = (ip or "").strip()
    if not ip:
        return {"_error": "missing_ip"}

    url = f"{INTERNETDB_BASE}/{ip}"
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return {"_error": f"http_{r.status_code}", "_body": _safe_text(r), "_url": r.url}
        data = r.json() or {}
        if not isinstance(data, dict):
            return {"_error": "unexpected_json", "_url": r.url}
        return data
    except Exception as e:
        return {"_error": str(e)}


def extract_cves(shodan_raw: Dict[str, Any]) -> List[str]:
   
    out: Set[str] = set()
    vulns = (shodan_raw or {}).get("vulns") or {}
    if isinstance(vulns, dict):
        for k in vulns.keys():
            if isinstance(k, str) and k.upper().startswith("CVE-"):
                out.add(k.upper())
    elif isinstance(vulns, list):
        for k in vulns:
            if isinstance(k, str) and k.upper().startswith("CVE-"):
                out.add(k.upper())
    return sorted(out)


def summarize_services(shodan_raw: Dict[str, Any]) -> List[Dict[str, Any]]:
  
    data = (shodan_raw or {}).get("data") or []
    services: List[Dict[str, Any]] = []
    if not isinstance(data, list):
        return services

    for item in data[:80]:
        if not isinstance(item, dict):
            continue
        port = item.get("port")
        transport = item.get("transport")
        product = item.get("product") or ""
        version = item.get("version") or ""
        cpe = item.get("cpe") or []
        banner = item.get("data") or ""
        services.append({
            "port": port,
            "transport": transport,
            "product": product,
            "version": version,
            "cpe": cpe,
            "banner_sample": (banner[:220] if isinstance(banner, str) else "")
        })
    return services


def summarize_services_from_internetdb(ip: str, idb: Dict[str, Any]) -> List[Dict[str, Any]]:
   
    services: List[Dict[str, Any]] = []
    ports = (idb or {}).get("ports") or []
    cpes = (idb or {}).get("cpes") or []

    if not isinstance(ports, list):
        ports = []
    if not isinstance(cpes, list):
        cpes = []

    cpe_list = [c for c in cpes if isinstance(c, str)]
    cpe_sample = cpe_list[:8]

    for p in ports[:80]:
        if isinstance(p, int):
            services.append({
                "port": p,
                "transport": "tcp",
                "product": "",
                "version": "",
                "cpe": cpe_sample,
                "banner_sample": f"InternetDB:{ip}"
            })
    return services
