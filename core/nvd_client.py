
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import time
import requests

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_CACHE_TTL_SEC = 60 * 60 * 8  # 8 hours


def _now() -> float:
    return time.time()


def _safe_text(r: requests.Response, n: int = 2500) -> str:
    try:
        return (r.text or "")[:n]
    except Exception:
        return ""


def cpe_uri_to_cpe23(cpe: str) -> Optional[str]:
  
    if not cpe:
        return None
    cpe = cpe.strip()
    if cpe.startswith("cpe:2.3:"):
        return cpe

    
    if cpe.startswith("cpe:/"):
        
        body = cpe[len("cpe:/"):] 
        parts = body.split(":")
        if len(parts) < 3:
            return None

        part = parts[0]  # a/o/h
        vendor = parts[1] if len(parts) > 1 else "*"
        product = parts[2] if len(parts) > 2 else "*"
        version = parts[3] if len(parts) > 3 else "*"

        
        return f"cpe:2.3:{_norm(part)}:{_norm(vendor)}:{_norm(product)}:{_norm(version)}:*:*:*:*:*:*:*"

    
    if cpe.startswith("cpe:") and not cpe.startswith("cpe:2.3:"):
        
        return None

    return None


def _norm(x: str) -> str:
    x = (x or "").strip()
    if not x:
        return "*"
    
    return x.replace(" ", "_")


def nvd_query_by_cpe(
    cpe23: str,
    api_key: str = "",
    timeout: int = 18,
    max_results: int = 200
) -> Dict[str, Any]:
    
    cpe23 = (cpe23 or "").strip()
    if not cpe23.startswith("cpe:2.3:"):
        return {"_error": "invalid_cpe23", "_cpe": cpe23}

   
    cached = _CACHE.get(cpe23)
    if cached:
        ts, data = cached
        if _now() - ts <= _CACHE_TTL_SEC:
            return data

    headers = {"Accept": "application/json", "User-Agent": "AmanScan/2.0"}
    if api_key:
        headers["apiKey"] = api_key.strip()

    params = {
        "cpeName": cpe23,
        "resultsPerPage": int(max_results),
        "startIndex": 0,
    }

    try:
        r = requests.get(NVD_BASE, headers=headers, params=params, timeout=timeout)
        if r.status_code != 200:
            return {"_error": f"http_{r.status_code}", "_url": r.url, "_body": _safe_text(r)}
        data = r.json() or {}
        if not isinstance(data, dict):
            data = {"data": data}
        
        _CACHE[cpe23] = (_now(), data)
        return data
    except Exception as e:
        return {"_error": str(e), "_cpe": cpe23}


def parse_nvd_cves(raw: Dict[str, Any], limit: int = 200) -> List[Dict[str, Any]]:
   
    out: List[Dict[str, Any]] = []
    vulns = raw.get("vulnerabilities")
    if not isinstance(vulns, list):
        return out

    for v in vulns[:limit]:
        cve_obj = (v or {}).get("cve") if isinstance(v, dict) else None
        if not isinstance(cve_obj, dict):
            continue

        cve_id = cve_obj.get("id") or ""
        if not cve_id.startswith("CVE-"):
            continue

        desc = ""
        descs = cve_obj.get("descriptions")
        if isinstance(descs, list):
            
            en = next((d.get("value") for d in descs if isinstance(d, dict) and d.get("lang") == "en"), None)
            desc = en or next((d.get("value") for d in descs if isinstance(d, dict) and d.get("value")), "") or ""

       
        cvss = _extract_cvss(cve_obj)

        weaknesses = []
        w = cve_obj.get("weaknesses")
        if isinstance(w, list):
            for ww in w:
                if not isinstance(ww, dict):
                    continue
                desc_list = ww.get("description")
                if isinstance(desc_list, list):
                    for d in desc_list:
                        if isinstance(d, dict) and (d.get("value") or "").startswith("CWE-"):
                            weaknesses.append(d["value"])

        refs = []
        rr = cve_obj.get("references")
        if isinstance(rr, list):
            for r in rr:
                if isinstance(r, dict) and r.get("url"):
                    refs.append(r["url"])

        out.append({
            "cve": cve_id,
            "description": desc,
            "cvss": cvss,
            "weaknesses": sorted(set(weaknesses)),
            "references": refs[:20],
        })

    return out


def _extract_cvss(cve_obj: Dict[str, Any]) -> Dict[str, Any]:
    metrics = cve_obj.get("metrics") if isinstance(cve_obj.get("metrics"), dict) else {}
    
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if isinstance(arr, list) and arr:
            first = arr[0]
            if not isinstance(first, dict):
                continue
            cvss_data = first.get("cvssData") if isinstance(first.get("cvssData"), dict) else {}
            base = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            sev = first.get("baseSeverity") or cvss_data.get("baseSeverity")
            return {
                "version": key.replace("cvssMetric", "v").replace("V", "."),
                "baseScore": base,
                "severity": sev,
                "vector": vector,
            }
    return {}
