from typing import Dict, Any, Optional, Tuple
import time
import requests


EPSS_API = "https://api.first.org/data/v1/epss"  


class EPSSCache:
    def __init__(self, ttl_seconds: int = 6 * 3600):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    def get(self, cve: str) -> Optional[Dict[str, Any]]:
        cve = (cve or "").upper().strip()
        if not cve:
            return None
        item = self._cache.get(cve)
        if not item:
            return None
        ts, data = item
        if time.time() - ts > self.ttl:
            return None
        return data

    def set(self, cve: str, data: Dict[str, Any]) -> None:
        cve = (cve or "").upper().strip()
        if not cve:
            return
        self._cache[cve] = (time.time(), data)


_epss_cache = EPSSCache()


def fetch_epss(cve: str, timeout: int = 12) -> Dict[str, Any]:
  
    cve = (cve or "").upper().strip()
    if not cve:
        return {"epss": None, "percentile": None, "date": None, "_error": "missing_cve"}

    cached = _epss_cache.get(cve)
    if cached:
        return cached

    try:
        r = requests.get(EPSS_API, params={"cve": cve}, timeout=timeout)
        if r.status_code != 200:
            data = {"epss": None, "percentile": None, "date": None, "_error": f"http_{r.status_code}"}
            _epss_cache.set(cve, data)
            return data

        js = r.json() or {}
        arr = (js.get("data") or [])
        if not arr:
            data = {"epss": None, "percentile": None, "date": None, "_error": "no_data"}
            _epss_cache.set(cve, data)
            return data

        row = arr[0] or {}
       
        epss = row.get("epss")
        pct = row.get("percentile")
        date = row.get("date")

        try:
            epss_f = float(epss) if epss is not None else None
        except Exception:
            epss_f = None
        try:
            pct_f = float(pct) if pct is not None else None
        except Exception:
            pct_f = None

        data = {"epss": epss_f, "percentile": pct_f, "date": date, "_error": None}
        _epss_cache.set(cve, data)
        return data

    except Exception as e:
        data = {"epss": None, "percentile": None, "date": None, "_error": str(e)}
        _epss_cache.set(cve, data)
        return data
