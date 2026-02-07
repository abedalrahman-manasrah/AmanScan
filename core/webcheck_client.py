
import requests
from typing import Any, Dict, List

WEB_CHECK_ENDPOINTS: List[str] = [
    "dns", "headers", "cookies", "ports",
    "dnssec", "hsts", "linked-pages",
    "block-lists", "social-tags", "trace-route"
]

def run_webcheck(base_url: str, target_url: str, timeout: int = 25) -> Dict[str, Any]:
    base_url = (base_url or "").rstrip("/")

   
    if not base_url:
        return {"_skipped": True, "_reason": "webcheck_disabled"}

    out: Dict[str, Any] = {"_base": base_url}
    for ep in WEB_CHECK_ENDPOINTS:
        url = f"{base_url}/api/{ep}"
        try:
            r = requests.get(url, params={"url": target_url}, timeout=timeout)
            content_type = (r.headers.get("content-type") or "").lower()
            payload = r.json() if content_type.startswith("application/json") else (r.text or "")
            out[ep] = {"status": r.status_code, "data": payload}
        except requests.exceptions.ConnectionError as e:
          
            out["_error"] = "webcheck_connection_refused"
            out["_detail"] = str(e)
            break
        except Exception as e:
            out[ep] = {"_error": str(e)}
    return out
