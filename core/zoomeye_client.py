
from __future__ import annotations

from typing import Any, Dict, List
import time
import requests



ZOOMEYE_SEARCH_URL = "https://api.zoomeye.ai/v2/search"
ZOOMEYE_USER_AGENT = "AmanScan/1.0 (+https://local.amanscan)"



def _safe_text(r: requests.Response, limit: int = 900) -> str:
    try:
        t = r.text or ""
    except Exception:
        t = ""
    t = t.strip()
    return t[:limit] + ("..." if len(t) > limit else "")


def _looks_like_html(s: str) -> bool:
    s = (s or "").lstrip().lower()
    return (
        s.startswith("<!doctype html")
        or s.startswith("<html")
        or "<head" in s[:200]
        or "jiasule" in s[:400]
    )


def _build_headers(token_or_key: str, mode: str) -> Dict[str, str]:
  
    headers = {
        "User-Agent": ZOOMEYE_USER_AGENT,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    val = (token_or_key or "").strip()
    if not val:
        return headers

    if mode == "jwt":
        headers["Authorization"] = f"JWT {val}"
    elif mode == "bearer":
        headers["Authorization"] = f"Bearer {val}"
    elif mode == "apikey":
        headers["API-KEY"] = val
    elif mode == "key":
        headers["key"] = val

    return headers



def zoomeye_search(query: str, token_or_key: str, page: int = 1, timeout: int = 18) -> Dict[str, Any]:
  
    query = (query or "").strip()
    token_or_key = (token_or_key or "").strip()

    if not token_or_key:
        return {"_error": "missing_zoomeye_key_or_token"}
    if not query:
        return {"_error": "missing_query"}

    payload = {"q": query, "page": int(page or 1)}
    auth_modes = ["jwt", "apikey", "bearer", "key"]

    last_error: Dict[str, Any] = {}

    for mode in auth_modes:
        headers = _build_headers(token_or_key, mode)
        try:
            r = requests.post(
                ZOOMEYE_SEARCH_URL,
                json=payload,
                headers=headers,
                timeout=timeout,
            )

            
            if r.status_code == 200:
                body_preview = _safe_text(r, 300)
                if _looks_like_html(body_preview):
                    return {
                        "_error": "html_block",
                        "_hint": "ZoomEye returned HTML page (WAF/CDN challenge).",
                        "mode": mode,
                        "url": r.url,
                        "body": body_preview,
                    }

                try:
                    data = r.json()
                except Exception:
                    return {
                        "_error": "invalid_json",
                        "mode": mode,
                        "url": r.url,
                        "body": _safe_text(r),
                    }

                return data if isinstance(data, dict) else {"data": data}

            
            if r.status_code in (401, 403):
                body = _safe_text(r)
                last_error = {
                    "_error": f"http_{r.status_code}",
                    "mode": mode,
                    "url": r.url,
                    "body": body,
                    "html_block": _looks_like_html(body),
                }
                time.sleep(0.2)
                continue

            
            last_error = {
                "_error": f"http_{r.status_code}",
                "mode": mode,
                "url": r.url,
                "body": _safe_text(r),
            }

        except Exception as e:
            last_error = {"_error": f"exception:{e}", "mode": mode}

        time.sleep(0.15)

    if last_error.get("html_block"):
        last_error["_hint"] = (
            "ZoomEye WAF/CDN block detected. "
            "Use a valid JWT token, ensure your plan allows API access, "
            "or try from another network."
        )

    return last_error or {"_error": "unknown_error"}


def zoomeye_search_ip(ip: str, token_or_key: str, page: int = 1, timeout: int = 18) -> Dict[str, Any]:
    ip = (ip or "").strip()
    if not ip:
        return {"_error": "missing_ip"}
    return zoomeye_search(f'ip:"{ip}"', token_or_key, page=page, timeout=timeout)



def summarize_zoomeye(raw: Dict[str, Any], limit: int = 50) -> List[Dict[str, Any]]:
    matches = raw.get("data") or raw.get("matches") or []
    if not isinstance(matches, list):
        return []

    out: List[Dict[str, Any]] = []

    for m in matches[:limit]:
        if not isinstance(m, dict):
            continue

        ip = m.get("ip") or m.get("ipaddr") or m.get("ip_str")
        port = None
        service = ""
        banner = ""

        pi = m.get("portinfo") or {}
        if isinstance(pi, dict):
            port = pi.get("port")
            service = pi.get("service") or pi.get("app") or ""
            banner = pi.get("banner") or pi.get("title") or ""
        else:
            port = m.get("port")
            service = m.get("service") or ""
            banner = m.get("banner") or ""

        out.append({
            "ip": ip,
            "port": port,
            "service": service,
            "banner_sample": banner[:220] if isinstance(banner, str) else "",
            "source": "zoomeye",
        })

    return out



class ZoomEye:
 

    def __init__(self, api_key: str):
        self.api_key = (api_key or "").strip()

    def search_ip(self, ip: str, page: int = 1, timeout: int = 18, **kwargs) -> Dict[str, Any]:
      
        return zoomeye_search_ip(ip, self.api_key, page=page, timeout=timeout)

    def search(self, query: str, page: int = 1, timeout: int = 18, **kwargs) -> Dict[str, Any]:
        return zoomeye_search(query, self.api_key, page=page, timeout=timeout)

    @staticmethod
    def summarize(raw: Dict[str, Any], limit: int = 50) -> List[Dict[str, Any]]:
        return summarize_zoomeye(raw, limit=limit)
