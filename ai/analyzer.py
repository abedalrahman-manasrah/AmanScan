
from typing import Any, Dict
import json

from openai import OpenAI


SYSTEM_INSTRUCTIONS_AR = """
أنت محلل أمن معلومات دفاعي (Blue Team).
التقرير مبني على فحص سلبي (OSINT) وقد يحتوي على False Positives.



المطلوب:
1) خلاصة تنفيذية غير تقنية.
2) ملخص المخاطر بالأرقام.
3) أخطر 10 مخاطر مع الدليل.
4) خطة معالجة .
5) كيف نتحقق بعد الإصلاح.
6) حدود الفحص.

اكتب بالعربية وبأسلوب مهني مختصر.
"""


def _safe_str(x: Any, limit: int = 600) -> str:
    try:
        if isinstance(x, (dict, list)):
            s = json.dumps(x, ensure_ascii=False)
        else:
            s = str(x)
    except Exception:
        s = str(x)
    s = (s or "").strip()
    return s[:limit] + ("..." if len(s) > limit else "")


def _normalize_webcheck(raw: Any) -> Dict[str, Any]:
    """
    يعالج:
    - dict نجاح
    - dict فشل (_error, _detail)
    - أو string
    بدون أي .get على string
    """
    if not isinstance(raw, dict):
        return {"type": str(type(raw)), "data": _safe_str(raw)}

    out = {}
    for k, v in raw.items():
        if isinstance(v, dict):
            out[k] = {
                "status": v.get("status"),
                "sample": _safe_str(v.get("data")),
            }
        else:
            out[k] = _safe_str(v)
    return out


def _compact_scan(scan: Dict[str, Any]) -> Dict[str, Any]:
    exploit = scan.get("exploit_intel") or {}
    nvd = scan.get("nvd") or {}
    nvd_by_cve = nvd.get("by_cve") or {}

    def risk(c):
        try:
            return int((exploit.get(c) or {}).get("risk_score") or 0)
        except Exception:
            return 0

    cves = sorted(scan.get("cves") or [], key=risk, reverse=True)[:20]

    top = {}
    for c in cves:
        e = exploit.get(c) or {}
        n = nvd_by_cve.get(c) or {}
        top[c] = {
            "risk": e.get("risk_score"),
            "severity": e.get("severity"),
            "epss": e.get("epss"),
            "kev": e.get("cisa_kev"),
            "public": e.get("public_exploit_evidence"),
            "cvss": (n.get("cvss") or {}).get("baseScore"),
        }

    return {
        "target": scan.get("target_url"),
        "ip": scan.get("ip"),
        "exposure": (scan.get("risk_summary") or {}).get("exposure_hint_0_15"),
        "overall_risk": (scan.get("risk_summary") or {}).get("overall_risk_0_100"),
        "counts": (scan.get("risk_summary") or {}).get("counts"),
        "services": (scan.get("services") or [])[:15],
        "top_cves": top,
        "webcheck": _normalize_webcheck(scan.get("webcheck_raw")),
    }


def analyze_with_openai(api_key: str, scan: Dict[str, Any], model: str = "gpt-5") -> Dict[str, Any]:
    if not api_key:
        return {"_error": "missing_openai_key"}

    client = OpenAI(api_key=api_key)
    payload = _compact_scan(scan)

    resp = client.responses.create(
        model=model,
        input=[
            {"role": "system", "content": SYSTEM_INSTRUCTIONS_AR},
            {
                "role": "user",
                "content": "حلّل التقرير التالي:\n"
                + json.dumps(payload, ensure_ascii=False, indent=2),
            },
        ],
        store=False,
    )

    text = getattr(resp, "output_text", "") or ""
    return {
        "model": model,
        "text_ar": text.strip()
    }
