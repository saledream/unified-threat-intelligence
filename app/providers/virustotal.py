"""VirusTotal passive reports with separate personal and commercial policies."""
import asyncio
import base64, os
import httpx

BASE = "https://www.virustotal.com/api/v3"

def _licensed() -> bool:
    return os.getenv("VIRUSTOTAL_COMMERCIAL_AUTHORIZED", "").lower() in {"1", "true", "yes"}

def usage_mode() -> str:
    return os.getenv("VIRUSTOTAL_USAGE_MODE", "commercial").strip().lower()


def authorized() -> bool:
    mode = usage_mode()
    return mode == "personal" or (mode == "commercial" and _licensed())


async def lookup(value: str, kind: str) -> dict:
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not authorized(): return {"status": "requires_authorization", "error": "Choose personal use explicitly, or authorize licensed commercial access"}
    if not key: return {"status": "not_configured"}
    if kind == "ip": path = f"ip_addresses/{value}"
    elif kind == "domain": path = f"domains/{value}"
    elif kind == "hash": path = f"files/{value}"
    elif kind == "url":
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip('='); path = f"urls/{url_id}"
    else: return {"status": "unsupported_indicator_type"}
    if usage_mode() == "personal":
        from app.services.virustotal_quota import reserve_public_request
        limited = await asyncio.to_thread(reserve_public_request, key)
        if limited:
            return limited
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(f"{BASE}/{path}", headers={"x-apikey": key, "Accept": "application/json"})
        if r.status_code == 404: return {"status": "not_found"}
        if r.status_code in (401,403): return {"status": "unauthorized"}
        if r.status_code == 429: return {"status": "rate_limited", "retry_after": r.headers.get("Retry-After")}
        if r.status_code >= 400: return {"status": "provider_error", "http_status": r.status_code}
        obj = r.json().get("data", {}); a = obj.get("attributes", {}); stats = a.get("last_analysis_stats", {})
        gui_type={'ip_address':'ip-address'}.get(obj.get('type'),obj.get('type'))
        return {"status": "success", "source_url": f"https://www.virustotal.com/gui/{gui_type}/{obj.get('id')}", "object_type": obj.get("type"), "reputation": a.get("reputation"),
                "analysis_stats": stats, "malicious": stats.get("malicious"), "suspicious": stats.get("suspicious"),
                "first_seen": a.get("first_submission_date") or a.get("creation_date"),
                "analysis_at": a.get("last_analysis_date"), "tags": a.get("tags", [])[:20],
                "interpretation_note":"Analysis time is not an observation of malicious activity."}
    except httpx.TimeoutException: return {"status": "timeout"}
    except (httpx.RequestError, ValueError): return {"status": "connection_error"}
