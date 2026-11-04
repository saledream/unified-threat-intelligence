"""AlienVault OTX passive multi-indicator lookup."""
import os
from urllib.parse import quote
import httpx

BASE = "https://otx.alienvault.com/api/v1/indicators"

async def lookup(value: str, kind: str, hash_type: str | None = None) -> dict:
    key = os.getenv("OTX_API_KEY", "").strip()
    if not key: return {"status": "not_configured", "error": "AlienVault OTX API key is not configured"}
    otx_type = {"ip":"IPv6" if ':' in value else "IPv4", "domain":"domain", "url":"url", "hash":"file"}.get(kind)
    if not otx_type: return {"status": "unsupported_indicator_type"}
    # OTX indicator endpoints use the original observable in the path; URL-encode it.
    endpoint = f"{BASE}/{otx_type}/{quote(value, safe='')}/general"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(endpoint, headers={"X-OTX-API-KEY": key, "Accept":"application/json"})
        if r.status_code == 404: return {"status":"not_found"}
        if r.status_code in (401,403): return {"status":"unauthorized"}
        if r.status_code == 429: return {"status":"rate_limited", "retry_after":r.headers.get("Retry-After")}
        if r.status_code >= 400: return {"status":"provider_error", "http_status":r.status_code}
        d=r.json(); p=d.get("pulse_info") or {}; pulses=[]
        for x in p.get("pulses",[])[:10]:
            pulses.append({"id":x.get("id"),"name":x.get("name"),"created":x.get("created"),"modified":x.get("modified"),
                           "tags":x.get("tags",[]),"references":x.get("references",[])[:5]})
        return {"status":"success","query_type":kind,"pulse_count":p.get("count",0),"pulses":pulses,
                "reputation":d.get("reputation"),"country_code":d.get("country_code"),"asn":d.get("asn")}
    except httpx.TimeoutException: return {"status":"timeout"}
    except (httpx.RequestError,ValueError): return {"status":"connection_error"}

async def check_ip(ip: str) -> dict:
    # Backward-compatible wrapper retained for existing MCP/API contracts.
    return {"provider":"otx", **await lookup(ip, "ip")}
