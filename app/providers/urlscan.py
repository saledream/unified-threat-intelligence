"""Passive urlscan.io historical Search API integration; never submits scans."""
import os
import httpx

API = "https://urlscan.io/api/v1/search/"

def _escape(value: str) -> str:
    # Quote exact values and escape characters meaningful to query-string syntax.
    return value.replace('\\', '\\\\').replace('"', '\\"')

async def search_history(value: str, kind: str) -> dict:
    field = {"domain": "page.domain.keyword", "ip": "page.ip", "url": "task.url.keyword"}.get(kind)
    if not field:
        return {"status": "unsupported_indicator_type"}
    query = f'{field}:"{_escape(value)}"'
    headers = {"Accept": "application/json", "User-Agent": "MMCY-ThreatIntel/1.0"}
    key = os.getenv("URLSCAN_API_KEY", "").strip()
    if key: headers["API-Key"] = key
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=False) as client:
            r = await client.get(API, params={"q": query, "size": 20}, headers=headers)
        if r.status_code in (401, 403): return {"status": "unauthorized"}
        if r.status_code == 429: return {"status": "rate_limited", "retry_after": r.headers.get("Retry-After")}
        if r.status_code >= 400: return {"status": "provider_error", "http_status": r.status_code}
        data = r.json(); rows = []
        for item in data.get("results", [])[:20]:
            task, page, verdicts = item.get("task", {}), item.get("page", {}), item.get("verdicts", {})
            rows.append({"scan_id": task.get("uuid"), "scan_time": task.get("time"), "url": task.get("url"),
                         "domain": page.get("domain"), "ip": page.get("ip"), "country": page.get("country"),
                         "malicious": verdicts.get("overall", {}).get("malicious"),
                         "score": verdicts.get("overall", {}).get("score"), "result_url": item.get("result")})
        return {"status": "success" if rows else "not_found", "query_type": kind, "historical_count": len(rows), "historical_scans": rows,
                "search_date_limit_days": data.get("search_date_limit_days")}
    except httpx.TimeoutException: return {"status": "timeout"}
    except (httpx.RequestError, ValueError): return {"status": "connection_error"}
