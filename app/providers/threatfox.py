import os
from app.providers.abusech_policy import authorized as abusech_authorized
import re
import httpx

API_URL = "https://threatfox-api.abuse.ch/api/v1/"


async def search_ioc(indicator: str) -> dict:
    indicator = indicator.strip()

    if not indicator:
        return {
            "provider": "threatfox",
            "status": "invalid_indicator",
            "error": "Indicator is empty",
        }

    if not abusech_authorized():
        return {"provider": "threatfox", "status": "requires_authorization"}
    if re.fullmatch(r"[a-fA-F0-9]{40}", indicator):
        return {"provider": "threatfox", "status": "unsupported_indicator_type"}
    api_key = os.getenv("ABUSECH_API_KEY")
    if not api_key:
        return {
            "provider": "threatfox",
            "status": "not_configured",
        }

    payload = {
        "query": "search_ioc",
        "search_term": indicator,
        "exact_match": True,
    }

    if re.fullmatch(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{64})", indicator):
        payload = {"query": "search_hash", "hash": indicator.lower()}
    headers = {
        "Auth-Key": api_key,
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(
                API_URL,
                json=payload,
                headers=headers,
            )

        if response.status_code in (401, 403):
            return {"provider": "threatfox", "status": "unauthorized"}

        if response.status_code == 429:
            return {"provider": "threatfox", "status": "rate_limited", "retry_after": response.headers.get("Retry-After")}

        if response.status_code >= 400:
            return {
                "provider": "threatfox",
                "status": "provider_error",
                "http_status": response.status_code,
            }

        try:
            result = response.json()
        except ValueError:
            return {
                "provider": "threatfox",
                "status": "invalid_response",
            }

        query_status = result.get("query_status")

        if query_status == "no_result":
            return {
                "provider": "threatfox",
                "status": "not_found",
                "queried_indicator": indicator,
            }

        if query_status != "ok":
            return {
                "provider": "threatfox",
                "status": "provider_error",
                "provider_status": query_status,
            }

        records = result.get("data") or []

        if not records:
            return {
                "provider": "threatfox",
                "status": "not_found",
                "queried_indicator": indicator,
            }

        return {
            "provider": "threatfox",
            "status": "success",
            "queried_indicator": indicator,
            "result_count": len(records),
            "indicators": [
                {
                    "id": item.get("id"),
                    "ioc": item.get("ioc"),
                    "ioc_type": item.get("ioc_type"),
                    "threat_type": item.get("threat_type"),
                    "malware": item.get("malware"),
                    "malware_alias": item.get("malware_alias"),
                    "malware_printable": item.get("malware_printable"),
                    "confidence_level": item.get("confidence_level"),
                    "first_seen": item.get("first_seen"),
                    "last_seen": item.get("last_seen"),
                    "reporter": item.get("reporter"),
                    "reference": item.get("reference"),
                    "tags": item.get("tags") or [],
                }
                for item in records[:20]
            ],
            "intelligence_source": "ThreatFox",
            "interpretation_note": (
                "Threat intelligence records are evidence for analyst correlation, "
                "not standalone proof that an observed system is compromised."
            ),
        }

    except httpx.TimeoutException:
        return {
            "provider": "threatfox",
            "status": "timeout",
        }

    except httpx.RequestError:
        return {
            "provider": "threatfox",
            "status": "connection_error",
        }
