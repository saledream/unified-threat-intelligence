import os
from app.providers.abusech_policy import authorized as abusech_authorized
import httpx

API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


async def check_url(url: str) -> dict:
    url = url.strip()

    if not url:
        return {
            "provider": "urlhaus",
            "status": "invalid_indicator",
            "error": "URL is empty",
        }

    if not abusech_authorized():
        return {"provider": "urlhaus", "status": "requires_authorization"}

    api_key = os.getenv("ABUSECH_API_KEY")
    if not api_key:
        return {
            "provider": "urlhaus",
            "status": "not_configured",
        }

    headers = {
        "Auth-Key": api_key,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(
                API_URL,
                data={"url": url},
                headers=headers,
            )

        if response.status_code in (401, 403):
            return {"provider": "urlhaus", "status": "unauthorized"}

        if response.status_code == 429:
            return {"provider": "urlhaus", "status": "rate_limited"}

        if response.status_code >= 400:
            return {
                "provider": "urlhaus",
                "status": "provider_error",
                "http_status": response.status_code,
            }

        try:
            result = response.json()
        except ValueError:
            return {
                "provider": "urlhaus",
                "status": "invalid_response",
            }

        query_status = result.get("query_status")

        if query_status == "no_results":
            return {
                "provider": "urlhaus",
                "status": "not_found",
                "queried_url": url,
            }

        if query_status != "ok":
            return {
                "provider": "urlhaus",
                "status": "provider_error",
                "provider_status": query_status,
            }

        return {
            "provider": "urlhaus",
            "status": "success",
            "queried_url": url,
            "url_status": result.get("url_status"),
            "threat": result.get("threat"),
            "date_added": result.get("date_added"),
            "last_online": result.get("last_online"),
            "reporter": result.get("reporter"),
            "larted": result.get("larted"),
            "takedown_time_seconds": result.get("takedown_time_seconds"),
            "tags": result.get("tags") or [],
            "payloads": [
                {
                    "filename": item.get("filename"),
                    "file_type": item.get("file_type"),
                    "response_size": item.get("response_size"),
                    "response_md5": item.get("response_md5"),
                    "response_sha256": item.get("response_sha256"),
                }
                for item in (result.get("payloads") or [])[:10]
            ],
            "intelligence_source": "URLhaus",
            "interpretation_note": (
                "A URLhaus match is threat intelligence evidence. "
                "It does not establish that an internal endpoint visited or executed the URL."
            ),
        }

    except httpx.TimeoutException:
        return {"provider": "urlhaus", "status": "timeout"}

    except httpx.RequestError:
        return {"provider": "urlhaus", "status": "connection_error"}
