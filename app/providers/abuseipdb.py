import os
import httpx
from ipaddress import ip_address

API_URL = "https://api.abuseipdb.com/api/v2/check"


async def check_ip(ip: str, max_age_days: int = 90) -> dict:
    """Read-only AbuseIPDB reputation lookup for a public IP."""

    try:
        parsed_ip = ip_address(ip.strip())
    except ValueError:
        return {
            "provider": "abuseipdb",
            "status": "invalid_indicator",
            "error": "Invalid IP address",
        }

    if not parsed_ip.is_global:
        return {
            "provider": "abuseipdb",
            "status": "blocked",
            "error": "Non-public IP addresses cannot be submitted",
        }

    if not 1 <= max_age_days <= 365:
        return {
            "provider": "abuseipdb",
            "status": "invalid_parameter",
            "error": "max_age_days must be between 1 and 365",
        }

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "provider": "abuseipdb",
            "status": "not_configured",
            "error": "AbuseIPDB API key is not configured",
        }

    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }

    params = {
        "ipAddress": str(parsed_ip),
        "maxAgeInDays": max_age_days,
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                API_URL,
                headers=headers,
                params=params,
            )

        if response.status_code == 401:
            return {
                "provider": "abuseipdb",
                "status": "unauthorized",
                "error": "API key rejected",
            }

        if response.status_code == 429:
            return {
                "provider": "abuseipdb",
                "status": "rate_limited",
                "retry_after": response.headers.get("Retry-After"),
                "remaining": response.headers.get("X-RateLimit-Remaining"),
            }

        if response.status_code != 200:
            return {
                "provider": "abuseipdb",
                "status": "provider_error",
                "http_status": response.status_code,
            }

        payload = response.json()
        data = payload.get("data", {})

        return {
            "provider": "abuseipdb",
            "status": "success",
            "queried_ip": data.get("ipAddress"),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "distinct_reporters": data.get("numDistinctUsers"),
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor"),
            "is_whitelisted": data.get("isWhitelisted"),
            "last_reported_at": data.get("lastReportedAt"),
            "report_window_days": max_age_days,
        }

    except httpx.TimeoutException:
        return {
            "provider": "abuseipdb",
            "status": "timeout",
            "error": "Provider request timed out",
        }

    except httpx.RequestError:
        return {
            "provider": "abuseipdb",
            "status": "connection_error",
            "error": "Could not connect to AbuseIPDB",
        }

    except ValueError:
        return {
            "provider": "abuseipdb",
            "status": "invalid_response",
            "error": "Provider returned an invalid response",
        }
