
import os
from ipaddress import ip_address

import httpx


API_URL = "https://api.greynoise.io/v3/community/"


async def check_ip(ip: str) -> dict:
    """Check a public IP against GreyNoise Community. Read-only lookup."""

    # Validate the IP address
    try:
        parsed_ip = ip_address(ip.strip())
    except ValueError:
        return {
            "provider": "greynoise",
            "status": "invalid_indicator",
            "error": "Invalid IP address",
        }

    if not parsed_ip.is_global:
        return {
            "provider": "greynoise",
            "status": "blocked",
            "error": "Only public global IP addresses are allowed",
        }

    if parsed_ip.version != 4:
        return {"provider": "greynoise", "status": "unsupported_indicator_type"}

    api_key = os.getenv("GREYNOISE_API_KEY", "").strip()

    if not api_key:
        return {
            "provider": "greynoise",
            "status": "not_configured",
            "error": "GreyNoise API key is not configured",
        }

    headers = {
        "key": api_key,
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"{API_URL}{parsed_ip}",
                headers=headers,
            )

        if response.status_code == 401:
            return {
                "provider": "greynoise",
                "status": "unauthorized",
                "error": "GreyNoise rejected the API key",
            }

        if response.status_code == 403:
            return {
                "provider": "greynoise",
                "status": "forbidden",
                "error": "API key does not have permission for this endpoint",
            }

        if response.status_code == 404:
            return {
                "provider": "greynoise",
                "status": "not_found",
                "queried_ip": str(parsed_ip),
                "message": "No GreyNoise community record found",
            }

        if response.status_code == 429:
            return {
                "provider": "greynoise",
                "status": "rate_limited",
                "retry_after": response.headers.get("Retry-After"),
            }

        if response.status_code >= 400:
            return {
                "provider": "greynoise",
                "status": "provider_error",
                "http_status": response.status_code,
            }

        try:
            data = response.json()
        except ValueError:
            return {
                "provider": "greynoise",
                "status": "invalid_response",
                "error": "GreyNoise returned invalid JSON",
            }

        return {
            "provider": "greynoise",
            "status": "success",
            "queried_ip": str(parsed_ip),
            "noise": data.get("noise"),
            "riot": data.get("riot"),
            "classification": data.get("classification"),
            "name": data.get("name"),
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
            "link": data.get("link"),
        }

    except httpx.TimeoutException:
        return {
            "provider": "greynoise",
            "status": "timeout",
            "error": "GreyNoise request timed out",
        }

    except httpx.RequestError:
        return {
            "provider": "greynoise",
            "status": "connection_error",
            "error": "Could not connect to GreyNoise",
        }
