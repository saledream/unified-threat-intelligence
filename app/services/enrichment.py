"""Shared threat-intelligence enrichment orchestration."""

import asyncio
from ipaddress import ip_address

from app.providers.abuseipdb import check_ip
from app.providers.greynoise import check_ip as check_greynoise
from app.providers.otx import check_ip as check_otx


async def enrich_ip_all(ip: str) -> dict:
    """
    Enrich a public IP using AbuseIPDB, GreyNoise and AlienVault OTX.
    Queries run independently and concurrently. Read-only operation.
    """
    import asyncio
    from ipaddress import ip_address
    try:
        parsed_ip = ip_address(ip.strip())
    except ValueError:
        return {'indicator': ip, 'status': 'invalid_indicator', 'error': 'Invalid IP address'}
    if not parsed_ip.is_global:
        return {'indicator': str(parsed_ip), 'status': 'blocked', 'error': 'Only public global IP addresses are allowed'}
    results = await asyncio.gather(enrich_ip_abuseipdb(str(parsed_ip)), enrich_ip_greynoise(str(parsed_ip)), enrich_ip_otx(str(parsed_ip)), return_exceptions=True)
    providers = ['abuseipdb', 'greynoise', 'otx']
    enrichment = {}
    for provider, result in zip(providers, results):
        if isinstance(result, Exception):
            enrichment[provider] = {'provider': provider, 'status': 'internal_error', 'error': 'Provider lookup failed unexpectedly'}
        else:
            enrichment[provider] = result
    return {'indicator': str(parsed_ip), 'indicator_type': 'ipv4' if parsed_ip.version == 4 else 'ipv6', 'operation': 'read_only_enrichment', 'providers_queried': providers, 'results': enrichment, 'interpretation_note': 'Provider results are independent evidence. Missing records, zero scores, and unavailable providers do not establish that an indicator is safe.'}


from app.services.indicators import validate_indicator
from app.providers.malwarebazaar import check_hash
from app.providers.threatfox import search_ioc
from app.providers.urlhaus import check_url


async def enrich_ip_abuseipdb(ip: str, max_age_days: int=90) -> dict:
    """Look up a public IP in AbuseIPDB. Read-only reputation check."""
    validation = validate_indicator(ip, 'ip')
    if not validation.get('valid'):
        return {'provider': 'abuseipdb', 'status': 'invalid_indicator', 'validation': validation}
    if not validation.get('external_lookup_allowed', False):
        return {'provider': 'abuseipdb', 'status': 'blocked', 'reason': 'Only public IP addresses are allowed'}
    if not isinstance(max_age_days, int) or isinstance(max_age_days, bool) or (not 1 <= max_age_days <= 365):
        return {'provider': 'abuseipdb', 'status': 'invalid_parameter', 'error': 'max_age_days must be between 1 and 365'}
    return await _execute_legacy('abuseipdb', validation['indicator'], 'ip', validation, max_age_days)

async def enrich_ip_greynoise(ip: str) -> dict:
    """Check a public IP against GreyNoise Community. Read-only lookup."""
    validation = validate_indicator(ip, 'ip')
    if not validation.get('valid'):
        return {'provider': 'greynoise', 'status': 'invalid_indicator', 'validation': validation}
    if not validation.get('external_lookup_allowed', False):
        return {'provider': 'greynoise', 'status': 'blocked', 'reason': 'Only public IP addresses are allowed'}
    return await _execute_legacy('greynoise', validation['indicator'], 'ip', validation)

async def enrich_ip_otx(ip: str) -> dict:
    """Check a public IP against AlienVault OTX. Read-only lookup."""
    validation = validate_indicator(ip, 'ip')
    if not validation.get('valid'):
        return {'provider': 'otx', 'status': 'invalid_indicator', 'validation': validation}
    if not validation.get('external_lookup_allowed', False):
        return {'provider': 'otx', 'status': 'blocked', 'reason': 'Only public IP addresses are allowed'}
    return await _execute_legacy('otx', validation['indicator'], 'ip', validation)

async def enrich_file_hash_malwarebazaar(file_hash: str) -> dict:
    """Look up an MD5, SHA1, or SHA256 file hash in MalwareBazaar. Read-only lookup; never uploads or downloads files."""
    validation = validate_indicator(file_hash, 'hash')
    if not validation.get('valid'):
        return {'provider': 'malwarebazaar', 'status': 'invalid_indicator', 'validation': validation}
    if not validation.get('external_lookup_allowed', True):
        return {'provider': 'malwarebazaar', 'status': 'blocked', 'reason': 'Indicator is not eligible for external lookup'}
    return await _execute_legacy('malwarebazaar', validation['indicator'], 'hash', validation)

async def enrich_indicator_threatfox(indicator: str, indicator_type: str) -> dict:
    """Search ThreatFox for a public IP, domain, URL, or file hash. Read-only lookup; never submits indicators."""
    validation = validate_indicator(indicator, indicator_type)
    if not validation.get('valid'):
        return {'provider': 'threatfox', 'status': 'invalid_indicator', 'validation': validation}
    if not validation.get('external_lookup_allowed', False):
        return {'provider': 'threatfox', 'status': 'blocked', 'reason': 'Indicator is not eligible for external lookup'}
    return await _execute_legacy('threatfox', validation['indicator'], indicator_type, validation)

async def enrich_url_urlhaus(url: str) -> dict:
    """Look up an HTTPS URL in URLhaus. Read-only lookup; never submits URLs or downloads payloads."""
    validation = validate_indicator(url, 'url')
    if not validation.get('valid'):
        return {'provider': 'urlhaus', 'status': 'invalid_indicator', 'validation': validation}
    if not validation.get('external_lookup_allowed', False):
        return {'provider': 'urlhaus', 'status': 'blocked', 'reason': 'URL is not eligible for external lookup'}
    return await _execute_legacy('urlhaus', validation['indicator'], 'url', validation)


async def enrich_indicator_otx(indicator: str, indicator_type: str) -> dict:
    # Shared OTX multi-indicator wrapper.
    from app.providers import otx
    check = validate_indicator(indicator, indicator_type)
    if not check.get("valid") or not check.get("external_lookup_allowed"):
        return {"status": "invalid_indicator", "error": check.get("error", "External lookup prohibited")}
    return await _execute_legacy("otx", check["indicator"], indicator_type, check)


async def _execute_legacy(name, value, kind, meta, max_age_days=90):
    """Preserve legacy response fields while enforcing shared provider policy/budgets."""
    from app.services.registry import CAPABILITIES, load_overrides, lookup
    from app.services.provider_runtime import execute
    cap = next(c for c in CAPABILITIES if c.name == name)
    try:
        overrides = await asyncio.wait_for(asyncio.to_thread(load_overrides), timeout=7)
    except Exception:
        return {'provider': name, 'status': 'blocked', 'error': 'Provider policy unavailable'}
    policy = cap.policy_status(overrides)
    if policy != 'configured':
        return {'provider': name, 'status': policy}
    async def operation(_name, _value, _kind, _meta):
        if name == 'abuseipdb':
            return await check_ip(value, max_age_days)
        return await lookup(cap, value, kind, meta)
    # AbuseIPDB max-age changes response semantics; include it in cache identity.
    query_meta = {**meta, 'max_age_days': max_age_days} if name == 'abuseipdb' else meta
    return {'provider': name, **await execute(cap, value, kind, query_meta, operation)}
