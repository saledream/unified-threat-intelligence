"""IANA-discovered registration context with HTTPS, DNS pinning and no redirects."""
import asyncio
import socket
import time
from urllib.parse import urlsplit, quote
import httpx
from app.services.indicators import public_ip, validate_indicator

BOOTSTRAP = 'https://data.iana.org/rdap/dns.json'
_bootstrap = None
_bootstrap_until = 0


async def safe_get(url):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError('Prohibited RDAP service destination')
    rows = await asyncio.to_thread(socket.getaddrinfo, parsed.hostname, 443, type=socket.SOCK_STREAM)
    addresses = sorted({row[4][0] for row in rows})
    if not addresses or not all(public_ip(address) for address in addresses):
        raise ValueError('Non-public RDAP service destination')
    # Connect to the checked address, preserving the original TLS certificate name and Host.
    pinned = httpx.URL(url).copy_with(host=addresses[0])
    async with httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False) as client:
        return await client.get(pinned, headers={'Host': parsed.hostname, 'Accept': 'application/rdap+json'},
                                extensions={'sni_hostname': parsed.hostname})


async def lookup_domain(domain: str) -> dict:
    global _bootstrap, _bootstrap_until
    check = validate_indicator(domain, 'domain')
    if not check.get('valid'):
        return {'status': 'invalid_indicator'}
    domain = check['indicator']
    try:
        if _bootstrap is None or time.monotonic() >= _bootstrap_until:
            response = await safe_get(BOOTSTRAP)
            response.raise_for_status()
            _bootstrap = response.json()
            _bootstrap_until = time.monotonic() + 86400
        services = [urls for tlds, urls in _bootstrap.get('services', []) if domain.rsplit('.', 1)[-1] in tlds]
        bases = [url for urls in services for url in urls if url.startswith('https://')]
        if not bases:
            return {'status': 'skipped', 'reason': 'No HTTPS authoritative RDAP service in IANA bootstrap'}
        source = f"{bases[0].rstrip('/')}/domain/{quote(domain, safe='')}"
        response = await safe_get(source)
        if response.status_code == 404:
            return {'status': 'not_found', 'queried_domain': domain,
                    'reason': 'No registration record for this exact hostname; parent registration may differ'}
        if response.status_code == 429:
            return {'status': 'rate_limited', 'retry_after': response.headers.get('Retry-After')}
        if 300 <= response.status_code < 400:
            return {'status': 'skipped', 'reason': 'RDAP referral redirect requires reviewed provider configuration'}
        if response.status_code >= 400:
            return {'status': 'provider_error', 'http_status': response.status_code}
        data = response.json()
        events = {e.get('eventAction'): e.get('eventDate') for e in data.get('events', [])}
        entities = []
        for entity in data.get('entities', []):
            item = {'handle': entity.get('handle'), 'roles': entity.get('roles', [])}
            vcard = entity.get('vcardArray') or []
            if len(vcard) > 1:
                item['name'] = next((f[3] for f in vcard[1] if len(f) > 3 and f[0] == 'fn'), None)
            entities.append(item)
        return {'status': 'success', 'queried_domain': domain, 'handle': data.get('handle'),
                'registered_domain': data.get('ldhName'), 'entities': entities,
                'registrar': next((e.get('name') for e in entities if 'registrar' in e['roles']), None),
                'registration_date': events.get('registration'), 'last_changed': events.get('last changed'),
                'expiration_date': events.get('expiration'),
                'nameservers': [n['ldhName'] for n in data.get('nameservers', []) if n.get('ldhName')],
                'domain_status': data.get('status', []), 'source_url': source}
    except httpx.TimeoutException:
        return {'status': 'timeout'}
    except (ValueError, TypeError, KeyError):
        return {'status': 'invalid_response', 'error': 'Unsafe service destination or malformed RDAP response'}
    except (httpx.HTTPError, OSError):
        return {'status': 'connection_error'}
