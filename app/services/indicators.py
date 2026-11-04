"""IOC validation without target connections or DNS resolution."""
import os
import re
from ipaddress import ip_address
from urllib.parse import urlsplit, urlunsplit


def parse_ip_endpoint(value: str):
    """Separate optional endpoint context without inferring a URL or connecting."""
    try:
        return ip_address(value), None
    except ValueError:
        match = re.fullmatch(r'(\[[^\]]+\]|[0-9.]+):([0-9]{1,5})', value)
        if not match:
            raise ValueError('Invalid IP or IP:port endpoint')
        host, port = match.groups()
        parsed = ip_address(host.strip('[]'))
        if host.startswith('[') and parsed.version != 6:
            raise ValueError('Brackets are for IPv6 endpoints')
        if not 1 <= int(port) <= 65535:
            raise ValueError('Invalid endpoint port')
        return parsed, int(port)


def is_internal_domain(hostname: str) -> bool:
    hostname = hostname.rstrip('.').lower()
    suffixes = ('.localhost', '.local', '.internal', '.lan', '.home.arpa',
                '.test', '.invalid', '.example', '.intranet', '.corp', '.onion')
    configured = tuple(x.strip().lower().lstrip('.') for x in
                       os.getenv('INTERNAL_DOMAIN_SUFFIXES', '').split(',') if x.strip())
    return (hostname == 'localhost' or any(hostname.endswith(x) for x in suffixes)
            or any(hostname == x or hostname.endswith('.' + x) for x in configured))


def public_ip(value: str) -> bool:
    parsed = ip_address(value)
    return (parsed.is_global and not parsed.is_multicast and not parsed.is_reserved
            and not parsed.is_unspecified and not parsed.is_loopback
            and '%' not in value and getattr(parsed, 'ipv4_mapped', None) is None
            and getattr(parsed, 'sixtofour', None) is None
            and getattr(parsed, 'teredo', None) is None)


def validate_indicator(indicator: str, indicator_type: str) -> dict:
    'Validate and normalize an IP, domain, URL or file hash without contacting a target. Reports whether external disclosure is allowed; validation is not a safety verdict.'
    if not isinstance(indicator, str) or not isinstance(indicator_type, str):
        return {'valid': False, 'error': 'Indicator and type must be strings'}
    if len(indicator) > 4096 or any(ord(ch) < 32 or ord(ch) == 127 for ch in indicator):
        return {'valid': False, 'error': 'Invalid length or control characters'}
    kind, value = indicator_type.lower().strip(), indicator.strip()
    if not value:
        return {'valid': False, 'error': 'Indicator is empty'}
    try:
        if kind == 'ip':
            parsed, port = parse_ip_endpoint(value)
            allowed = public_ip(str(parsed))
            return {'valid': True, 'type': 'ip', 'ip_version': parsed.version,
                    'indicator': str(parsed), 'is_global': allowed,
                    'external_lookup_allowed': allowed, **({'port': port} if port is not None else {})}
        if kind == 'domain':
            domain = value.rstrip('.').encode('idna').decode('ascii').lower()
            if is_internal_domain(domain):
                raise ValueError('Internal or reserved domain')
            if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})', domain):
                raise ValueError('Expected a public fully qualified domain/hostname')
            return {'valid': True, 'type': 'domain', 'indicator': domain, 'external_lookup_allowed': True}
        if kind == 'url':
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in ('https', 'http') or not parsed.hostname:
                raise ValueError('Expected an HTTP/HTTPS URL')
            if parsed.username is not None or parsed.password is not None:
                raise ValueError('Embedded credentials')
            if parsed.fragment or '\\' in value or any(ch.isspace() for ch in value):
                raise ValueError('Fragments, backslashes or whitespace')
            if parsed.port not in (None, 80 if parsed.scheme.lower() == 'http' else 443):
                raise ValueError('Only default ports supported')
            host = parsed.hostname.rstrip('.').lower()
            try:
                ip_address(host)
            except ValueError:
                check = validate_indicator(host, 'domain')
                if not check['valid']:
                    raise ValueError(check['error'])
                host = check['indicator']
            else:
                if not public_ip(host):
                    raise ValueError('Non-public URL host')
            authority = f'[{host}]' if ':' in host else host
            normalized = urlunsplit((parsed.scheme.lower(), authority, parsed.path or '/', parsed.query, ''))
            return {'valid': True, 'type': 'url', 'indicator': normalized, 'hostname': host,
                    'external_lookup_allowed': True,
                    'note': 'Passive provider query; no target connection or DNS resolution'}
        if kind == 'hash':
            if not re.fullmatch(r'(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})', value):
                raise ValueError('Expected MD5/SHA1/SHA256')
            return {'valid': True, 'type': 'hash', 'indicator': value.lower(),
                    'hash_type': {32: 'md5', 40: 'sha1', 64: 'sha256'}[len(value)],
                    'external_lookup_allowed': True}
        raise ValueError('Unsupported type')
    except (ValueError, UnicodeError):
        return {'valid': False, 'error': 'Invalid or prohibited indicator format'}
