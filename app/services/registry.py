"""Provider capability and policy registry shared by HTTP and MCP."""
import os
from dataclasses import dataclass, asdict
from app.providers.abusech_policy import authorized as abusech_authorized
from app.providers import extended
from app.providers import abuseipdb, greynoise, otx, threatfox, urlhaus, malwarebazaar, rdap, urlscan, virustotal


@dataclass(frozen=True)
class Capability:
    name: str
    types: tuple[str, ...]
    lookup_method: str
    credential_env: str = ''
    authorization_env: str = ''
    licensing: str = 'Review provider terms and subscription before business use'
    input_format: str = 'Normalized public IOC; URL path/query preserved'
    normalization: str = 'IP canonical form, IDNA lowercase hostname, lowercase hex hash'
    ip_versions: tuple[int, ...] = (4, 6)
    hash_types: tuple[str, ...] = ('md5', 'sha1', 'sha256')
    passive: bool = True
    timeout_seconds: float = 25.0
    retries: int = 1
    cache_ttl_seconds: int = 300
    min_interval_seconds: float = 1.0
    reliability: str = 'medium'
    provenance_group: str = ''
    accepts_context: bool = False
    required_envs: tuple[str, ...] = ()
    enabled_by_default: bool = True
    commercial_env: str = ''

    def policy_status(self, overrides: dict | None = None) -> str:
        switch = os.getenv(f'PROVIDER_{self.name.upper()}_ENABLED')
        explicit_enabled = switch is not None and switch.lower() in ('true','1','yes')
        enabled = (overrides or {}).get(self.name, self.enabled_by_default or explicit_enabled)
        if not enabled or (switch is not None and not explicit_enabled):
            return 'disabled'
        if self.name == 'virustotal' and not virustotal.authorized():
            return 'requires_authorization'
        if self.authorization_env == 'ABUSECH_COMMERCIAL_AUTHORIZED' and not abusech_authorized():
            return 'requires_authorization'
        if self.name != 'virustotal' and self.authorization_env != 'ABUSECH_COMMERCIAL_AUTHORIZED' and self.authorization_env and os.getenv(self.authorization_env, '').lower() not in ('true', '1', 'yes'):
            return 'requires_authorization'
        if self.commercial_env and os.getenv('INTEL_USAGE_MODE','commercial') != 'personal' and os.getenv(self.commercial_env,'').lower() not in ('true','1','yes'):
            return 'requires_authorization'
        if any(not os.getenv(k,'').strip() for k in self.required_envs):
            return 'not_configured'
        if self.credential_env and not os.getenv(self.credential_env, '').strip():
            return 'not_configured'
        return 'configured'


CAPABILITIES = (
    Capability('abuseipdb', ('ip',), 'check_ip', 'ABUSEIPDB_API_KEY'),
    Capability('greynoise', ('ip',), 'check_ip', 'GREYNOISE_API_KEY', ip_versions=(4,), reliability='high'),
    Capability('otx', ('ip', 'domain', 'url', 'hash'), 'lookup', 'OTX_API_KEY'),
    Capability('threatfox', ('ip', 'domain', 'url', 'hash'), 'search_ioc', 'ABUSECH_API_KEY', 'ABUSECH_COMMERCIAL_AUTHORIZED', hash_types=('md5', 'sha256'), reliability='high', provenance_group='abusech'),
    Capability('urlhaus', ('url',), 'check_url', 'ABUSECH_API_KEY', 'ABUSECH_COMMERCIAL_AUTHORIZED', reliability='high', provenance_group='abusech'),
    Capability('malwarebazaar', ('hash',), 'check_hash', 'ABUSECH_API_KEY', 'ABUSECH_COMMERCIAL_AUTHORIZED', reliability='high', provenance_group='abusech'),
    Capability('rdap', ('domain',), 'lookup_domain', reliability='authoritative_context', cache_ttl_seconds=3600),
    Capability('urlscan', ('ip', 'domain', 'url'), 'search_history', licensing='Historical search only; account quotas and terms apply'),
    Capability('shodan', ('ip',), 'lookup', 'SHODAN_API_KEY', accepts_context=True, reliability='exposure_context', provenance_group='shodan', licensing='Authenticated host-report entitlement required; queries Shodan records only, never requests a scan'),
    Capability('shodan_internetdb', ('ip',), 'lookup', accepts_context=True, reliability='exposure_context', provenance_group='shodan', commercial_env='SHODAN_COMMERCIAL_AUTHORIZED', cache_ttl_seconds=3600),
    Capability('ipinfo', ('ip',), 'lookup', 'IPINFO_TOKEN', accepts_context=True, reliability='network_context'),
    Capability('pulsedive', ('ip','domain','url'), 'lookup', 'PULSEDIVE_API_KEY', accepts_context=True),
    Capability('spur', ('ip',), 'lookup', 'SPUR_TOKEN', accepts_context=True, reliability='network_context'),
    Capability('censys', ('ip','domain'), 'lookup', 'CENSYS_API_TOKEN', accepts_context=True, reliability='exposure_context'),
    Capability('cloudflare_radar', ('ip','domain'), 'lookup', 'CLOUDFLARE_API_TOKEN', accepts_context=True, reliability='network_context', licensing='Radar IP network context; no account ID required'),
    Capability('cloudflare_urlscanner', ('ip','domain','url'), 'lookup', 'CLOUDFLARE_API_TOKEN', accepts_context=True, required_envs=('CLOUDFLARE_ACCOUNT_ID',), enabled_by_default=False, licensing='Optional URL Scanner history; separate URL Scanner permission and account ID required'),
    Capability('certificate_transparency', ('domain',), 'lookup', accepts_context=True, reliability='registration_context', cache_ttl_seconds=3600),
    Capability('dns_doh', ('domain',), 'lookup', accepts_context=True, reliability='resolution_context', enabled_by_default=False),
    Capability('local_feeds', ('ip','domain','url','hash'), 'lookup', accepts_context=True, reliability='feed_context'),
    Capability('virustotal', ('ip', 'domain', 'url', 'hash'), 'lookup', 'VIRUSTOTAL_API_KEY', 'VIRUSTOTAL_COMMERCIAL_AUTHORIZED', licensing='Personal Public API: 4/minute, 500/day; commercial workflows require licensed authorization', reliability='high', min_interval_seconds=15.0),
)
MODULES = {m.__name__.rsplit('.', 1)[-1]: m for m in (abuseipdb, greynoise, otx, threatfox, urlhaus, malwarebazaar, rdap, urlscan, virustotal)}

MODULES.update({c.name:extended for c in CAPABILITIES if c.accepts_context})


async def lookup(cap: Capability, value: str, kind: str, meta: dict) -> dict:
    method = getattr(MODULES[cap.name], cap.lookup_method)
    if cap.accepts_context:
        return await method(value, kind, {**meta, '_provider':cap.name})
    if cap.name in ('otx',):
        return await method(value, kind, meta.get('hash_type'))
    if cap.name in ('urlscan', 'virustotal'):
        return await method(value, kind)
    return await method(value)


def load_overrides() -> dict:
    # Offline library use needs no database. Deployed API/MCP share PostgreSQL settings.
    if not all(os.getenv(k) for k in ('POSTGRES_DB', 'POSTGRES_USER', 'POSTGRES_PASSWORD')):
        return {}
    from sqlalchemy import select
    from app.database import SessionLocal
    from app.models import ProviderSetting
    with SessionLocal() as db:
        return {row.name: row.enabled for row in db.scalars(select(ProviderSetting)).all()}


def provider_status() -> dict:
    from app.services.mitre_attack import DATASET
    overrides = load_overrides()
    return {**{c.name: c.policy_status(overrides) for c in CAPABILITIES},
            'mitre_attack': 'available' if DATASET.is_file() else 'dataset_missing'}


def inventory() -> list[dict]:
    overrides = load_overrides()
    return [{**asdict(c), 'status': c.policy_status(overrides),
             'enabled': overrides.get(c.name, c.enabled_by_default)} for c in CAPABILITIES]
