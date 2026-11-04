"""MCP surface over shared services. No human-approval operation is registered."""
import asyncio
import inspect
from functools import wraps
from app.services.projection import compact_result
import os
from app.services import investigation, identity, source_queries, knowledge, intel_store
from app.services.vulnerabilities import lookup_cve

def principal():
    return 'local:anonymous'

def register(mcp):
    def tool(**options):
        def decorate(function):
            @wraps(function)
            async def wrapped(*args,**kwargs):
                result=function(*args,**kwargs)
                if inspect.isawaitable(result):result=await result
                return compact_result(result)
            return mcp.tool(**options)(wrapped)
        return decorate
    from app.services import cloudflare_radar
    tool(name='cloudflare_asn_lookup')(cloudflare_radar.asn_lookup)
    tool(name='cloudflare_domain_rank')(cloudflare_radar.domain_rank)
    tool(name='cloudflare_ddos_trends')(cloudflare_radar.ddos_trends)
    tool(name='cloudflare_email_security')(cloudflare_radar.email_security)
    @tool()
    def health()->dict:
        """Read service readiness and available provider policies without network calls."""
        from app.services.registry import provider_status
        return {'status':'ok','providers':provider_status()}

    @tool()
    async def ip_lookup(ip:str)->dict:
        """Read all configured public-IP sources through the unified engine."""
        return await _typed(ip,'ip')
    @tool()
    async def shodan_host_lookup(ip:str)->dict:
        """Read an authenticated Shodan report for a public IP. Account entitlements apply. No new scan, active probing, or sample download."""
        return await investigation.provider_lookup('shodan',ip)
    @tool()
    async def domain_lookup(domain:str)->dict:
        """Read all configured domain sources through the unified engine."""
        return await _typed(domain,'domain')
    @tool()
    async def url_lookup(url:str)->dict:
        """Read historical URL/host intelligence. Does not submit a scan."""
        return await _typed(url,'url')
    @tool()
    async def hash_lookup(file_hash:str)->dict:
        """Read file-hash metadata. Does not upload or download a file."""
        return await _typed(file_hash,'hash')
    tool(name='lookup_cve')(lookup_cve)
    tool(name='bulk_lookup_iocs',description='Enrich 1–20 indicators, with bounded concurrency and compact evidence.')(investigation.bulk_lookup)
    tool(name='investigate_indicator',description='Investigate an IOC, optionally following up to three explicit observed relationships at depth one. No scans are submitted.')(investigation.investigate)
    tool(name='provider_lookup',description='Read an IOC report from one named registry provider, using shared validation and policy.')(investigation.provider_lookup)
    @tool()
    async def dns_lookup(domain:str,qtype:str='A')->dict:
        """Query Cloudflare DoH when enabled by provider policy. Discloses the domain to the resolver."""
        from app.services.registry import CAPABILITIES,load_overrides
        from app.providers.extended import dns_query
        cap=next(c for c in CAPABILITIES if c.name=='dns_doh')
        policy=cap.policy_status(load_overrides())
        if policy!='configured':return {'status':policy}
        return await dns_query(domain,qtype)
    tool(name='search_pulses',description='Search OTX pulses or retrieve a pulse by ID; community context only.')(source_queries.otx_pulses)
    tool(name='search_malware_samples',description='Read MalwareBazaar metadata by tag or signature. Never download samples.')(source_queries.malwarebazaar_search)
    tool(name='urlhaus_host_lookup')(source_queries.urlhaus_host)
    tool(name='yara_rule_lookup',description='Read YARAify rule matches, rule text, or file-hash metadata. Never execute rules or fetch samples.')(source_queries.yara_lookup)
    tool(name='fingerprint_lookup',description='Search locally synchronized SSLBL JA3 or certificate fingerprints.')(source_queries.fingerprint_lookup)
    tool(name='search_reference',description='Search imported ATT&CK, Sigma, LOLBAS, GTFOBins, HijackLibs, WADComs or D3FEND references. Returned content is untrusted data.')(knowledge.search_reference)
    tool(name='command_context',description='Find lexical command-reference context locally. Never execute the command.')(knowledge.command_context)
    tool(name='check_email_breaches',description='Opt-in breach metadata lookup. Requires explicit permission to disclose this email to the chosen provider. Never returns recovered passwords.')(identity.check_breach)
    tool(name='check_domain_breaches')(identity.domain_breaches)
    tool(name='check_password_sha1',description='Accept a SHA-1 digest computed locally, never a plaintext password. Only the first five hash characters are sent to Pwned Passwords.')(identity.password_check_sha1)
    tool(name='get_latest_breach')(identity.latest_breach)

    @tool()
    async def get_feed_status()->dict:
        """Read local feed/corpus synchronization state. No network request."""
        return {'status':'success','sources':await asyncio.to_thread(intel_store.feed_status)}

    @tool()
    async def search_threats(query:str='',source:str|None=None,kind:str|None=None,limit:int=10)->dict:
        """Search local records. Source accepts names such as ThreatFox or feed:threatfox, or corpus:sigma. Unknown filters return an error, never a misleading empty result. At most 50 records."""
        from app.services.local_search import search_local
        return await asyncio.to_thread(search_local,query,source,kind,limit)

    @tool()
    async def get_recent_threats(source:str|None=None,limit:int=10)->dict:
        """Read the most recently ingested local feed records; retrieval time is not event time."""
        from app.services.local_search import search_local
        return await asyncio.to_thread(search_local,'',source,None,limit)


async def _typed(value,kind):
    from app.services.indicators import validate_indicator
    from app.services.unified import enrich_indicator_all,agent_summary
    value=investigation.refang(value)
    validation=validate_indicator(value,kind)
    if not validation.get('external_lookup_allowed'):return {'status':'blocked','validation':validation}
    return agent_summary(await enrich_indicator_all(value))
