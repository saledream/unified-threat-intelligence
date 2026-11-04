import io
import json
import logging
import zipfile
import pytest
from app.services import intel_store as store,feeds,knowledge,identity,investigation
from app.providers import extended
from app.providers.http import RedactQueryCredentials

@pytest.mark.asyncio
async def test_cloudflare_radar_ip_uses_accountless_endpoint(monkeypatch):
    from app.services.registry import CAPABILITIES
    monkeypatch.setenv('CLOUDFLARE_API_TOKEN','offline-token')
    monkeypatch.setenv('CLOUDFLARE_ACCOUNT_ID','')
    cap=next(c for c in CAPABILITIES if c.name=='cloudflare_radar')
    assert cap.policy_status()=='configured'
    calls=[]
    async def request(method,url,**kwargs):
        calls.append((url,kwargs))
        return {'status':'success','data':{'success':True,'result':{'ip':{'ip':'1.2.3.4','asn':'0','location':'UA'}}}}
    monkeypatch.setattr(extended,'request',request)
    result=await extended.lookup('1.2.3.4','ip',{'_provider':'cloudflare_radar'})
    assert result['status']=='success' and result['location']=='UA'
    assert calls[0][0]=='https://api.cloudflare.com/client/v4/radar/entities/ip'
    assert calls[0][1]['params']=={'ip':'1.2.3.4'}
    from app.services.correlation import correlate
    report=correlate([{'provider':'cloudflare_radar',**result}],'1.2.3.4')
    assert report['assessment']=='informational' and not report['evidence']

def test_cloudflare_scanner_policy_is_separate(monkeypatch):
    from app.services.registry import CAPABILITIES
    cap=next(c for c in CAPABILITIES if c.name=='cloudflare_urlscanner')
    assert cap.policy_status()=='disabled'
    monkeypatch.setenv('PROVIDER_CLOUDFLARE_URLSCANNER_ENABLED','true')
    monkeypatch.setenv('CLOUDFLARE_API_TOKEN','offline-token')
    monkeypatch.setenv('CLOUDFLARE_ACCOUNT_ID','')
    assert cap.policy_status()=='not_configured'

@pytest.fixture(autouse=True)
def isolated(monkeypatch,tmp_path):
    monkeypatch.setenv('INTEL_STATE_DB',str(tmp_path/'intel.db'))
    monkeypatch.setenv('JWT_SECRET_KEY','offline-only-test-secret-which-is-long-enough')

def test_cache_encrypted_ttl_and_rotation(monkeypatch):
    store.cache_put('key',{'private':'sensitive IOC'},300)
    assert store.cache_get('key')=={'private':'sensitive IOC'}
    with store.connection() as db:assert b'sensitive IOC' not in db.execute('SELECT body FROM cache').fetchone()[0]
    monkeypatch.setenv('JWT_SECRET_KEY','rotated-offline-secret-which-is-long-enough')
    assert store.cache_get('key') is None
    store.cache_put('expired',{'a':1},-1)
    assert store.cache_get('expired') is None

def test_feed_exact_case_sensitive_url_and_percent_literal():
    rows=feeds.parse_feed('openphish','https://example.com/Case?A=B\nhttp://127.0.0.1/a','https://source.test/feed')
    store.upsert_records('feed:openphish',rows,True)
    assert store.search_records('https://example.com/Case?A=B','url',exact=True)
    assert not store.search_records('https://example.com/case?a=b','url',exact=True)
    assert not store.search_records('%')

def test_feed_ip_port_and_malware_fields_preserved():
    data={'query_status':'ok','data':[{'id':'42','ioc_type':'ip:port','ioc':'8.8.8.8:443','malware_printable':'example'}]}
    rows=feeds.parse_feed('threatfox',data,'https://threatfox.abuse.ch/')
    assert rows[0]['value']=='8.8.8.8'
    assert rows[0]['data']['ioc']=='8.8.8.8:443'

@pytest.mark.asyncio
async def test_failed_feed_sync_preserves_existing_data_and_lease(monkeypatch):
    store.upsert_records('feed:feodo',[{'id':'1','kind':'ip','value':'8.8.8.8','data':{}}])
    with store.connection() as db:db.execute("UPDATE syncs SET updated=0 WHERE source='feed:feodo'")
    async def fail(*args,**kwargs):return {'status':'timeout'}
    monkeypatch.setattr(feeds,'request',fail)
    assert (await feeds.sync_feed('feodo'))['status']=='timeout'
    assert store.search_records('8.8.8.8','ip',exact=True)
    assert feeds.claim_sync('feodo',900)['status']=='timeout'

def test_archive_is_data_only_and_preserves_notices():
    raw=io.BytesIO()
    with zipfile.ZipFile(raw,'w') as z:
        z.writestr('root/LICENSE','source license')
        z.writestr('root/yml/Test.yml','Name: Test.exe\nCreated: 2026-01-01\nCommands:\n - Command: never-execute-this')
    rows,notices=knowledge.parse_archive('lolbas',raw.getvalue(),'a'*40)
    assert rows[0]['data']['reference']['Created']=='2026-01-01'
    assert 'never-execute-this' in json.dumps(rows)
    assert notices['LICENSE']=='source license'
    assert '/blob/'+ 'a'*40 in rows[0]['source_url']

def test_unsafe_yaml_rejected():
    raw=io.BytesIO()
    with zipfile.ZipFile(raw,'w') as z:
        z.writestr('root/LICENSE','source license')
        z.writestr('root/yml/Test.yml','!!python/object/apply:os.system [echo unsafe]')
    with pytest.raises(Exception):knowledge.parse_archive('lolbas',raw.getvalue(),'a'*40)

@pytest.mark.asyncio
async def test_password_only_discloses_prefix(monkeypatch):
    calls=[];digest='ABCDE'+'F'*35
    async def request(method,url,**kwargs):
        calls.append((url,kwargs));return {'status':'success','data':'F'*35+':27\n'+'0'*35+':0'}
    monkeypatch.setattr(identity,'request',request)
    result=await identity.password_check_sha1(digest)
    assert result['occurrences']==27
    assert calls[0][0].endswith('/ABCDE')
    assert digest not in json.dumps(calls)
    assert calls[0][1]['headers']['Add-Padding']=='true'

@pytest.mark.asyncio
async def test_identity_disclosure_and_credential_projection(monkeypatch):
    assert (await identity.check_breach('a@example.com'))['status']=='disabled'
    monkeypatch.setenv('ENABLE_IDENTITY_LOOKUPS','true')
    assert (await identity.check_breach('a@example.com'))['status']=='requires_consent'
    monkeypatch.setenv('HUDSONROCK_API_KEY','offline')
    async def request(*args,**kwargs):return {'status':'success','data':{'data':[{'stealer_family':'example','credentials':[{'password':'never-return'}],'date_compromised':'2026-01-01'}]}}
    monkeypatch.setattr(identity,'request',request)
    result=await identity.check_breach('a@example.com','hudsonrock',True)
    assert result['exposures'][0]['stealer_family']=='example'
    assert 'never-return' not in json.dumps(result)

def test_secret_query_and_email_log_redaction():
    record=logging.LogRecord('httpx',20,'',1,'HTTP %s',('https://pulsedive.com/api/indicator.php?key=secret-value&indicator=x',),None)
    RedactQueryCredentials().filter(record)
    assert 'secret-value' not in record.getMessage()
    record=logging.LogRecord('httpx',20,'',1,'GET https://haveibeenpwned.com/api/v3/breachedaccount/private%40example.com',(),None)
    RedactQueryCredentials().filter(record)
    assert 'private' not in record.getMessage()

@pytest.mark.asyncio
async def test_context_provider_not_threat_verdict(monkeypatch):
    async def request(*args,**kwargs):return {'status':'success','data':{'ip':'8.8.8.8','ports':[443],'vulns':['CVE-2024-1234']}}
    monkeypatch.setattr(extended,'request',request)
    result=await extended.lookup('8.8.8.8','ip',{'_provider':'shodan_internetdb'})
    from app.services.correlation import correlate
    analysis=correlate([{'provider':'shodan_internetdb',**result}],'8.8.8.8')
    assert not analysis['evidence']
    assert analysis['assessment']=='informational'

@pytest.mark.asyncio
async def test_bulk_dedup_and_refang(monkeypatch):
    seen=[]
    async def enrich(value):seen.append(value);return {'indicator':value,'status':'completed'}
    monkeypatch.setattr(investigation,'enrich_indicator_all',enrich)
    await investigation.bulk_lookup(['hxxps://example[.]com/a','hxxps://example[.]com/a'])
    assert seen==['https://example.com/a']
    assert (await investigation.bulk_lookup(['x']*21))['status']=='invalid_parameter'

@pytest.mark.asyncio
async def test_mcp_no_approval_tool_and_no_submission_on_request(monkeypatch):
    from fastmcp import Client
    from app.main import mcp
    monkeypatch.setenv('ENABLE_SUBMISSIONS','false')
    async with Client(mcp) as client:
        names={t.name for t in await client.list_tools()}
        assert {'request_url_analysis','lookup_cve','search_reference','bulk_lookup_iocs'}<=names
        assert not any('approve' in n or 'execute' in n for n in names)
        result=await client.call_tool('request_url_analysis',{'url':'https://example.com/'})
        assert result.data['status']=='disabled'

@pytest.mark.asyncio
async def test_internal_dns_never_disclosed(monkeypatch):
    async def forbidden(*args,**kwargs):raise AssertionError('must not call external DNS')
    monkeypatch.setattr(extended,'request',forbidden)
    assert (await extended.dns_query('host.internal'))['status']=='invalid_indicator'

@pytest.mark.asyncio
async def test_cve_sources_keep_probability_severity_and_exploitation_distinct(monkeypatch):
    from app.services import vulnerabilities as v
    store.upsert_records('feed:cisa_kev',[{'id':'cve','kind':'cve','value':'CVE-2024-12345','data':{'cveID':'CVE-2024-12345'},'source_url':'https://www.cisa.gov/'}])
    async def request(method,url,**kwargs):
        if 'first.org' in url:return {'status':'success','data':{'data':[{'cve':'CVE-2024-12345','epss':'0.001'}]}}
        return {'status':'success','data':{'vulnerabilities':[{'cve':{'id':'CVE-2024-12345','metrics':{'cvssMetricV31':[{'cvssData':{'baseScore':9.8}}]},'descriptions':[{'lang':'en','value':'Reference vulnerability'}]}}]}}
    monkeypatch.setattr(v,'request',request)
    result=await v.lookup_cve('CVE-2024-12345')
    assert result['known_exploited'] is True
    assert next(r for r in result['sources'] if r['provider']=='epss')['estimates'][0]['epss']=='0.001'
    assert (await v.lookup_cve('not-a-cve'))['status']=='invalid_indicator'

@pytest.mark.asyncio
async def test_pivots_only_observed_bounded_depth(monkeypatch):
    seen=[]
    async def enrich(value):
        seen.append(value)
        return {'status':'completed','indicator':value,'related_indicators':[
            {'type':'ip','value':'8.8.8.8','inferred':False,'providers':['urlscan']},
            {'type':'ip','value':'127.0.0.1','inferred':False},
            {'type':'ip','value':'1.1.1.1','inferred':True}]}
    monkeypatch.setattr(investigation,'enrich_indicator_all',enrich)
    result=await investigation.investigate('example.com',3)
    assert seen==['example.com','8.8.8.8']
    assert result['limits']['depth']==1

def test_oidc_fails_closed_without_configuration(monkeypatch):
    from app.auth.factory import build_auth
    monkeypatch.setenv('MCP_AUTH_MODE','oidc')
    monkeypatch.setenv('OIDC_CONFIG_URL','')
    with pytest.raises(ValueError,match='incomplete'):build_auth()

def test_agent_output_hard_bound_and_truncation_visible():
    from app.services.projection import compact_result
    result=compact_result({'status':'success','records':[{'description':'x'*20000}]*200})
    assert result['output_truncated'] is True
    assert len(json.dumps(result))<=28000

@pytest.mark.asyncio
async def test_all_expanded_tool_schemas_and_dataset_missing(monkeypatch):
    from fastmcp import Client
    from app.main import mcp
    async with Client(mcp) as client:
        tools={t.name:t for t in await client.list_tools()}
        assert tools['lookup_cve'].input_schema['properties']['cve_id']['type']=='string'
        assert tools['bulk_lookup_iocs'].input_schema['properties']['indicators']['type']=='array'
        result=await client.call_tool('search_reference',{'corpus':'sigma','query':'powershell'})
        assert result.data['status']=='dataset_missing'


def test_local_source_aliases_do_not_create_false_empty_results():
    from app.services.local_search import search_local
    store.upsert_records('feed:threatfox',[{'id':'demo','kind':'ip','value':'124.221.142.210','data':{'malware_printable':'example'}}])
    for source in ('threatfox','ThreatFox','feed:threatfox'):
        result=search_local('124.221.142.210',source)
        assert result['source_filter']=='feed:threatfox'
        assert len(result['records'])==1
    assert search_local('124.221.142.210','misspelled-source')['status']=='invalid_parameter'


def test_storage_derivation_survives_branding_changes(monkeypatch):
    """Records encrypted by earlier releases must remain readable."""
    from cryptography.fernet import Fernet
    monkeypatch.setenv('INTEL_STORAGE_KEY', '')
    monkeypatch.setenv('JWT_SECRET_KEY', 'offline-only-test-secret-which-is-long-enough')
    historical_cipher = Fernet(b'fYBBMiBoIMPHh6IpkVon9pi8FVZI2cSuCSeoQwxag7U=')
    payload = historical_cipher.encrypt(b'{"existing_record":true}')
    assert store.unseal(payload) == {'existing_record': True}
    assert json.loads(historical_cipher.decrypt(store.seal({'new_record': True}))) == {'new_record': True}
