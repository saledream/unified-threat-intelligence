import pytest
from app.providers import shodan
from app.services.registry import CAPABILITIES

@pytest.mark.asyncio
async def test_host_report_passive_bounded_projection(monkeypatch):
    monkeypatch.setenv('SHODAN_API_KEY','offline-key')
    seen=[]
    async def request(method,url,**kwargs):
        seen.append((method,url,kwargs))
        return {'status':'success','data':{'ip_str':'8.8.8.8','ports':[53],'last_update':'2026-01-01',
            'vulns':{'CVE-2024-12345':{}},'data':[{'port':53,'product':'DNS','data':'raw banner omitted'}]*31}}
    monkeypatch.setattr(shodan,'request',request)
    result=await shodan.check_host('8.8.8.8')
    assert seen[0][0]=='GET' and seen[0][1]=='https://api.shodan.io/shodan/host/8.8.8.8'
    assert seen[0][2]['params']=={'key':'offline-key','history':'false','minify':'false'}
    assert len(result['services'])==30 and result['services_truncated'] is True
    assert 'data' not in result['services'][0]
    assert 'last_seen' not in result
    from app.services.correlation import correlate
    report=correlate([{'provider':'shodan',**result}],'8.8.8.8')
    assert report['assessment']=='informational' and not report['evidence']

@pytest.mark.asyncio
async def test_missing_key_and_private_ip_never_call_provider(monkeypatch):
    async def forbidden(*args,**kwargs):raise AssertionError('No external call expected')
    monkeypatch.setattr(shodan,'request',forbidden)
    assert (await shodan.check_host('8.8.8.8'))['status']=='not_configured'
    monkeypatch.setenv('SHODAN_API_KEY','offline')
    assert (await shodan.check_host('127.0.0.1'))['status']=='blocked'

@pytest.mark.asyncio
async def test_forbidden_is_not_clean_or_keyless_fallback(monkeypatch):
    monkeypatch.setenv('SHODAN_API_KEY','offline')
    async def request(*args,**kwargs):return {'status':'forbidden','http_status':403}
    monkeypatch.setattr(shodan,'request',request)
    result=await shodan.check_host('8.8.8.8')
    assert result['status']=='forbidden' and result['http_status']==403
    assert 'InternetDB' in result['reason']

def test_authenticated_and_keyless_capabilities_separate(monkeypatch):
    auth=next(c for c in CAPABILITIES if c.name=='shodan')
    free=next(c for c in CAPABILITIES if c.name=='shodan_internetdb')
    assert auth.policy_status()=='not_configured'
    assert auth.provenance_group==free.provenance_group=='shodan'
    monkeypatch.setenv('SHODAN_API_KEY','offline')
    assert auth.policy_status()=='configured'
    monkeypatch.setenv('PROVIDER_SHODAN_ENABLED','false')
    assert auth.policy_status()=='disabled'

@pytest.mark.asyncio
async def test_shodan_mcp_tool_uses_shared_policy():
    from fastmcp import Client
    from app.main import mcp
    async with Client(mcp) as client:
        names={t.name for t in await client.list_tools()}
        assert 'shodan_host_lookup' in names
        result=await client.call_tool('shodan_host_lookup',{'ip':'127.0.0.1'})
        assert result.data['status']=='blocked'
