import pytest
from app.services import cloudflare_radar as radar
from app.providers import extended

@pytest.fixture
def calls(monkeypatch):
    monkeypatch.setenv('CLOUDFLARE_API_TOKEN','offline')
    monkeypatch.setenv('CLOUDFLARE_ACCOUNT_ID','')
    monkeypatch.setattr('app.services.registry.load_overrides',lambda:{})
    seen=[]
    async def request(method,url,**kwargs):
        seen.append((method,url,kwargs))
        data={'meta':{'normalization':'PERCENTAGE','units':[{'name':'value','value':'%'}]},'summary_0':{'example':'10'}}
        if '/ranking/domain/' in url:data={'details_0':{'bucket':'1000','categories':[]},'meta':{}}
        if '/entities/asns/ip' in url:data={'asn':{'asn':45090,'name':'TENCENT-NET-AP'}}
        return {'status':'success','data':{'success':True,'result':data},'source_url':url}
    monkeypatch.setattr(radar,'request',request)
    return seen

@pytest.mark.asyncio
async def test_asn_and_domain_rank_accountless(calls):
    assert (await radar.asn_lookup('124.221.142.210'))['data']['asn']['asn']==45090
    result=await radar.domain_rank('cloudflare.com')
    assert result['rank_details']['bucket']=='1000'
    assert 'rank' not in result['rank_details']
    assert not any('/accounts/' in url for _,url,_ in calls)

@pytest.mark.asyncio
@pytest.mark.parametrize('layer,dimension,view,path',[
    ('layer3','VECTOR','summary','attacks/layer3/summary/VECTOR'),
    ('layer3','PROTOCOL','timeseries','attacks/layer3/timeseries_groups/PROTOCOL'),
    ('layer7','HTTP_METHOD','summary','attacks/layer7/summary/HTTP_METHOD'),
])
async def test_ddos_contract_and_metadata(calls,layer,dimension,view,path):
    result=await radar.ddos_trends(layer,dimension,view,7,'CN')
    assert calls[0][1].endswith(path)
    assert calls[0][2]['params']['dateRange']=='7d'
    assert calls[0][2]['params']['location']=='CN'
    assert result['data']['meta']['normalization']=='PERCENTAGE'
    assert 'assessment' not in result

@pytest.mark.asyncio
async def test_email_metrics_are_aggregate(calls):
    result=await radar.email_security('THREAT_CATEGORY','timeseries',14)
    assert calls[0][1].endswith('email/security/timeseries_groups/THREAT_CATEGORY')
    assert result['scope']['dataset']=='aggregate_email_security'
    assert 'assessment' not in result

@pytest.mark.asyncio
async def test_invalid_input_never_reaches_provider(calls):
    assert (await radar.asn_lookup('127.0.0.1'))['status']=='blocked'
    assert (await radar.domain_rank('internal.local'))['status']=='blocked'
    assert (await radar.ddos_trends(dimension='../../accounts'))['status']=='invalid_parameter'
    assert (await radar.ddos_trends(days=10000))['status']=='invalid_parameter'
    assert (await radar.ddos_trends(location='CN&token=leak'))['status']=='invalid_parameter'
    assert (await radar.email_security('not-a-dimension'))['status']=='invalid_parameter'
    assert not calls

@pytest.mark.asyncio
async def test_provider_policy_applies(calls,monkeypatch):
    monkeypatch.setenv('PROVIDER_CLOUDFLARE_RADAR_ENABLED','false')
    assert (await radar.ddos_trends())['status']=='disabled'
    assert not calls

@pytest.mark.asyncio
async def test_domain_ranking_routes_through_unified_capability(calls):
    result=await extended.lookup('cloudflare.com','domain',{'_provider':'cloudflare_radar'})
    assert result['status']=='success'
    assert calls[0][1].endswith('/ranking/domain/cloudflare.com')
