"""Provider request contracts use HTTPX MockTransport, never external calls."""
import json
from unittest.mock import AsyncMock
import httpx
import pytest
from app.providers import threatfox, otx, urlscan, virustotal, rdap

@pytest.fixture
def mock_http(monkeypatch):
    requests=[]
    responses=[]
    original=httpx.AsyncClient
    def handler(request):
        requests.append(request)
        status,payload,headers=responses.pop(0)
        return httpx.Response(status,json=payload,headers=headers)
    monkeypatch.setattr(httpx,'AsyncClient',lambda **kwargs: original(**{**kwargs,'transport':httpx.MockTransport(handler),'trust_env':False}))
    return requests,responses

@pytest.mark.parametrize('size',[32,64])
async def test_threatfox_hash_contract(monkeypatch,mock_http,size):
    req,res=mock_http
    monkeypatch.setenv('ABUSECH_API_KEY','offline-test')
    monkeypatch.setenv('ABUSECH_COMMERCIAL_AUTHORIZED','true')
    res.append((200,{'query_status':'no_result'},{}))
    assert (await threatfox.search_ioc('a'*size))['status']=='not_found'
    assert json.loads(req[0].content)=={'query':'search_hash','hash':'a'*size}
    assert req[0].method=='POST'

async def test_threatfox_sha1_not_sent(monkeypatch,mock_http):
    req,_=mock_http
    monkeypatch.setenv('ABUSECH_COMMERCIAL_AUTHORIZED','true')
    assert (await threatfox.search_ioc('a'*40))['status']=='unsupported_indicator_type'
    assert not req

async def test_otx_url_is_encoded_as_one_observable(monkeypatch,mock_http):
    req,res=mock_http
    monkeypatch.setenv('OTX_API_KEY','offline-test')
    res.append((200,{'pulse_info':{'count':0,'pulses':[]}},{}))
    result=await otx.lookup('https://example.org/a?x=1','url')
    assert result['status']=='success'
    assert b'https%3A%2F%2Fexample.org%2Fa%3Fx%3D1' in req[0].url.raw_path

async def test_urlscan_is_historical_get_not_submission(mock_http):
    req,res=mock_http
    res.append((200,{'results':[]},{}))
    assert (await urlscan.search_history('example.org','domain'))['status']=='not_found'
    assert req[0].method=='GET' and req[0].url.path=='/api/v1/search/'
    assert req[0].url.params['q']=='page.domain.keyword:"example.org"'

async def test_virustotal_existing_url_report_only(monkeypatch,mock_http):
    req,res=mock_http
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','offline-test')
    monkeypatch.setenv('VIRUSTOTAL_COMMERCIAL_AUTHORIZED','true')
    res.append((404,{},{}))
    assert (await virustotal.lookup('https://example.org/a','url'))['status']=='not_found'
    assert req[0].method=='GET' and req[0].url.path.startswith('/api/v3/urls/')

async def test_rdap_pins_public_destination_and_preserves_tls_host(monkeypatch,mock_http):
    req,res=mock_http
    async def unused():pass
    monkeypatch.setattr(rdap.socket,'getaddrinfo',lambda *a,**kw:[(2,1,6,'',('8.8.8.8',443))])
    res.append((200,{'handle':'test'},{}))
    await rdap.safe_get('https://rdap.provider.org/domain/example.org')
    assert req[0].url.host=='8.8.8.8'
    assert req[0].headers['Host']=='rdap.provider.org'
    assert req[0].extensions['sni_hostname']=='rdap.provider.org'

async def test_rdap_rebinding_private_answer_is_rejected(monkeypatch,mock_http):
    req,_=mock_http
    monkeypatch.setattr(rdap.socket,'getaddrinfo',lambda *a,**kw:[(2,1,6,'',('127.0.0.1',443))])
    with pytest.raises(ValueError):
        await rdap.safe_get('https://rdap.provider.org/domain/example.org')
    assert not req

async def test_rdap_referral_is_not_followed(monkeypatch):
    import time
    monkeypatch.setattr(rdap,'_bootstrap',{'services':[[['org'],['https://rdap.provider.org/']]]})
    monkeypatch.setattr(rdap,'_bootstrap_until',time.monotonic()+3600)
    get=AsyncMock(return_value=httpx.Response(302,headers={'Location':'http://127.0.0.1/'}))
    monkeypatch.setattr(rdap,'safe_get',get)
    assert (await rdap.lookup_domain('example.org'))['status']=='skipped'
    assert get.await_count==1

async def test_personal_mode_uses_public_report_endpoint_without_commercial_flag(monkeypatch,mock_http,tmp_path):
    req,res=mock_http
    monkeypatch.setenv('VIRUSTOTAL_USAGE_MODE','personal')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','offline-test')
    monkeypatch.setenv('VIRUSTOTAL_COMMERCIAL_AUTHORIZED','false')
    monkeypatch.setenv('VIRUSTOTAL_QUOTA_DB',str(tmp_path/'quota.sqlite3'))
    res.append((200,{'data':{'type':'ip_address','id':'8.8.8.8','attributes':{'last_analysis_stats':{'malicious':0,'suspicious':0}}}},{}))
    result=await virustotal.lookup('8.8.8.8','ip')
    assert result['status']=='success'
    assert req[0].method=='GET' and req[0].url.path=='/api/v3/ip_addresses/8.8.8.8'
