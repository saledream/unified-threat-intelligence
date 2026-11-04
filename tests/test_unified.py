"""Offline orchestrator tests exercise actual routing; never call providers."""
import asyncio
from dataclasses import replace
from unittest.mock import AsyncMock
import pytest
from app.services import unified
from app.services.registry import CAPABILITIES, Capability

@pytest.fixture
def routed(monkeypatch):
    monkeypatch.setattr(unified, 'load_overrides', lambda: {})
    monkeypatch.setattr(Capability, 'policy_status', lambda self, overrides=None: 'configured')
    monkeypatch.setattr(unified, 'CAPABILITIES', tuple(replace(c, min_interval_seconds=0, retries=0) for c in CAPABILITIES))
    fake = AsyncMock(return_value={'status': 'not_found'})
    monkeypatch.setattr(unified, '_lookup', fake)
    return fake

@pytest.mark.parametrize('value,kind', [('8.8.8.8','ip'), ('2606:4700:4700::1111','ip'),
    ('example.org','domain'), ('www.example.org','domain'), ('https://example.org/a','url'),
    ('http://example.org/a','url'), ('a'*32,'hash'), ('b'*40,'hash'), ('c'*64,'hash')])
def test_detection(value,kind):
    assert unified.detect_indicator(value) == kind

@pytest.mark.asyncio
async def test_private_ip_is_blocked(routed):
    result = await unified.enrich_indicator_all('127.0.0.1')
    assert result['status'] == 'blocked'
    routed.assert_not_awaited()

@pytest.mark.asyncio
async def test_disabled_provider_is_not_queried_or_counted(routed, monkeypatch):
    monkeypatch.setattr(Capability, 'policy_status', lambda self, overrides=None: 'disabled' if self.name == 'shodan' else 'configured')
    result = await unified.enrich_indicator_all('8.8.8.8')
    assert not any(call.args[0] == 'shodan' for call in routed.await_args_list)
    assert not any(row['provider'] == 'shodan' for row in result['provider_results'])
    assert {'provider': 'shodan', 'status': 'disabled'} in result['providers_skipped']

@pytest.mark.asyncio
async def test_partial_failure_is_not_clean(routed):
    async def fake(name, value, kind, meta):
        if name == 'otx':
            raise TimeoutError()
        return {'status':'not_found'}
    routed.side_effect = fake
    result = await unified.enrich_indicator_all('8.8.8.8')
    assert result['status'] == 'partial'
    assert result['assessment'] == 'inconclusive'
    assert len(result['provider_results']) == len([c for c in unified.CAPABILITIES if 'ip' in c.types])
    assert result['providers_checked'] == len([c for c in unified.CAPABILITIES if 'ip' in c.types])-1

@pytest.mark.asyncio
async def test_url_queries_both_representations(routed):
    result = await unified.enrich_indicator_all('HTTPS://Example.ORG:443/a?x=1')
    calls = {(c.args[0], c.args[1], c.args[2]) for c in routed.await_args_list}
    for name in ('otx','threatfox','urlscan','virustotal'):
        assert (name,'https://example.org/a?x=1','url') in calls
        assert (name,'example.org','domain') in calls
    assert not any(name == 'rdap' for name, _, _ in calls)
    assert not any(name in ('abuseipdb','greynoise') for name,_,_ in calls)
    assert result['normalized_representations']['domain'] == 'example.org'

@pytest.mark.asyncio
async def test_url_public_ip_literal_routes_ip_without_dns(routed):
    await unified.enrich_indicator_all('https://8.8.8.8/a')
    assert any(c.args[:3] == ('abuseipdb','8.8.8.8','ip') for c in routed.await_args_list)

@pytest.mark.asyncio
@pytest.mark.parametrize('size', [32,40,64])
async def test_hash_routing_obeys_algorithms(routed,size):
    result = await unified.enrich_indicator_all('a'*size)
    queried = {c.args[0] for c in routed.await_args_list}
    assert queried == ({'malwarebazaar','otx','virustotal','local_feeds'} | ({'threatfox'} if size!=40 else set()))
    if size == 40:
        assert next(r for r in result['provider_results'] if r['provider']=='threatfox')['status']=='unsupported_indicator_type'

@pytest.mark.asyncio
async def test_unconfigured_and_disabled_do_not_call_adapters(monkeypatch):
    monkeypatch.setattr(unified, 'load_overrides', lambda: {c.name:False for c in CAPABILITIES})
    fake=AsyncMock()
    monkeypatch.setattr(unified, '_lookup',fake)
    result=await unified.enrich_indicator_all('8.8.8.8')
    fake.assert_not_awaited()
    assert result['providers_checked']==0
    assert result['assessment']=='inconclusive'

@pytest.mark.asyncio
async def test_provider_calls_are_concurrent(routed):
    entered=set()
    gate=asyncio.Event()
    async def fake(name,*args):
        entered.add(name)
        if len(entered)>=8:gate.set()
        await asyncio.wait_for(gate.wait(),.5)
        return {'status':'not_found'}
    routed.side_effect=fake
    result=await unified.enrich_indicator_all('8.8.8.8')
    assert len(entered)==len([c for c in unified.CAPABILITIES if 'ip' in c.types])
    assert result['status']=='completed'

@pytest.mark.asyncio
async def test_policy_store_failure_fails_closed(monkeypatch):
    def fail():raise RuntimeError('database unavailable')
    monkeypatch.setattr(unified,'load_overrides',fail)
    fake=AsyncMock();monkeypatch.setattr(unified,'_lookup',fake)
    assert (await unified.enrich_indicator_all('example.org'))['status']=='blocked'
    fake.assert_not_awaited()

async def test_ipv6_skips_ipv4_only_community_adapter(routed):
    result=await unified.enrich_indicator_all('2606:4700:4700::1111')
    assert not any(c.args[0]=='greynoise' for c in routed.await_args_list)
    assert next(r for r in result['provider_results'] if r['provider']=='greynoise')['status']=='unsupported_indicator_type'
    assert result['providers_eligible']==len([c for c in unified.CAPABILITIES if 'ip' in c.types and 6 in c.ip_versions])

async def test_ip_port_context_is_never_sent_as_ip_report_input(routed):
    result=await unified.enrich_indicator_all('124.221.142.210:443')
    assert result['indicator']=='124.221.142.210:443'
    assert result['normalized_representations']=={'ip':'124.221.142.210','port':'443'}
    assert all(c.args[1]=='124.221.142.210' and c.args[2]=='ip' for c in routed.await_args_list)
