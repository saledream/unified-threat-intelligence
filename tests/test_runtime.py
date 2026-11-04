import asyncio
from dataclasses import replace
from unittest.mock import AsyncMock
from app.services.provider_runtime import execute
from app.services.registry import CAPABILITIES

async def test_cache_and_concurrent_duplicate_requests_share_one_call():
    cap=replace(CAPABILITIES[0],min_interval_seconds=0)
    op=AsyncMock(return_value={'status':'not_found'})
    results=await asyncio.gather(*(execute(cap,'8.8.8.8','ip',{},op) for _ in range(3)))
    assert op.await_count==1
    assert sum(r['cached'] for r in results)==2

async def test_rate_limit_cooldown_avoids_additional_requests():
    cap=replace(CAPABILITIES[0],min_interval_seconds=0)
    op=AsyncMock(return_value={'status':'rate_limited','retry_after':'900'})
    await execute(cap,'8.8.8.8','ip',{},op)
    result=await execute(cap,'1.1.1.1','ip',{},op)
    assert result['status']=='rate_limited'
    assert op.await_count==1

async def test_transient_failure_retries_boundedly_and_is_not_cached():
    cap=replace(CAPABILITIES[0],min_interval_seconds=0)
    op=AsyncMock(return_value={'status':'connection_error'})
    assert (await execute(cap,'8.8.8.8','ip',{},op))['status']=='connection_error'
    assert op.await_count==2

async def test_deadline_isolates_slow_provider():
    cap=replace(CAPABILITIES[0],timeout_seconds=.01,min_interval_seconds=0)
    async def slow(*args):await asyncio.sleep(1)
    assert (await execute(cap,'8.8.8.8','ip',{},slow))['status']=='timeout'
