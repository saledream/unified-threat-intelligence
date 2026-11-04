"""Bounded per-process provider execution, cache and quota protection.
No raw IOC persistence. Each API/MCP worker has an independent budget.
"""
import asyncio
import hashlib
import json
import time
import weakref
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

STATES = weakref.WeakKeyDictionary()
RETRYABLE = {'timeout', 'connection_error', 'provider_error'}
CACHEABLE = {'success', 'not_found', 'no_result'}


def state():
    loop = asyncio.get_running_loop()
    if loop not in STATES:
        STATES[loop] = {'cache': OrderedDict(), 'locks': {}, 'next': {}, 'health': {}, 'cooldown': {}, 'semaphore': asyncio.Semaphore(8)}
    return STATES[loop]


def retry_delay(value):
    try:
        return min(3600, max(1, float(value)))
    except (ValueError, TypeError):
        try:
            return min(3600, max(1, (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()))
        except (ValueError, TypeError, OverflowError):
            return 60


async def execute(cap, value, kind, meta, operation):
    s = state()
    # Include policy configuration fingerprint so rotating keys cannot reuse prior credentials' results.
    import os
    config = [os.getenv(cap.credential_env, ''), os.getenv(cap.authorization_env, ''),
              os.getenv('VIRUSTOTAL_USAGE_MODE', 'commercial'),os.getenv('ABUSECH_USAGE_MODE','commercial'),
              os.getenv('INTEL_USAGE_MODE','commercial'),*[os.getenv(k,'') for k in cap.required_envs],
              os.getenv('CENSYS_ORG_ID',''),os.getenv('CENSYS_SEARCH_AUTHORIZED','')]
    key = hashlib.sha256(json.dumps([cap.name, value, kind, meta, config]).encode()).hexdigest()
    lock = s['locks'].setdefault(cap.name, asyncio.Lock())
    async with lock:
        now = time.monotonic()
        for old in list(s['cache']):
            if s['cache'][old][0] <= now:
                del s['cache'][old]
        cached = s['cache'].get(key)
        if cached:
            return {**deepcopy(cached[1]), 'cached': True}
        persistent = os.getenv('INTEL_PERSIST_CACHE','false').lower()=='true'
        if persistent:
            try:
                from app.services.intel_store import cache_get
                saved=await asyncio.wait_for(asyncio.to_thread(cache_get,key),timeout=3)
                if saved is not None:return {**saved,'cached':True,'cache_scope':'persistent'}
            except Exception:
                pass
        if s['cooldown'].get(cap.name, 0) > now:
            return {'status': 'rate_limited', 'retry_after': round(s['cooldown'][cap.name] - now, 1), 'reason': 'Provider cooldown'}
        await asyncio.sleep(max(0, s['next'].get(cap.name, 0) - now))
        started = time.monotonic()
        async def attempts():
            result = {}
            for attempt in range(cap.retries + 1):
                if attempt:
                    await asyncio.sleep(0.25 * (2 ** (attempt - 1)))
                result = await operation(cap.name, value, kind, meta)
                if not isinstance(result, dict):
                    return {'status': 'invalid_response'}
                if result.get('status') not in RETRYABLE or result.get('http_status', 503) < 500:
                    break
            return result
        try:
            async with s['semaphore']:
                result = await asyncio.wait_for(attempts(), cap.timeout_seconds)
        except (asyncio.TimeoutError, TimeoutError):
            result = {'status': 'timeout'}
        except Exception:
            result = {'status': 'internal_error', 'error': 'Provider lookup failed'}
        result = {**result, 'cached': False, 'retrieved_at': datetime.now(timezone.utc).isoformat(),
                  'duration_ms': round((time.monotonic() - started) * 1000)}
        s['next'][cap.name] = time.monotonic() + cap.min_interval_seconds
        if result.get('status') == 'rate_limited':
            s['cooldown'][cap.name] = time.monotonic() + retry_delay(result.get('retry_after'))
        s['health'][cap.name] = {k: result[k] for k in ('status', 'retrieved_at', 'duration_ms')}
        if result.get('status') in CACHEABLE:
            s['cache'][key] = (time.monotonic() + cap.cache_ttl_seconds, deepcopy(result))
            if persistent:
                try:
                    from app.services.intel_store import cache_put
                    await asyncio.wait_for(asyncio.to_thread(cache_put,key,result,cap.cache_ttl_seconds),timeout=3)
                except Exception:
                    result['cache_warning']='Persistent cache unavailable; result retained in this worker only'
            while len(s['cache']) > 512:
                s['cache'].popitem(last=False)
        return result
