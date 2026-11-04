"""Shared passive IOC orchestration for REST and MCP."""
import asyncio
import re
from datetime import datetime, timezone
from ipaddress import ip_address
from uuid import uuid4
from app.services.indicators import validate_indicator, parse_ip_endpoint
from app.services.correlation import correlate, FAILURES
from app.services.registry import CAPABILITIES, Capability, lookup, load_overrides
from app.services.provider_runtime import execute
from app.services.contracts import IntelligenceReport


def detect_indicator(value: str) -> str | None:
    if not isinstance(value, str) or len(value) > 4096:
        return None
    value = value.strip()
    try:
        parse_ip_endpoint(value)
        return 'ip'
    except ValueError:
        pass
    if re.fullmatch(r'(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})', value):
        return 'hash'
    if value.lower().startswith(('https://', 'http://')):
        return 'url'
    return 'domain' if value and '://' not in value else None


async def _lookup(name, value, kind, meta):
    cap = next(c for c in CAPABILITIES if c.name == name)
    return await lookup(cap, value, kind, meta)


async def enrich_indicator_all(indicator: str) -> dict:
    request_id = str(uuid4())
    base = {'schema_version': '1.0', 'indicator': indicator, 'request_id': request_id,
            'generated_at': datetime.now(timezone.utc).isoformat()}
    kind = detect_indicator(indicator)
    if kind is None:
        return {**base, 'status': 'invalid_indicator', 'error': 'Unrecognized indicator'}
    validation = validate_indicator(indicator, kind)
    if not validation.get('valid'):
        return {**base, 'indicator_type': kind, 'status': 'invalid_indicator', 'error': validation.get('error')}
    if not validation.get('external_lookup_allowed'):
        return {**base, 'indicator_type': kind, 'status': 'blocked', 'error': 'External lookup prohibited'}
    normalized = validation['indicator']
    try:
        overrides = await asyncio.wait_for(asyncio.to_thread(load_overrides), timeout=7)
    except Exception:
        return {**base, 'status': 'blocked', 'error': 'Provider policy unavailable; no external lookup performed'}
    reps, metas = {kind: normalized}, {kind: validation}
    if validation.get('port') is not None:
        reps['port'] = str(validation['port'])
    if kind == 'url':
        host = validation['hostname']
        hostkind = 'ip' if ':' in host or re.fullmatch(r'[0-9.]+', host) else 'domain'
        hc = validate_indicator(host, hostkind)
        if hc.get('valid') and hc.get('external_lookup_allowed'):
            reps[hostkind], metas[hostkind] = hc['indicator'], hc
    jobs, skipped = [], []
    for cap in CAPABILITIES:
        if cap.policy_status(overrides) == 'disabled':
            skipped.append({'provider': cap.name, 'status': 'disabled'})
            continue
        applicable = [(t, v) for t, v in reps.items() if t in cap.types]
        if not applicable:
            skipped.append({'provider': cap.name, 'status': 'unsupported_indicator_type'})
        for qtype, value in applicable:
            jobs.append((cap, value, qtype, metas[qtype]))

    async def run(cap, value, qtype, meta):
        policy = cap.policy_status(overrides)
        common = {'provider': cap.name, 'source_reliability': cap.reliability,
                  'provenance_group': cap.provenance_group or cap.name,
                  'query_indicator': value, 'query_type': qtype}
        if qtype == 'ip' and meta.get('ip_version') not in cap.ip_versions:
            return {**common, 'status': 'unsupported_indicator_type', 'reason': 'IP version unsupported by provider'}
        if qtype == 'hash' and meta['hash_type'] not in cap.hash_types:
            return {**common, 'status': 'unsupported_indicator_type', 'reason': 'Hash algorithm unsupported by provider'}
        if policy != 'configured':
            return {**common, 'status': policy}
        result = await execute(cap, value, qtype, meta, _lookup)
        return {**result, **common}

    # Provider locks/HTTP deadlines bound each call; this deadline also bounds queueing.
    tasks = [asyncio.create_task(run(*job)) for job in jobs]
    done, pending = await asyncio.wait(tasks, timeout=55) if tasks else (set(), set())
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    results = []
    for task, (cap, value, qtype, _) in zip(tasks, jobs):
        if task in done:
            results.append(task.result())
        else:
            results.append({'provider': cap.name, 'query_indicator': value, 'query_type': qtype,
                            'status': 'timeout', 'reason': 'Overall search deadline'})
    analysis = correlate(results, normalized)
    unavailable = {'not_configured', 'requires_authorization', 'disabled', 'skipped'}
    completed = [r for r in results if r['status'] in ('success', 'not_found', 'no_result')]
    report = {**base, 'indicator_type': kind,
            'indicator_subtype': validation.get('hash_type') or (f"ipv{validation['ip_version']}" if kind == 'ip' else kind),
            'normalized_representations': reps,
            'status': 'partial' if any(r['status'] in FAILURES or r['status'] in unavailable for r in results) else 'completed',
            **analysis, 'providers_checked': len({r['provider'] for r in completed}),
            'providers_eligible': len({r['provider'] for r in results if r['status'] != 'unsupported_indicator_type'}),
            'providers_matched': len({e['provider'] for e in analysis['evidence']}),
            'lookups_completed': len(completed), 'provider_results': results, 'providers_skipped': skipped,
            'recommended_steps': ['Correlate source evidence with Wazuh/Graylog telemetry and asset context.',
                                  'Review dates, coverage gaps and source references before deciding on action.']}
    return IntelligenceReport.model_validate(report).model_dump(exclude_none=True)


def agent_summary(result: dict) -> dict:
    """Compact projection only; no independent intelligence decisions."""
    keys = ('schema_version', 'indicator', 'indicator_type', 'indicator_subtype', 'request_id', 'generated_at', 'status',
            'error', 'normalized_representations', 'assessment', 'assessment_reason', 'evidence',
            'correlation', 'providers_checked', 'providers_matched', 'providers_eligible',
            'provider_coverage', 'context','related_indicators', 'limitations', 'recommended_steps')
    out = {k: result[k] for k in keys if k in result}
    out['provider_lookups'] = [{k: r[k] for k in ('provider', 'query_type', 'status', 'cached', 'retrieved_at', 'reason') if k in r}
                              for r in result.get('provider_results', [])]
    return out
