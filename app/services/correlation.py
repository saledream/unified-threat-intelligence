"""Conservative evidence correlation. Provider count is not independence."""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from app.services.indicators import validate_indicator

FAILURES = frozenset({'timeout', 'internal_error', 'provider_error', 'invalid_response',
    'rate_limited', 'unauthorized', 'forbidden', 'not_configured', 'blocked',
    'connection_error', 'invalid_indicator', 'invalid_parameter', 'requires_authorization', 'disabled'})


def _age(ts):
    if ts is None:
        return None
    try:
        if isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(ts, timezone.utc)
        else:
            dt = datetime.fromisoformat(str(ts).replace(' UTC', '+00:00').replace('Z', '+00:00'))
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        days = (datetime.now(timezone.utc) - dt).days
        if days < 0:
            return {'days': days, 'band': 'future_unverified'}
        return {'days': days, 'band': 'recent' if days <= 30 else 'current' if days <= 180 else 'historical'}
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def _related(results, primary):
    """Only explicit IOC fields establish observed relationships; never scan prose/links."""
    found = {}
    def add(value, kind, provider):
        if not isinstance(value, str):
            return
        check = validate_indicator(value, kind)
        if not check.get('valid') or not check.get('external_lookup_allowed'):
            return
        value = check['indicator']
        if value == primary:
            return
        item = found.setdefault((kind, value), {'type': kind, 'value': value,
            'relationship': 'returned_in_source_record', 'inferred': False, 'providers': set()})
        item['providers'].add(provider)
    for r in results:
        if r.get('status') != 'success':
            continue
        p = r['provider']
        for address in (r.get('addresses') or []):add(address,'ip',p)
        for hostname in (r.get('hostnames') or []):add(hostname,'domain',p)
        for key in ('sha256_hash', 'sha1_hash', 'md5_hash'):
            add(r.get(key), 'hash', p)
        for row in (r.get('historical_scans') or []):
            for key, kind in (('url', 'url'), ('domain', 'domain'), ('ip', 'ip')):
                add(row.get(key), kind, p)
        for row in (r.get('indicators') or []):
            kind = {'domain': 'domain', 'url': 'url', 'md5_hash': 'hash', 'sha256_hash': 'hash'}.get(row.get('ioc_type'))
            if kind:
                add(row.get('ioc'), kind, p)
        for row in (r.get('payloads') or []):
            for key in ('response_md5', 'response_sha256'):
                add(row.get(key), 'hash', p)
    return [{**item, 'providers': sorted(item['providers'])} for item in list(found.values())[:50]]


def correlate(results, primary_indicator=''):
    evidence, coverage, context, conflicts = [], Counter(), [], []
    for r in results:
        numeric = ('abuse_confidence_score', 'total_reports', 'pulse_count', 'historical_count', 'malicious', 'suspicious')
        records = ('indicators', 'historical_scans', 'payloads')
        malformed = any(r.get(k) is not None and (isinstance(r[k], bool) or not isinstance(r[k], (int, float))) for k in numeric)
        malformed |= any(r.get(k) is not None and (not isinstance(r[k], list) or any(not isinstance(x, dict) for x in r[k])) for k in records)
        if r.get('status') == 'success' and malformed:
            r.update(status='invalid_response', error='Provider returned malformed evidence fields')
        p, status = r.get('provider', 'unknown'), r.get('status', 'unknown')
        coverage[status] += 1
        if status != 'success':
            continue
        common = {'provider': p, 'query_indicator': r.get('query_indicator', primary_indicator),
                  'query_type': r.get('query_type'), 'source_reliability': r.get('source_reliability', 'medium'),
                  'provenance_group': r.get('provenance_group', 'abusech' if p in ('threatfox', 'urlhaus', 'malwarebazaar') else p)}
        rows = []
        if p == 'threatfox':
            for rec in (r.get('indicators') or []):
                rows.append({'kind': 'threat_feed_match', 'indicator': rec.get('ioc'),
                    'classification': rec.get('threat_type'), 'malware': rec.get('malware_printable') or rec.get('malware'),
                    'confidence': rec.get('confidence_level'), 'first_seen': rec.get('first_seen'),
                    'last_seen': rec.get('last_seen'), 'reference': rec.get('reference'), 'record_id': rec.get('id')})
        elif p == 'malwarebazaar' and r.get('sha256_hash'):
            rows.append({'kind': 'malware_sample_match', 'indicator': r['sha256_hash'], 'malware': r.get('signature'),
                         'first_seen': r.get('first_seen'), 'last_seen': r.get('last_seen')})
        elif p == 'urlhaus' and r.get('queried_url'):
            rows.append({'kind': 'malicious_url_feed_match', 'indicator': r['queried_url'],
                         'classification': r.get('threat'), 'first_seen': r.get('date_added'), 'last_seen': r.get('last_online')})
        elif p == 'abuseipdb' and (r.get('abuse_confidence_score') or 0) >= 50 and (r.get('total_reports') or 0) > 0:
            rows.append({'kind': 'abuse_reports', 'confidence': r['abuse_confidence_score'],
                         'report_count': r['total_reports'], 'last_seen': r.get('last_reported_at')})
        elif p == 'greynoise':
            if r.get('classification') == 'malicious':
                rows.append({'kind': 'scanner_classification', 'classification': 'malicious',
                             'last_seen': r.get('last_seen'), 'reference': r.get('link')})
            elif r.get('classification') == 'benign' or r.get('riot'):
                context.append({**common, 'kind': 'benign_context', 'reference': r.get('link')})
        elif p == 'otx' and (r.get('pulse_count') or 0) > 0:
            # Association and pulse modification date are not an IOC observation/verdict.
            context.append({**common, 'kind': 'pulse_association', 'count': r['pulse_count']})
        elif p in ('urlscan','cloudflare_urlscanner'):
            for rec in (r.get('historical_scans') or []):
                if rec.get('malicious') is True:
                    rows.append({'kind': 'historical_scan_verdict', 'indicator': rec.get('url'),
                                 'last_seen': rec.get('scan_time'), 'reference': rec.get('result_url')})
            if not rows and r.get('historical_count', 0):
                context.append({**common, 'kind': 'historical_scan_context', 'count': r['historical_count']})
        elif p == 'virustotal' and ((r.get('malicious') or 0) > 0 or (r.get('suspicious') or 0) > 0):
            rows.append({'kind': 'multi_engine_detection', 'malicious': r.get('malicious'),
                         'suspicious': r.get('suspicious'), 'analysis_at':r.get('analysis_at'), 'last_seen': r.get('last_seen'), 'reference': r.get('source_url')})
        elif p == 'pulsedive':
            risk=r.get('risk')
            if isinstance(risk,str) and risk.lower() in ('high','critical'):
                rows.append({'kind':'source_risk_assessment','classification':risk.lower(),'reference':r.get('source_url')})
            else:context.append({**common,'kind':'source_risk_context','risk':risk})
        elif p == 'local_feeds':
            for match in (r.get('feed_matches') or []):
                source=match.get('source','')
                if source not in ('feed:feodo','feed:sslbl_ip','feed:threatfox','feed:urlhaus','feed:malwarebazaar','feed:openphish'):
                    context.append({**common,'kind':'feed_association','source':source});continue
                data=match.get('data') or {}
                rows.append({'kind':'local_feed_match','indicator':match.get('value'),'reference':match.get('source_url'),
                    'classification':data.get('threat_type') or source,
                    'malware':data.get('malware_printable') or data.get('malware') or data.get('signature'),
                    'first_seen':data.get('first_seen'),'last_seen':data.get('last_seen') or data.get('last_online'),
                    'feed_observed_at':match.get('observed'),'feed_retrieved_at':match.get('retrieved')})
        elif p in ('shodan','shodan_internetdb','ipinfo','spur','censys','certificate_transparency','dns_doh','cloudflare_radar'):
            context.append({**common,'kind':'passive_asset_context','reference':r.get('source_url'),
                'note':r.get('interpretation_note')})
        for row in rows:
            ev = {**common, **{k: v for k, v in row.items() if v is not None}}
            ev['recency'] = _age(ev.get('last_seen') or ev.get('first_seen'))
            # Collapse identical evidence from multiple representations of the same provider.
            fingerprint = (p, ev.get('kind'), ev.get('indicator') or common['query_indicator'],
                           ev.get('classification'), ev.get('malware'), ev.get('reference'),
                           ev.get('first_seen'), ev.get('last_seen'))
            ev['_fingerprint'] = fingerprint
            if not any(e['_fingerprint'] == fingerprint for e in evidence):
                evidence.append(ev)
    groups = []
    for ev in evidence:
        ev.pop('_fingerprint', None)
        ref = ev.get('reference')
        group = next((g for g in groups if ref and g.get('reference') == ref), None)
        if group is None:
            groups.append({'reference': ref, 'providers': [ev['provider']], 'provenance_group': ev['provenance_group']})
        elif ev['provider'] not in group['providers']:
            group['providers'].append(ev['provider'])
    if evidence and any(c['kind'] == 'benign_context' for c in context):
        conflicts.append('Threat evidence coexists with benign service context; review dates, assets and query scope.')
    malware, classes = defaultdict(set), defaultdict(set)
    for ev in evidence:
        if isinstance(ev.get('malware'), str):
            malware[ev['malware']].add(ev['provider'])
        if ev.get('classification'):
            classes[str(ev['classification'])].add(ev['provider'])
    if evidence:
        assessment = 'suspicious'
        reason = 'Source-backed threat evidence requires investigation. Upstream independence is unverified; provider count alone cannot establish maliciousness.'
    elif any(r.get('status') not in ('success', 'not_found', 'no_result', 'unsupported_indicator_type') for r in results) or not results:
        assessment, reason = 'inconclusive', 'Coverage gaps prevent a complete assessment; no actionable threat evidence returned.'
    elif context:
        assessment, reason = 'informational', 'Only contextual records returned; registration, scan history and pulse associations do not establish maliciousness.'
    else:
        assessment, reason = 'no_known_malicious_activity_found', 'No actionable threat evidence returned by the completed lookups; this does not establish safety.'
    return {'assessment': assessment, 'assessment_reason': reason, 'evidence': evidence,
            'context': context, 'related_indicators': _related(results, primary_indicator),
            'correlation': {'independent_providers_with_evidence': None,
                'distinct_providers_with_evidence': len({e['provider'] for e in evidence}),
                'provenance_groups': groups, 'conflicts': conflicts,
                'malware_families': {k: sorted(v) for k, v in malware.items()},
                'classifications': {k: sorted(v) for k, v in classes.items()}},
            'provider_coverage': dict(coverage),
            'limitations': ['A provider match is evidence, not proof of internal compromise.',
                'First-seen dates establish a first observation only, not current activity. Do not label a host active C2 or invent detection totals without explicit current source evidence.',
                'Provider count is not proof of independent observations; shared references are grouped.',
                'No match is not proof of safety; provider failures are not clean results.',
                'Source confidence is not system confidence. Missing observation dates remain unknown.',
                'IOC lookups do not connect to targets. Optional DNS queries disclose the hostname to the resolver. Configure internal DNS suffixes before use.']}
