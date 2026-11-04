"""Offline tests for evidence-based intelligence assessment."""
from app.services.correlation import correlate

def test_feed_first_seen_is_not_promoted_to_last_seen():
    result=correlate([{'provider':'local_feeds','status':'success','feed_matches':[
        {'source':'feed:threatfox','value':'8.8.8.8','observed':'2026-11-04 00:20:12 UTC',
         'data':{'first_seen':'2026-11-04 00:20:12 UTC','last_seen':None,'malware_printable':'Example','threat_type':'botnet_cc'}}]}],'8.8.8.8')
    evidence=result['evidence'][0]
    assert evidence['first_seen']=='2026-11-04 00:20:12 UTC'
    assert 'last_seen' not in evidence
    assert evidence['malware']=='Example'


def test_feed_match_is_suspicious_not_proven_malicious():
    # A threat feed match is evidence, not proof of compromise.
    result = correlate([{'provider': 'threatfox', 'status': 'success', 'indicators': [
        {'ioc': 'example.org', 'threat_type': 'botnet_cc', 'malware': 'Example'}]}])
    assert result['assessment'] == 'suspicious'
    assert len(result['evidence']) == 1


def test_duplicate_records_are_collapsed():
    # Duplicate records from one provider must not inflate evidence counts.
    record = {'ioc': 'example.org', 'threat_type': 'botnet_cc', 'malware': 'Example'}
    result = correlate([{'provider': 'threatfox', 'status': 'success', 'indicators': [record, record]}])
    assert len(result['evidence']) == 1


def test_failure_is_inconclusive():
    # A timeout cannot be interpreted as a clean lookup.
    assert correlate([{'provider': 'otx', 'status': 'timeout'}])['assessment'] == 'inconclusive'


def test_no_match_is_not_safe_verdict():
    # No match is explicitly qualified and never labeled safe.
    result = correlate([{'provider': 'threatfox', 'status': 'not_found'}])
    assert result['assessment'] == 'no_known_malicious_activity_found'
    assert 'not proof of safety' in ' '.join(result['limitations'])

def test_shared_feed_ownership_does_not_establish_independence():
    from app.services.correlation import correlate
    results = [
        {"provider":"threatfox","status":"success","source_reliability":"high","indicators":[{"ioc":"evil.example","threat_type":"botnet_cc","malware":"X","last_seen":"2026-11-01T00:00:00Z"}]},
        {"provider":"malwarebazaar","status":"success","source_reliability":"high","sha256_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature":"X","first_seen":"2026-11-02T00:00:00Z"},
    ]
    out=correlate(results,"evil.example")
    assert out["assessment"] == "suspicious"
    assert out["correlation"]["independent_providers_with_evidence"] is None
    assert {g["provenance_group"] for g in out["correlation"]["provenance_groups"]} == {"abusech"}

def test_prose_does_not_invent_ioc_relationships():
    from app.services.correlation import correlate
    results=[{"provider":"otx","status":"success","source_reliability":"medium","pulse_count":1,"pulses":[{"name":"See https://evil.example/a and 8.8.8.8"}]}]
    out=correlate(results,"seed.example")
    values={x["value"] for x in out["related_indicators"]}
    assert not values


def test_malformed_provider_scalar_is_not_a_clean_result():
    source={'provider':'abuseipdb','status':'success','abuse_confidence_score':'unexpected','total_reports':1}
    result=correlate([source,{'provider':'otx','status':'not_found'}])
    assert source['status']=='invalid_response'
    assert result['assessment']=='inconclusive'
    assert result['provider_coverage']['invalid_response']==1
