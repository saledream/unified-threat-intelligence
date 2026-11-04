"""Personal Public API policy and persisted request quota regressions."""
import pytest
from app.providers import virustotal
from app.services.registry import CAPABILITIES
from app.services import virustotal_quota as quota

@pytest.fixture(autouse=True)
def isolated_quota(monkeypatch,tmp_path):
    monkeypatch.setenv('VIRUSTOTAL_QUOTA_DB',str(tmp_path/'quota.sqlite3'))

async def test_personal_mode_with_no_key_is_not_configured(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_USAGE_MODE','personal')
    monkeypatch.delenv('VIRUSTOTAL_API_KEY',raising=False)
    monkeypatch.setenv('VIRUSTOTAL_COMMERCIAL_AUTHORIZED','false')
    assert (await virustotal.lookup('8.8.8.8','ip'))['status']=='not_configured'
    cap=next(c for c in CAPABILITIES if c.name=='virustotal')
    assert cap.policy_status()=='not_configured'

@pytest.mark.parametrize('mode',['commercial','unknown',''])
async def test_personal_permission_does_not_enable_business_or_unknown_modes(monkeypatch,mode):
    monkeypatch.setenv('VIRUSTOTAL_USAGE_MODE',mode)
    monkeypatch.setenv('VIRUSTOTAL_COMMERCIAL_AUTHORIZED','false')
    assert not virustotal.authorized()
    assert (await virustotal.lookup('8.8.8.8','ip'))['status']=='requires_authorization'

def test_minute_limit_is_persistent_and_key_is_not_stored(monkeypatch):
    monkeypatch.setattr(quota.time,'time',lambda:1000000)
    for _ in range(4):assert quota.reserve_public_request('synthetic-test-key') is None
    assert quota.reserve_public_request('synthetic-test-key')['status']=='rate_limited'
    from pathlib import Path
    import os
    assert b'synthetic-test-key' not in Path(os.environ['VIRUSTOTAL_QUOTA_DB']).read_bytes()

def test_daily_limit_survives_separate_connections(monkeypatch):
    now=1000000
    for i in range(500):
        monkeypatch.setattr(quota.time,'time',lambda i=i:now+i*121)
        assert quota.reserve_public_request('synthetic-test-key') is None
    monkeypatch.setattr(quota.time,'time',lambda:now+500*121)
    result=quota.reserve_public_request('synthetic-test-key')
    assert result['status']=='rate_limited' and result['retry_after']>60

def test_quota_store_failure_fails_closed(monkeypatch,tmp_path):
    invalid=tmp_path/'file';invalid.write_text('not a directory')
    monkeypatch.setenv('VIRUSTOTAL_QUOTA_DB',str(invalid/'quota.sqlite3'))
    assert quota.reserve_public_request('synthetic-test-key')['status']=='blocked'
