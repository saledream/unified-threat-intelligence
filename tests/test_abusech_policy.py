from app.providers.abusech_policy import authorized
from app.services.registry import CAPABILITIES

def test_personal_abusech_mode_does_not_need_commercial_flag(monkeypatch):
    monkeypatch.setenv('ABUSECH_USAGE_MODE','personal')
    monkeypatch.setenv('ABUSECH_COMMERCIAL_AUTHORIZED','false')
    monkeypatch.setenv('ABUSECH_API_KEY','synthetic-offline-key')
    assert authorized()
    assert next(c for c in CAPABILITIES if c.name=='threatfox').policy_status()=='configured'

def test_personal_abusech_missing_key_is_reported_honestly(monkeypatch):
    monkeypatch.setenv('ABUSECH_USAGE_MODE','personal')
    assert next(c for c in CAPABILITIES if c.name=='threatfox').policy_status()=='not_configured'

def test_business_abusech_gate_preserved(monkeypatch):
    monkeypatch.setenv('ABUSECH_USAGE_MODE','commercial')
    assert not authorized()
