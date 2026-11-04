import os
import pytest
from app.providers import virustotal
from app.services.unified import CAPABILITIES

@pytest.mark.asyncio
async def test_virustotal_requires_explicit_commercial_authorization(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_COMMERCIAL_AUTHORIZED", raising=False)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "do-not-use")
    out=await virustotal.lookup("example.com","domain")
    assert out["status"] == "requires_authorization"

def test_registry_contains_phase3_sources():
    names={c.name for c in CAPABILITIES}
    assert {"rdap","urlscan","virustotal"} <= names
    otx=next(c for c in CAPABILITIES if c.name=="otx")
    assert set(otx.types)=={"ip","domain","url","hash"}
