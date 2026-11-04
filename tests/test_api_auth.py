"""Public search API contract: no login, account management, or submission approval."""
import pytest
from fastapi.testclient import TestClient
from app.api.main import app
from app.services import unified

@pytest.fixture
def client():
    # Test the installed host middleware with its default localhost origin.
    with TestClient(app,base_url='http://localhost') as client:
        yield client

def test_search_without_credentials(client,monkeypatch):
    async def enrich(indicator):
        return {'indicator':indicator,'status':'success','provider_results':[]}
    monkeypatch.setattr(unified,'enrich_indicator_all',enrich)
    response=client.post('/api/enrichment/unified',json={'indicator':'8.8.8.8'})
    assert response.status_code==200
    assert response.json()['indicator']=='8.8.8.8'
    assert 'www-authenticate' not in response.headers

def test_private_indicator_remains_blocked(client):
    assert client.post('/api/enrichment/unified',json={'indicator':'127.0.0.1'}).json()['status']=='blocked'

def test_empty_and_oversized_search_rejected(client):
    for value in ('','a'*4097):
        assert client.post('/api/enrichment/unified',json={'indicator':value}).status_code==422

def test_no_account_or_submission_endpoints(client):
    for path in ('/api/auth/me','/api/auth/users','/api/audit/events','/api/submissions'):
        assert client.get(path).status_code==404
    assert client.post('/api/auth/login',json={}).status_code==404
    assert client.post('/api/submissions/url',json={}).status_code==404

def test_health_and_provider_configuration_are_public(client):
    assert client.get('/api/health').status_code==200
    response=client.get('/api/providers/status')
    assert response.status_code==200
    assert 'virustotal' in response.json()
