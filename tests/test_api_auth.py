"""SQLite-backed API contract tests; PostgreSQL deployment tested separately."""
import os
import secrets
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

@pytest.fixture
def platform(monkeypatch):
    for key in ('POSTGRES_DB','POSTGRES_USER','POSTGRES_PASSWORD'):
        monkeypatch.setenv(key,'offline-test')
    monkeypatch.setenv('JWT_SECRET_KEY',secrets.token_hex(32))
    monkeypatch.setenv('ALLOWED_HOSTS','testserver,localhost')
    from app import database
    from app import models
    from app.auth.security import hash_password
    from app.api.main import app
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    database.Base.metadata.create_all(engine)
    sessions=sessionmaker(engine,expire_on_commit=False)
    monkeypatch.setattr(database,'SessionLocal',sessions)
    monkeypatch.setattr(database,'engine',engine)
    with sessions() as db:
        for role in ('admin','analyst','viewer'):
            db.add(models.User(username=role,password_hash=hash_password('offline-password-123!'),role=role,is_active=True,token_version=0))
        db.commit()
    with TestClient(app) as client:
        def login(role):
            response=client.post('/api/auth/login',json={'username':role,'password':'offline-password-123!'})
            assert response.status_code==200, response.text
            return {'Authorization':'Bearer '+response.json()['access_token']}
        yield client,sessions,login
    engine.dispose()


def test_auth_roles_and_revocation(platform):
    client,sessions,login=platform
    assert client.post('/api/enrichment/unified',json={'indicator':'8.8.8.8'}).status_code==401
    viewer=login('viewer')
    assert client.post('/api/enrichment/unified',headers=viewer,json={'indicator':'8.8.8.8'}).status_code==403
    assert client.get('/api/auth/users',headers=viewer).status_code==403
    analyst=login('analyst')
    assert client.get('/api/providers/registry',headers=analyst).status_code==403
    assert client.post('/api/enrichment/unified',headers=analyst,json={'indicator':'127.0.0.1'}).json()['status']=='blocked'
    assert client.post('/api/auth/logout',headers=analyst).status_code==200
    assert client.get('/api/auth/me',headers=analyst).status_code==401

def test_human_approval_requires_admin_password_and_exact_digest(platform,monkeypatch):
    from app.services import submissions
    client,_,login=platform
    monkeypatch.setenv('ENABLE_SUBMISSIONS','true')
    monkeypatch.setenv('VIRUSTOTAL_USAGE_MODE','personal')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','offline')
    analyst=login('analyst');admin=login('admin');viewer=login('viewer')
    calls=[]
    async def send(payload):
        calls.append(payload);return {'status':'submitted','provider':'virustotal','receipt':'offline-receipt'}
    monkeypatch.setattr(submissions,'_send',send)
    row=client.post('/api/submissions/url',headers=analyst,json={'url':'https://example.com/'}).json()
    assert row['status']=='pending' and not calls
    decision={'digest':row['digest'],'password':'offline-password-123!','approve':True,'acknowledge_disclosure':True}
    endpoint='/api/submissions/'+row['id']+'/decision'
    assert client.post(endpoint,headers=analyst,json=decision).status_code==403
    assert client.post(endpoint,headers=viewer,json=decision).status_code==403
    assert client.post(endpoint,headers=admin,json={**decision,'password':'wrong'}).status_code==401
    assert client.post(endpoint,headers=admin,json={**decision,'acknowledge_disclosure':False}).status_code==400
    assert not calls
    assert client.post(endpoint,headers=admin,json=decision).json()['status']=='submitted'
    assert client.post(endpoint,headers=admin,json=decision).json()['status']=='conflict'
    assert len(calls)==1

def test_file_request_raw_bytes_not_server_path(platform,monkeypatch):
    client,_,login=platform
    monkeypatch.setenv('ENABLE_SUBMISSIONS','true')
    monkeypatch.setenv('VIRUSTOTAL_USAGE_MODE','personal')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','offline')
    headers={**login('analyst'),'Content-Type':'application/octet-stream','X-Filename':'test.txt'}
    row=client.post('/api/submissions/file',headers=headers,content=b'offline harmless test').json()
    assert row['status']=='pending'
    assert row['submission']['size']==21
    assert 'content_b64' not in row['submission']
    assert client.post('/api/submissions/file',headers=login('analyst'),json={'path':'C:/secret'}).status_code==415


def test_admin_provider_policy_is_persisted_and_audited(platform,monkeypatch):
    client,sessions,login=platform
    admin=login('admin')
    response=client.patch('/api/providers/otx',headers=admin,json={'enabled':False})
    assert response.status_code==200
    rows=client.get('/api/providers/registry',headers=admin).json()['providers']
    assert next(r for r in rows if r['name']=='otx')['status']=='disabled'
    from app.services.registry import load_overrides
    assert load_overrides()['otx'] is False
    events=client.get('/api/audit/events',headers=admin).json()['events']
    assert any(e['action']=='provider.otx.disable' for e in events)
    assert client.patch('/api/providers/unknown',headers=admin,json={'enabled':False}).status_code==404


def test_admin_role_changes_revoke_existing_tokens(platform):
    client,sessions,login=platform
    admin,analyst=login('admin'),login('analyst')
    users=client.get('/api/auth/users',headers=admin).json()
    uid=next(u['id'] for u in users if u['username']=='analyst')
    assert client.patch(f'/api/auth/users/{uid}/role',headers=admin,json={'role':'viewer'}).status_code==200
    assert client.get('/api/auth/me',headers=analyst).status_code==401


def test_audit_uses_keyed_digests_and_does_not_store_ioc(platform):
    client,sessions,login=platform
    headers=login('analyst')
    client.post('/api/enrichment/unified',headers=headers,json={'indicator':'127.0.0.1'})
    from app.models import AuditEvent
    import hashlib
    with sessions() as db:
        event=db.scalar(select(AuditEvent).where(AuditEvent.action=='enrichment.unified'))
        assert event.indicator_digest != hashlib.sha256(b'127.0.0.1').hexdigest()
        assert len(event.indicator_digest)==64


def test_login_lockout(platform):
    client,_,_=platform
    for _ in range(5):
        assert client.post('/api/auth/login',json={'username':'analyst','password':'incorrect-password!'}).status_code==401
    response=client.post('/api/auth/login',json={'username':'analyst','password':'offline-password-123!'})
    assert response.status_code==429


def test_missing_mitre_dataset_is_clear(platform,monkeypatch,tmp_path):
    from app.services import mitre_attack
    monkeypatch.setattr(mitre_attack,'DATASET',tmp_path/'missing.json')
    mitre_attack.load_attack_data.cache_clear()
    client,_,login=platform
    result=client.get('/api/mitre/search?query=credential',headers=login('viewer'))
    assert result.status_code==503


async def test_mcp_http_requires_revocable_analyst_identity(platform):
    client,sessions,login=platform
    from app.auth.mcp import PlatformTokenVerifier
    verifier=PlatformTokenVerifier()
    assert await verifier.verify_token('invalid') is None
    viewer=login('viewer')['Authorization'][7:]
    assert await verifier.verify_token(viewer) is None
    analyst=login('analyst')['Authorization'][7:]
    token=await verifier.verify_token(analyst)
    assert token is not None and token.scopes==['intel:read']
    client.post('/api/auth/logout',headers={'Authorization':'Bearer '+analyst})
    assert await verifier.verify_token(analyst) is None
    from fastmcp import FastMCP
    from app.auth.factory import build_auth
    authenticated_mcp=FastMCP('platform authentication test',auth=build_auth())
    with TestClient(authenticated_mcp.http_app()) as mc:
        assert mc.post('/mcp',json={'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}}).status_code==401
