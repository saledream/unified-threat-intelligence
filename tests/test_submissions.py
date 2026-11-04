import asyncio
import pytest
from app.services import submissions as s
from app.services import intel_store as store

@pytest.fixture(autouse=True)
def isolated(monkeypatch,tmp_path):
    monkeypatch.setenv('INTEL_STATE_DB',str(tmp_path/'intel.db'))
    monkeypatch.setenv('JWT_SECRET_KEY','offline-only-test-secret-which-is-long-enough')
    monkeypatch.setenv('ENABLE_SUBMISSIONS','true')
    monkeypatch.setenv('VIRUSTOTAL_USAGE_MODE','personal')
    monkeypatch.setenv('VIRUSTOTAL_API_KEY','test-secret-key')

def test_no_submission_on_request_encrypted_owner_bound():
    r=s.request_file('7',b'private sample bytes','../../sample.exe')
    assert r['status']=='pending'
    assert r['submission']['sha256']
    assert 'content_b64' not in r['submission']
    assert '/' not in r['submission']['filename']
    assert s.get_request(r['id'],'8')=={'status':'not_found'}
    with store.connection() as db:
        raw=db.execute('SELECT payload FROM approvals').fetchone()[0]
        assert b'private sample bytes' not in raw
        assert b'content_b64' not in raw

@pytest.mark.asyncio
async def test_atomic_approval_and_digest_binding(monkeypatch):
    r=s.request_url('7','https://example.com/a')
    calls=[]
    async def send(payload):
        calls.append(payload)
        await asyncio.sleep(.02)
        return {'status':'submitted','provider':'virustotal','receipt':'abc'}
    monkeypatch.setattr(s,'_send',send)
    assert (await s.approve_and_execute(r['id'],'1','0'*64))['status']=='conflict'
    results=await asyncio.gather(*(s.approve_and_execute(r['id'],'1',r['digest']) for _ in range(2)))
    assert sorted(x['status'] for x in results)==['conflict','submitted']
    assert len(calls)==1

@pytest.mark.asyncio
async def test_uncertain_execution_never_retries(monkeypatch):
    r=s.request_url('7','https://example.com/a')
    async def send(payload):raise OSError('interrupted after provider acceptance')
    monkeypatch.setattr(s,'_send',send)
    assert (await s.approve_and_execute(r['id'],'1',r['digest']))['status']=='uncertain'
    assert (await s.approve_and_execute(r['id'],'1',r['digest']))['status']=='conflict'

@pytest.mark.asyncio
async def test_expired_and_rejected_never_execute(monkeypatch):
    r=s.request_file('7',b'secret','file')
    with store.connection() as db:db.execute('UPDATE approvals SET expires=0')
    assert s.get_request(r['id'],'7')['status']=='expired'
    assert (await s.approve_and_execute(r['id'],'1',r['digest']))['status']=='conflict'
    r=s.request_url('7','https://example.com/a')
    assert s.reject(r['id'],'1',r['digest'])['status']=='rejected'
    assert (await s.approve_and_execute(r['id'],'1',r['digest']))['status']=='conflict'

def test_validation_limits_and_disable(monkeypatch):
    assert s.request_url('7','http://127.0.0.1/')['status']=='invalid_indicator'
    assert s.request_file('7',b'','test')['status']=='invalid_file'
    for _ in range(5):assert s.request_url('7','https://example.com/')['status']=='pending'
    assert s.request_url('7','https://example.com/')['status']=='rate_limited'
    monkeypatch.setenv('ENABLE_SUBMISSIONS','false')
    assert s.request_url('8','https://example.com/')['status']=='disabled'

@pytest.mark.asyncio
async def test_contract_uses_exact_approved_url_and_visibility(monkeypatch):
    monkeypatch.setenv('URLSCAN_API_KEY','offline')
    calls=[]
    async def request(method,url,**kwargs):
        calls.append((method,url,kwargs))
        return {'status':'success','data':{'uuid':'test-id'}}
    monkeypatch.setattr(s,'request',request)
    r=s.request_url('7','https://example.com/path?q=1','urlscan')
    result=await s.approve_and_execute(r['id'],'1',r['digest'])
    assert result['status']=='submitted'
    assert calls[0][2]['json']=={'url':'https://example.com/path?q=1','visibility':'unlisted'}
