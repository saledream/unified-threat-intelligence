"""Encrypted, expiring, exactly-once human approval for external submissions.

Only the human-facing REST interface can approve. An MCP request is never approval.
An interrupted/uncertain execution is deliberately not retried automatically.
"""
import asyncio
import base64
import hashlib
import json
import os
import re
import time
import uuid
from app.services import intel_store as store
from app.services.indicators import validate_indicator
from app.providers.http import request

MAX_FILE_BYTES = 16 * 1024 * 1024
DISCLOSURE = {
    'virustotal': 'The URL or complete file is disclosed to VirusTotal and may be shared with its security partners. Standard submissions are not confidential.',
    'urlscan': 'The provider will visit the URL. Unlisted scans remain accessible to vetted urlscan Pro researchers and companies; unlisted is not private.',
    'cloudflare': 'Cloudflare will visit the URL. An unlisted report is excluded from search but accessible to anyone with its scan ID.',
}

def enabled():
    return os.getenv('ENABLE_SUBMISSIONS','false').lower() == 'true'

def provider_policy(provider):
    if provider not in DISCLOSURE:return {'status':'invalid_provider'}
    if not enabled():return {'status':'disabled','reason':'Submission workflows are disabled'}
    from app.services.registry import CAPABILITIES, load_overrides
    name = 'cloudflare_urlscanner' if provider == 'cloudflare' else provider
    cap=next(c for c in CAPABILITIES if c.name==name)
    status=cap.policy_status(load_overrides())
    if status!='configured':return {'status':status}
    if provider=='urlscan' and not os.getenv('URLSCAN_API_KEY'):return {'status':'not_configured'}
    return None

def _digest(payload):
    return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def _expire(db):
    # Erase encrypted sample bytes after expiry or an abandoned process. Never replay.
    db.execute("UPDATE approvals SET status='expired', payload=? WHERE status='pending' AND expires<=?",(store.seal({}),time.time()))
    db.execute("UPDATE approvals SET status='uncertain', payload=? WHERE status='executing' AND expires+300<=?",(store.seal({}),time.time()))
    db.execute('DELETE FROM approvals WHERE created<?',(time.time()-30*86400,))

def cleanup():
    with store.connection() as db:_expire(db)

async def cleanup_forever():
    while True:
        try:await asyncio.to_thread(cleanup)
        except Exception:pass  # Missing storage never authorizes a submission.
        await asyncio.sleep(60)

def _insert(requester,provider,payload):
    error=provider_policy(provider)
    if error:return error
    payload={**payload,'provider':provider,'visibility':'standard' if provider=='virustotal' else 'unlisted'}
    ident=str(uuid.uuid4()); now=time.time()
    with store.connection() as db:
        db.execute('BEGIN IMMEDIATE')
        _expire(db)
        if db.execute("SELECT COUNT(*) FROM approvals WHERE status='pending' AND requester=?",(requester,)).fetchone()[0]>=5:
            return {'status':'rate_limited','reason':'At most five pending submissions per requester'}
        if db.execute("SELECT COUNT(*) FROM approvals WHERE status IN ('pending','executing')").fetchone()[0]>=25:
            return {'status':'rate_limited','reason':'Approval queue is full'}
        db.execute('INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?)',
            (ident,requester,payload['kind'],'pending',store.seal(payload),now,now+900,None,None,_digest(payload)))
    return get_request(ident,requester)

def request_url(requester,url,provider='virustotal'):
    check=validate_indicator(url,'url')
    if not check.get('valid') or not check.get('external_lookup_allowed'):
        return {'status':'invalid_indicator','validation':check}
    return _insert(requester,provider,{'kind':'url','url':check['indicator']})

def request_file(requester,content,filename):
    if not content or len(content)>MAX_FILE_BYTES:return {'status':'invalid_file','reason':'File must contain 1 byte to 16 MiB'}
    # Filename is display-only. It is never interpreted as a server path.
    name=re.sub(r'[^A-Za-z0-9._ -]','_',filename or 'sample')[-120:]
    return _insert(requester,'virustotal',{'kind':'file','filename':name,'size':len(content),
        'sha256':hashlib.sha256(content).hexdigest(),'content_b64':base64.b64encode(content).decode()})

def _public(row):
    payload=store.unseal(row['payload'])
    payload.pop('content_b64',None)
    result=store.unseal(row['result']) if row['result'] else None
    return {'id':row['id'],'requester':row['requester'],'status':row['status'],'operation':row['operation'],
        'created':row['created'],'expires':row['expires'],'approved_by':row['approved_by'],
        'digest':row['digest'],'submission':payload,'disclosure':DISCLOSURE.get(payload.get('provider')),'result':result}

def list_requests(requester=None):
    with store.connection() as db:
        _expire(db)
        rows=db.execute('SELECT * FROM approvals '+('WHERE requester=? ' if requester else '')+'ORDER BY created DESC LIMIT 50',
            (requester,) if requester else ()).fetchall()
        return {'status':'success','requests':[_public(r) for r in rows]}

def get_request(ident,requester=None):
    with store.connection() as db:
        _expire(db)
        row=db.execute('SELECT * FROM approvals WHERE id=?',(ident,)).fetchone()
        if not row or (requester and row['requester']!=requester):return {'status':'not_found'}
        return _public(row)

def reject(ident,reviewer,digest):
    with store.connection() as db:
        _expire(db)
        count=db.execute("UPDATE approvals SET status='rejected', approved_by=?, payload=? WHERE id=? AND digest=? AND status='pending'",
            (reviewer,store.seal({}),ident,digest)).rowcount
    return {'status':'rejected' if count else 'conflict'}

def _claim(ident,reviewer,digest):
    with store.connection() as db:
        db.execute('BEGIN IMMEDIATE')
        _expire(db)
        row=db.execute('SELECT * FROM approvals WHERE id=? AND digest=?',(ident,digest)).fetchone()
        if not row or row['status']!='pending':return None,{'status':'conflict'}
        payload=store.unseal(row['payload'])
        if _digest(payload)!=row['digest']:return None,{'status':'integrity_error'}
        policy=provider_policy(payload['provider'])
        if policy:return None,policy
        db.execute("UPDATE approvals SET status='executing',approved_by=? WHERE id=? AND status='pending'",(reviewer,ident))
        return payload,None

async def _vt_quota():
    from app.providers.virustotal import usage_mode
    if usage_mode()=='personal':
        from app.services.virustotal_quota import reserve_public_request
        return await asyncio.to_thread(reserve_public_request,os.environ['VIRUSTOTAL_API_KEY'])

async def _send(payload):
    provider=payload['provider']
    if provider=='virustotal':
        quota=await _vt_quota()
        if quota:return quota
        headers={'x-apikey':os.environ['VIRUSTOTAL_API_KEY']}
        if payload['kind']=='file':
            r=await request('POST','https://www.virustotal.com/api/v3/files',headers=headers,
                files={'file':(payload['filename'],base64.b64decode(payload['content_b64']),'application/octet-stream')},timeout=45)
        else:r=await request('POST','https://www.virustotal.com/api/v3/urls',headers=headers,data={'url':payload['url']},timeout=30)
        receipt=(r.get('data') or {}).get('data',{}).get('id') if r.get('status')=='success' else None
    elif provider=='urlscan':
        r=await request('POST','https://urlscan.io/api/v1/scan/',headers={'api-key':os.environ['URLSCAN_API_KEY']},
            json={'url':payload['url'],'visibility':'unlisted'},timeout=30)
        receipt=(r.get('data') or {}).get('uuid') if r.get('status')=='success' else None
    else:
        account=os.environ.get('CLOUDFLARE_ACCOUNT_ID','')
        if not re.fullmatch(r'[a-fA-F0-9]{32}',account):return {'status':'not_configured'}
        r=await request('POST',f'https://api.cloudflare.com/client/v4/accounts/{account}/urlscanner/v2/scan',
            headers={'Authorization':'Bearer '+os.environ['CLOUDFLARE_API_TOKEN']},
            json={'url':payload['url'],'visibility':'Unlisted'},timeout=30)
        receipt=((r.get('data') or {}).get('result') or {}).get('uuid') if r.get('status')=='success' else None
    if receipt and isinstance(receipt,str) and re.fullmatch(r'[A-Za-z0-9_=-]{1,512}',receipt):
        return {'status':'submitted','provider':provider,'receipt':receipt}
    if r.get('status') in ('success','timeout','connection_error','invalid_response','provider_error'):
        return {'status':'uncertain','provider':provider,'reason':'The provider may have accepted this submission. It will not be retried automatically.'}
    return {'status':'failed','provider':provider,'provider_status':r.get('status')}

async def approve_and_execute(ident,reviewer,digest):
    payload,error=await asyncio.to_thread(_claim,ident,reviewer,digest)
    if error:return error
    # The durable executing marker precedes all external side effects.
    try:result=await _send(payload)
    except Exception:result={'status':'uncertain','reason':'Execution interrupted; automatic resubmission is prohibited'}
    with store.connection() as db:
        redacted={k:v for k,v in payload.items() if k!='content_b64'}
        db.execute('UPDATE approvals SET status=?,result=?,payload=? WHERE id=?',
            (result['status'],store.seal(result),store.seal(redacted),ident))
    return result

async def poll(ident,requester):
    row=get_request(ident,requester)
    result=row.get('result') or {}
    if result.get('status')!='submitted':return row
    with store.connection() as db:
        db.execute('CREATE TABLE IF NOT EXISTS analysis_polls (id TEXT PRIMARY KEY, polled REAL NOT NULL)')
        db.execute('BEGIN IMMEDIATE')
        prior=db.execute('SELECT polled FROM analysis_polls WHERE id=?',(ident,)).fetchone()
        if prior and time.time()-prior[0]<30:return {'status':'rate_limited','retry_after':30}
        db.execute('INSERT OR REPLACE INTO analysis_polls VALUES (?,?)',(ident,time.time()))
        db.execute('DELETE FROM analysis_polls WHERE polled<?',(time.time()-30*86400,))
    provider=result['provider']; receipt=result['receipt']
    policy=provider_policy(provider)
    if policy:return policy
    if provider=='virustotal':
        quota=await _vt_quota()
        if quota:return quota
        url=f'https://www.virustotal.com/api/v3/analyses/{receipt}'; headers={'x-apikey':os.environ['VIRUSTOTAL_API_KEY']}
    elif provider=='urlscan':
        url=f'https://urlscan.io/api/v1/result/{receipt}/';headers={'api-key':os.environ['URLSCAN_API_KEY']}
    else:
        account=os.environ['CLOUDFLARE_ACCOUNT_ID']
        if not re.fullmatch(r'[a-fA-F0-9]{32}',account):return {'status':'not_configured'}
        url=f'https://api.cloudflare.com/client/v4/accounts/{account}/urlscanner/v2/result/{receipt}'
        headers={'Authorization':'Bearer '+os.environ['CLOUDFLARE_API_TOKEN']}
    response=await request('GET',url,headers=headers,max_bytes=1_000_000)
    if response.get('status')=='not_found' and provider!='virustotal':return {'status':'pending','retry_after':30}
    return {'status':response.get('status'),'provider':provider,'analysis':response.get('data'),'retry_after':30}
