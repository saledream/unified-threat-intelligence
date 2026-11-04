"""Human submission review. Never expose approval credentials to an MCP client."""
from fastapi import APIRouter, Depends, Request, HTTPException
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy.orm import Session
from app.api.dependencies import require_admin, require_analyst
from app.api.audit import record_audit
from app.api.rate_limit import is_login_blocked, record_login_failure, clear_login_failures
from app.auth.security import verify_password
from app.database import get_db
from app.models import User
from app.services import submissions as service

router=APIRouter(prefix='/api/submissions',tags=['Human-approved submissions'])

class UrlRequest(BaseModel):
    url:str=Field(min_length=1,max_length=8192)
    provider:str='virustotal'

class Decision(BaseModel):
    digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    password:SecretStr=Field(min_length=1,max_length=1024)
    acknowledge_disclosure:bool=False
    approve:bool

@router.post('/url')
def request_url(data:UrlRequest,request:Request,user:User=Depends(require_analyst),db:Session=Depends(get_db)):
    result=service.request_url(str(user.id),data.url,data.provider)
    record_audit(db,user,'submission.request.url',result.get('status','unknown'),request=request)
    return result

@router.post('/file')
async def request_file(request:Request,user:User=Depends(require_analyst),db:Session=Depends(get_db)):
    if request.headers.get('content-type','').split(';')[0]!='application/octet-stream':
        raise HTTPException(415,'Send file bytes as application/octet-stream')
    content=bytearray()
    async for chunk in request.stream():
        if len(content)+len(chunk)>service.MAX_FILE_BYTES:raise HTTPException(413,'Maximum file size is 16 MiB')
        content.extend(chunk)
    result=service.request_file(str(user.id),bytes(content),request.headers.get('x-filename','sample'))
    record_audit(db,user,'submission.request.file',result.get('status','unknown'),request=request)
    return result

@router.get('')
def list_requests(user:User=Depends(require_analyst)):
    return service.list_requests(None if user.role=='admin' else str(user.id))

@router.post('/{ident}/decision')
async def decide(ident:str,data:Decision,request:Request,user:User=Depends(require_admin),db:Session=Depends(get_db)):
    ip=request.client.host if request.client else 'unknown'
    if is_login_blocked(db,user.username,ip):raise HTTPException(429,'Too many failed password confirmations')
    if not verify_password(data.password.get_secret_value(),user.password_hash):
        record_login_failure(db,user.username,ip)
        record_audit(db,user,'submission.decision','bad_password',request=request)
        raise HTTPException(401,'Password confirmation failed')
    clear_login_failures(db,user.username,ip)
    if data.approve and not data.acknowledge_disclosure:raise HTTPException(400,'Acknowledge the provider disclosure before approving')
    record_audit(db,user,'submission.approve' if data.approve else 'submission.reject','started',ident+':'+data.digest,'submission',request)
    result=await service.approve_and_execute(ident,str(user.id),data.digest) if data.approve else service.reject(ident,str(user.id),data.digest)
    record_audit(db,user,'submission.decision',result.get('status','unknown'),ident+':'+data.digest,'submission',request)
    return result

@router.get('/{ident}')
def get_request(ident:str,user:User=Depends(require_analyst)):
    return service.get_request(ident,None if user.role=='admin' else str(user.id))

@router.post('/{ident}/poll')
async def poll(ident:str,user:User=Depends(require_analyst)):
    return await service.poll(ident,None if user.role=='admin' else str(user.id))
