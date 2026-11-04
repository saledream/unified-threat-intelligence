import asyncio
from fastapi import APIRouter,Depends,Request
from pydantic import BaseModel,Field
from sqlalchemy.orm import Session
from app.api.dependencies import require_analyst,require_admin
from app.api.audit import record_audit
from app.database import get_db
from app.models import User
from app.services import investigation,knowledge,intel_store,feeds
from app.services.vulnerabilities import lookup_cve

router=APIRouter(prefix='/api/intelligence',tags=['Expanded intelligence'])

@router.get('/shodan/host')
async def shodan_host(ip:str,request:Request,user:User=Depends(require_analyst),db:Session=Depends(get_db)):
    record_audit(db,user,'shodan.host','started',ip,'ip',request)
    result=await investigation.provider_lookup('shodan',ip)
    record_audit(db,user,'shodan.host',result.get('status','unknown'),ip,'ip',request)
    return result
class BulkRequest(BaseModel):
    indicators:list[str]=Field(min_length=1,max_length=20)
class InvestigationRequest(BaseModel):
    indicator:str=Field(min_length=1,max_length=4096)
    max_pivots:int=Field(default=0,ge=0,le=3)

@router.post('/bulk')
async def bulk(data:BulkRequest,request:Request,user:User=Depends(require_analyst),db:Session=Depends(get_db)):
    record_audit(db,user,'investigation.bulk','started',request=request)
    result=await investigation.bulk_lookup(data.indicators)
    record_audit(db,user,'investigation.bulk',result['status'],request=request)
    return result

@router.post('/investigate')
async def investigate(data:InvestigationRequest,request:Request,user:User=Depends(require_analyst),db:Session=Depends(get_db)):
    record_audit(db,user,'investigation.pivots','started',request=request)
    return await investigation.investigate(data.indicator,data.max_pivots)

@router.get('/cve/{cve_id}')
async def cve(cve_id:str,user:User=Depends(require_analyst)):
    return await lookup_cve(cve_id)

@router.get('/sources')
def sources(user:User=Depends(require_analyst)):
    return {'status':'success','sources':intel_store.feed_status(),'feeds':list(feeds.FEEDS),'corpora':list(knowledge.CORPORA)}

@router.get('/search')
def search(query:str='',source:str|None=None,limit:int=10,user:User=Depends(require_analyst)):
    from app.services.local_search import search_local
    return search_local(query,source,limit=limit)

@router.post('/feeds/{name}/sync')
async def sync_feed(name:str,request:Request,user:User=Depends(require_admin),db:Session=Depends(get_db)):
    record_audit(db,user,'feed.sync','started',request=request)
    result=await feeds.sync_feed(name)
    record_audit(db,user,'feed.sync',result['status'],request=request)
    return result

@router.post('/corpora/{name}/sync')
async def sync_corpus(name:str,request:Request,user:User=Depends(require_admin),db:Session=Depends(get_db)):
    record_audit(db,user,'corpus.sync','started',request=request)
    result=await knowledge.sync_corpus(name)
    record_audit(db,user,'corpus.sync',result['status'],request=request)
    return result


@router.get('/radar/asn')
async def radar_asn(ip:str,user:User=Depends(require_analyst)):
    from app.services.cloudflare_radar import asn_lookup
    return await asn_lookup(ip)

@router.get('/radar/domain-rank')
async def radar_rank(domain:str,user:User=Depends(require_analyst)):
    from app.services.cloudflare_radar import domain_rank
    return await domain_rank(domain)

@router.get('/radar/ddos')
async def radar_ddos(layer:str='layer3',dimension:str='VECTOR',view:str='summary',days:int=7,location:str|None=None,user:User=Depends(require_analyst)):
    from app.services.cloudflare_radar import ddos_trends
    return await ddos_trends(layer,dimension,view,days,location)

@router.get('/radar/email-security')
async def radar_email(dimension:str='THREAT_CATEGORY',view:str='summary',days:int=7,user:User=Depends(require_analyst)):
    from app.services.cloudflare_radar import email_security
    return await email_security(dimension,view,days)
