"""Accountless, allowlisted Radar intelligence. Aggregate context is never an IOC verdict."""
import os
import re
from urllib.parse import quote
from app.providers.http import request
from app.services.indicators import validate_indicator

L3_DIMENSIONS=('PROTOCOL','IP_VERSION','VECTOR','DURATION','BITRATE','VERTICAL','INDUSTRY')
L7_DIMENSIONS=('HTTP_METHOD','HTTP_VERSION','IP_VERSION','MANAGED_RULES','MITIGATION_PRODUCT','VERTICAL','INDUSTRY')
EMAIL_DIMENSIONS=('SPAM','MALICIOUS','SPOOF','THREAT_CATEGORY','ARC','DKIM','DMARC','SPF','TLS_VERSION')
BASE='https://api.cloudflare.com/client/v4/radar/'

async def fetch(path,params):
    # Paths are built only by the fixed operations below, not accepted from clients.
    r=await request('GET',BASE+path,params=params,
        headers={'Authorization':'Bearer '+os.getenv('CLOUDFLARE_API_TOKEN','')},max_bytes=2_000_000)
    if r['status']!='success':return r
    payload=r.pop('data')
    if not isinstance(payload,dict) or not isinstance(payload.get('result'),dict):return {'status':'invalid_response'}
    if payload.get('success') is not True:return {'status':'provider_error'}
    return {**r,'data':payload['result'],'interpretation_note':'Cloudflare Radar observational context; not a maliciousness or safety verdict.'}

async def run(path,params):
    from app.services.registry import CAPABILITIES,load_overrides
    from app.services.provider_runtime import execute
    cap=next(c for c in CAPABILITIES if c.name=='cloudflare_radar')
    policy=cap.policy_status(load_overrides())
    if policy!='configured':return {'status':policy,'provider':'cloudflare_radar'}
    async def operation(*args):return await fetch(path,params)
    return {'provider':'cloudflare_radar',**await execute(cap,path,'radar_context',params,operation)}

async def domain_rank_raw(domain):
    check=validate_indicator(domain,'domain')
    if not check.get('external_lookup_allowed'):return {'status':'blocked'}
    r=await fetch('ranking/domain/'+quote(check['indicator'],safe=''),{'format':'JSON','rankingType':'POPULAR'})
    if r.get('status')!='success':return r
    data=r.pop('data')
    details=data.get('details_0')
    if not isinstance(details,dict):return {'status':'invalid_response'}
    return {**r,'domain':check['indicator'],'rank_details':details,'meta':data.get('meta'),
        'interpretation_note':'Domain popularity is context. A ranking bucket is not an exact rank, and popularity does not establish safety.'}

async def asn_lookup(ip:str)->dict:
    """Retrieve Cloudflare's AS details for a public IP; AS ownership is not actor attribution."""
    check=validate_indicator(ip,'ip')
    if not check.get('external_lookup_allowed'):return {'status':'blocked'}
    r=await run('entities/asns/ip',{'ip':check['indicator']})
    if r.get('status')=='success' and not isinstance(r.get('data',{}).get('asn'),dict):return {'status':'invalid_response'}
    return r

async def domain_rank(domain:str)->dict:
    """Read a domain's Radar popularity rank or bucket. Does not assess reputation."""
    from app.services.investigation import provider_lookup
    check=validate_indicator(domain,'domain')
    if not check.get('external_lookup_allowed'):return {'status':'blocked'}
    return await provider_lookup('cloudflare_radar',check['indicator'])

async def ddos_trends(layer:str='layer3',dimension:str='VECTOR',view:str='summary',days:int=7,location:str|None=None)->dict:
    """Aggregate DDoS context. layer3 supports VECTOR/PROTOCOL; layer7 supports HTTP_METHOD/MITIGATION_PRODUCT and other documented dimensions. view is summary or timeseries. Maximum 30 days. Not an IOC query."""
    dimensions=L3_DIMENSIONS if layer=='layer3' else L7_DIMENSIONS if layer=='layer7' else ()
    dimension=dimension.upper()
    if dimension not in dimensions or view not in ('summary','timeseries') or isinstance(days,bool) or not 1<=days<=30:
        return {'status':'invalid_parameter','allowed_dimensions':list(dimensions),'views':['summary','timeseries'],'max_days':30}
    if location is not None and not re.fullmatch(r'[A-Za-z]{2}',location):return {'status':'invalid_parameter'}
    params={'dateRange':f'{days}d','format':'JSON'}
    if location:params['location']=location.upper()
    operation='summary' if view=='summary' else 'timeseries_groups'
    result=await run(f'attacks/{layer}/{operation}/{dimension}',params)
    return {**result,'scope':{'dataset':'aggregate_ddos','layer':layer,'dimension':dimension,'days':days,'location':location.upper() if location else 'global'},
        'limitations':['Aggregate observed attack activity does not establish that a particular IP, domain or organization is malicious. Preserve returned units, normalization and date ranges.']}

async def email_security(dimension:str='THREAT_CATEGORY',view:str='summary',days:int=7)->dict:
    """Aggregate email threat/security categories and authentication metrics; no mailbox or email address is queried. Maximum 30 days; view is summary or timeseries."""
    dimension=dimension.upper()
    if dimension not in EMAIL_DIMENSIONS or view not in ('summary','timeseries') or isinstance(days,bool) or not 1<=days<=30:
        return {'status':'invalid_parameter','allowed_dimensions':list(EMAIL_DIMENSIONS),'views':['summary','timeseries'],'max_days':30}
    operation='summary' if view=='summary' else 'timeseries_groups'
    result=await run(f'email/security/{operation}/{dimension}',{'dateRange':f'{days}d','format':'JSON'})
    return {**result,'scope':{'dataset':'aggregate_email_security','dimension':dimension,'days':days},
        'limitations':['These are Cloudflare aggregate email observations, not evidence about a particular email address or domain. Preserve provider units, normalization, confidence metadata and time ranges.']}
