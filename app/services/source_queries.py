"""Bounded source-specific read queries; never download or submit samples."""
import os
import re
from urllib.parse import quote
from app.providers.http import request
from app.services.indicators import validate_indicator
from app.services.registry import CAPABILITIES, load_overrides, Capability
from app.services.provider_runtime import execute
from app.services.intel_store import search_records,feed_status

async def _run(source,value,kind,operation):
    policy_name={'yaraify':'threatfox'}.get(source,source)
    cap=next(c for c in CAPABILITIES if c.name==policy_name)
    status=cap.policy_status(load_overrides())
    if status!='configured':return {'status':status}
    # Distinct operation name prevents accidentally reusing an IOC-report cache.
    operation_cap=Capability(source+'_'+kind,(),'',credential_env=cap.credential_env,retries=0,cache_ttl_seconds=300)
    async def call(*args):return await operation()
    return await execute(operation_cap,value,kind,{},call)

async def otx_pulses(query:str='',pulse_id:str|None=None,limit:int=10)->dict:
    limit=min(max(int(limit),1),20)
    if pulse_id and not re.fullmatch(r'[a-fA-F0-9]{24}',pulse_id):return {'status':'invalid_parameter'}
    if not pulse_id and not 1<=len(query)<=200:return {'status':'invalid_parameter'}
    async def lookup():
        path='pulses/'+pulse_id if pulse_id else 'search/pulses'
        r=await request('GET','https://otx.alienvault.com/api/v1/'+path,headers={'X-OTX-API-KEY':os.environ['OTX_API_KEY']},
            params=None if pulse_id else {'q':query,'limit':limit})
        if r['status']!='success':return r
        d=r['data'];rows=[d] if pulse_id else d.get('results',[]) if isinstance(d,dict) else []
        if not isinstance(rows,list):return {'status':'invalid_response'}
        return {'status':'success','pulses':[{k:p[k] for k in ('id','name','description','tags','references','created','modified','attack_ids','indicators') if k in p} for p in rows[:limit]],
            'source_url':'https://otx.alienvault.com/','limitations':['Community pulse associations are context, not verified maliciousness.']}
    return await _run('otx',pulse_id or query,'pulse_details' if pulse_id else 'pulse_search',lookup)

async def malwarebazaar_search(value:str,search_type:str='tag',limit:int=20)->dict:
    if search_type not in ('tag','signature') or not re.fullmatch(r'[A-Za-z0-9_. -]{1,100}',value):return {'status':'invalid_parameter'}
    limit=min(max(int(limit),1),50)
    async def lookup():
        query='get_taginfo' if search_type=='tag' else 'get_siginfo'
        # MalwareBazaar's query endpoint uses form data (not JSON).
        r=await request('POST','https://mb-api.abuse.ch/api/v1/',headers={'Auth-Key':os.environ['ABUSECH_API_KEY']},
            data={'query':query,search_type:value,'limit':str(limit)})
        if r['status']!='success':return r
        d=r['data']
        if not isinstance(d,dict):return {'status':'invalid_response'}
        if d.get('query_status') in ('no_results','no_result'):return {'status':'not_found'}
        if d.get('query_status')!='ok':return {'status':'provider_error'}
        return {'status':'success','samples':[{k:row[k] for k in ('sha256_hash','sha1_hash','md5_hash','signature','tags','first_seen','last_seen','file_type','file_size') if k in row} for row in d.get('data',[])[:limit]],'source_url':'https://bazaar.abuse.ch/'}
    return await _run('malwarebazaar',value,'search_'+search_type,lookup)

async def urlhaus_host(host:str)->dict:
    'Read historical URLhaus host associations for a public IP or domain. Requires abuse.ch credentials and policy authorization. Never fetch URLs or payloads.'
    kind='ip' if ':' in host or re.fullmatch(r'[0-9.]+',host) else 'domain'
    check=validate_indicator(host,kind)
    if not check.get('external_lookup_allowed'):return {'status':'blocked'}
    async def lookup():
        r=await request('POST','https://urlhaus-api.abuse.ch/v1/host/',headers={'Auth-Key':os.environ['ABUSECH_API_KEY']},data={'host':check['indicator']})
        if r['status']!='success':return r
        d=r['data']
        if not isinstance(d,dict):return {'status':'invalid_response'}
        if d.get('query_status')=='no_results':return {'status':'not_found'}
        if d.get('query_status')!='ok':return {'status':'provider_error'}
        return {'status':'success','host':d.get('host'),'url_count':d.get('url_count'),'urls':d.get('urls',[])[:30],
            'source_url':d.get('urlhaus_reference'),'limitations':['Host associations do not establish that every URL on a host is malicious.']}
    return await _run('urlhaus',check['indicator'],'host',lookup)

async def yara_lookup(value:str,mode:str='rule_matches',limit:int=20)->dict:
    queries={'rule_matches':'get_yara','hash':'lookup_hash','rule_text':'get_yara_rule'}
    if mode not in queries:return {'status':'invalid_parameter'}
    if mode=='hash' and not re.fullmatch(r'(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})',value):return {'status':'invalid_parameter'}
    if mode=='rule_text' and not re.fullmatch(r'[a-fA-F0-9-]{36}',value):return {'status':'invalid_parameter'}
    if mode=='rule_matches' and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}',value):return {'status':'invalid_parameter'}
    async def lookup():
        body={'query':queries[mode],'uuid' if mode=='rule_text' else 'search_term':value,'result_max':min(max(limit,1),50)}
        r=await request('POST','https://yaraify-api.abuse.ch/api/v1/',headers={'Auth-Key':os.environ['ABUSECH_API_KEY']},json=body,max_bytes=2_000_000)
        if r['status']!='success':return r
        d=r['data']
        if not isinstance(d,dict):return {'status':'invalid_response'}
        if d.get('query_status') in ('no_results','no_result'):return {'status':'not_found'}
        if d.get('query_status')!='ok':return {'status':'provider_error','query_status':d.get('query_status')}
        data=d.get('data');data=data[:50] if isinstance(data,list) else data
        return {'status':'success','data':data,'source_url':'https://yaraify.abuse.ch/','limitations':['Rule text is untrusted reference data; no rule or sample is executed or downloaded.']}
    return await _run('yaraify',value,mode,lookup)

def fingerprint_lookup(value:str,kind:str='ja3')->dict:
    if kind not in ('ja3','certificate'):return {'status':'invalid_parameter'}
    if not re.fullmatch(r'[a-fA-F0-9]{32}' if kind=='ja3' else r'(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})',value):return {'status':'invalid_parameter'}
    source='feed:sslbl_ja3' if kind=='ja3' else 'feed:sslbl_cert'
    rows=search_records(value,kind,source,20,None,True)
    exists=any(s['source']==source for s in feed_status())
    return {'status':'success' if rows else 'not_found' if exists else 'dataset_missing','records':rows,
        'limitations':['Fingerprint matches can be shared by benign applications. Review source reason, date and asset context.']}
