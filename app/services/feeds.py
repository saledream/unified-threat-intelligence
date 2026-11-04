"""Public-feed ingestion with persistent freshness and bounded synchronization."""
import asyncio
import csv
import hashlib
import io
import os
import re
import time
from datetime import datetime, timezone
from app.providers.http import request
from app.providers.abusech_policy import authorized as abusech_authorized
from app.services import intel_store as store
from app.services.indicators import validate_indicator

FEEDS={
 'feodo':{'url':'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json','interval':900},
 'sslbl_ip':{'url':'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv','interval':900,'text':True},
 'sslbl_cert':{'url':'https://sslbl.abuse.ch/blacklist/sslblacklist.csv','interval':900,'text':True},
 'sslbl_ja3':{'url':'https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv','interval':900,'text':True},
 'cisa_kev':{'url':'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json','interval':3600},
 'openphish':{'url':'https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt','interval':43200,'text':True},
 'threatfox':{'url':'https://threatfox-api.abuse.ch/api/v1/','interval':3600,'abusech':True},
 'malwarebazaar':{'url':'https://mb-api.abuse.ch/api/v1/','interval':3600,'abusech':True},
 'urlhaus':{'url':'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/','interval':3600,'abusech':True},
 'otx':{'url':'https://otx.alienvault.com/api/v1/pulses/subscribed','interval':3600,'otx':True},
}


def _record(value,kind,data,source_url,record_id=None,title=None,observed=None):
    if kind in ('ip','domain','url','hash'):
        check=validate_indicator(value,kind)
        if not check.get('valid') or not check.get('external_lookup_allowed'):return None
        value=check['indicator']
    elif kind=='cve':
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}',value,re.I):return None
        value=value.upper()
    elif kind in ('ja3','certificate'):
        if not re.fullmatch(r'[a-fA-F0-9]{32}' if kind=='ja3' else r'(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})',value):return None
        value=value.lower()
    else:return None
    return {'id':str(record_id or hashlib.sha256((kind+':'+value).encode()).hexdigest()),'kind':kind,'value':value,
            'title':title or value,'data':data,'source_url':source_url,'observed':observed}


def parse_feed(name,payload,url):
    rows=[]
    def add(*args,**kwargs):
        row=_record(*args,**kwargs)
        if row:rows.append(row)
    if name=='feodo':
        if not isinstance(payload,list):raise ValueError('Expected Feodo array')
        for item in payload[:20000]:
            add(item.get('ip_address',''),'ip',item,url, title=item.get('malware'), observed=item.get('last_online') or item.get('first_seen'))
    elif name.startswith('sslbl_'):
        if not isinstance(payload,str):raise ValueError('Expected SSLBL CSV')
        for row in csv.reader(line for line in payload.splitlines() if line and not line.startswith('#')):
            if name=='sslbl_ip' and len(row)>=3:
                add(row[1].strip(),'ip',{'first_seen':row[0],'port':row[2],'classification':'listed_ssl_c2'},url,observed=row[0])
            elif name=='sslbl_cert' and len(row)>=3:
                add(row[1].strip(),'certificate',{'listed_at':row[0],'reason':row[2]},url,title=row[2],observed=row[0])
            elif name=='sslbl_ja3' and len(row)>=4:
                add(row[0].strip(),'ja3',{'first_seen':row[1],'last_seen':row[2],'reason':row[3]},url,title=row[3],observed=row[2])
    elif name=='cisa_kev':
        if not isinstance(payload,dict) or not isinstance(payload.get('vulnerabilities'),list):raise ValueError('Expected CISA KEV catalog')
        for item in payload['vulnerabilities']:
            add(item.get('cveID',''),'cve',item,url,title=item.get('vulnerabilityName'),observed=item.get('dateAdded'))
    elif name=='openphish':
        if not isinstance(payload,str):raise ValueError('Expected OpenPhish text')
        for value in payload.splitlines()[:30000]:add(value.strip(),'url',{'classification':'phishing_feed_entry'},url)
    elif name in ('threatfox','malwarebazaar','urlhaus'):
        if not isinstance(payload,dict):raise ValueError('Expected abuse.ch object')
        status=payload.get('query_status')
        if status not in ('ok','no_result','no_results','no_results_found'):raise ValueError('Provider did not return a successful feed')
        items=payload.get('urls',[]) if name=='urlhaus' else payload.get('data',[])
        if not isinstance(items,list):raise ValueError('Expected record array')
        for item in items[:10000]:
            if name=='threatfox':
                t={'domain':'domain','url':'url','ip:port':'ip','md5_hash':'hash','sha256_hash':'hash'}.get(item.get('ioc_type'))
                if t:
                    add(item.get('ioc',''),t,item,item.get('reference') or url,record_id=item.get('id'),title=item.get('malware_printable'),observed=item.get('last_seen') or item.get('first_seen'))
            elif name=='malwarebazaar':
                for key in ('sha256_hash','sha1_hash','md5_hash'):
                    if item.get(key):add(item[key],'hash',item,url,record_id=item.get('sha256_hash'),title=item.get('signature'),observed=item.get('last_seen') or item.get('first_seen'))
            else:
                add(item.get('url',''),'url',item,item.get('urlhaus_reference') or url,record_id=item.get('id'),title=item.get('threat'),observed=item.get('date_added'))
    elif name=='otx':
        if not isinstance(payload,dict) or not isinstance(payload.get('results'),list):raise ValueError('Expected OTX pulse results')
        for pulse in payload['results'][:50]:
            pulse_id=str(pulse.get('id',''))
            pulse_url='https://otx.alienvault.com/pulse/'+pulse_id
            summary={k:pulse[k] for k in ('id','name','description','created','modified','tags','references') if k in pulse}
            rows.append({'id':pulse_id,'kind':'pulse','value':pulse_id,'title':pulse.get('name') or pulse_id,'data':summary,'source_url':pulse_url,'observed':pulse.get('modified')})
            for item in (pulse.get('indicators') or [])[:1000]:
                kind={'IPv4':'ip','IPv6':'ip','domain':'domain','hostname':'domain','URL':'url','FileHash-MD5':'hash','FileHash-SHA1':'hash','FileHash-SHA256':'hash'}.get(item.get('type'))
                if kind:add(item.get('indicator',''),kind,{'pulse':summary,'observable':item},pulse_url,record_id=pulse_id+':'+str(item.get('id',item.get('indicator'))),title=pulse.get('name'),observed=item.get('created'))
    return rows


def claim_sync(name,interval,namespace='feed:'):
    now=time.time();source=namespace+name
    with store.connection() as db:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT * FROM syncs WHERE source=?',(source,)).fetchone()
        if row and now-row['updated']<interval:
            return {'source':source,'status':'cached' if row['status']=='success' else row['status'],
                    'records':row['count'],'retry_after':int(interval-(now-row['updated']))+1}
        db.execute('INSERT OR REPLACE INTO syncs VALUES (?,?,?,?,?)',(source,'syncing',now,0,None))
    return None


async def sync_feed(name):
    if name not in FEEDS:return {'status':'invalid_parameter','error':'Unknown feed'}
    spec=FEEDS[name];source='feed:'+name
    if spec.get('abusech'):
        if not abusech_authorized():return {'source':source,'status':'requires_authorization'}
        if not os.getenv('ABUSECH_API_KEY'):return {'source':source,'status':'not_configured'}
    if spec.get('otx') and not os.getenv('OTX_API_KEY'):return {'source':source,'status':'not_configured'}
    if name=='openphish' and os.getenv('OPENPHISH_TERMS_ACCEPTED','false').lower()!='true':
        return {'source':source,'status':'requires_authorization','reason':'Review OpenPhish community terms and enable OPENPHISH_TERMS_ACCEPTED'}
    existing=await asyncio.to_thread(claim_sync,name,spec['interval'])
    if existing:return existing
    headers={};body=None;method='GET';params=None
    if spec.get('abusech'):headers['Auth-Key']=os.getenv('ABUSECH_API_KEY')
    if name=='threatfox':method='POST';body={'query':'get_iocs','days':1}
    if name=='malwarebazaar':method='POST';body={'query':'get_recent','selector':'100'}
    if name=='otx':headers['X-OTX-API-KEY']=os.getenv('OTX_API_KEY');params={'limit':20}
    try:
        response=await request(method,spec['url'],headers=headers,params=params,
            data=body if name=='malwarebazaar' else None,json=body if name!='malwarebazaar' else None,
            text=spec.get('text',False),max_bytes=15_000_000,timeout=25)
        if response['status']!='success':
            await asyncio.to_thread(store.sync_status,source,response['status'],0,'Previous records preserved; latest synchronization failed')
            return {'source':source,**response}
        rows=parse_feed(name,response['data'],spec['url'])
        count=await asyncio.to_thread(store.upsert_records,source,rows,name!='otx')
        return {'source':source,'status':'success','records':count,'retrieved_at':datetime.now(timezone.utc).isoformat(),
                'limitations':['Snapshot/recent window only; absence is not proof of safety.']}
    except (ValueError,TypeError,KeyError):
        await asyncio.to_thread(store.sync_status,source,'invalid_response',0,'Malformed feed; previous data preserved')
        return {'source':source,'status':'invalid_response'}
    except Exception:
        await asyncio.to_thread(store.sync_status,source,'internal_error',0,'Synchronization failed; previous data preserved')
        return {'source':source,'status':'internal_error'}


async def sync_all():
    gate=asyncio.Semaphore(3)
    async def run(name):
        async with gate:return await sync_feed(name)
    return await asyncio.gather(*(run(name) for name in FEEDS))


async def poll_forever():
    interval=max(300,int(os.getenv('FEED_POLL_SECONDS','3600')))
    while True:
        await sync_all()
        await asyncio.sleep(interval)

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--once',action='store_true');args=parser.parse_args()
    if args.once:print(asyncio.run(sync_all()))
    else:asyncio.run(poll_forever())
