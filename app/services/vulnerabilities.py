"""Source-attributed CVE enrichment; severity, probability and exploitation remain distinct."""
import asyncio
import os
import re
from app.providers.http import request
from app.services.intel_store import search_records,feed_status
from app.services.feeds import sync_feed

async def lookup_cve(cve_id:str)->dict:
    'Read source-attributed NVD, EPSS and CISA KEV context for a CVE. Severity, predicted exploitation and known exploitation remain separate.'
    cve=cve_id.strip().upper()
    if not re.fullmatch(r'CVE-\d{4}-\d{4,12}',cve):return {'status':'invalid_indicator','error':'Expected a CVE identifier'}
    async def nvd():
        headers={'apiKey':os.getenv('NVD_API_KEY')} if os.getenv('NVD_API_KEY') else {}
        r=await request('GET','https://services.nvd.nist.gov/rest/json/cves/2.0',params={'cveId':cve},headers=headers,max_bytes=2_000_000,timeout=20)
        if r['status']!='success':return {'provider':'nvd',**r}
        d=r.pop('data');items=d.get('vulnerabilities',[]) if isinstance(d,dict) else []
        if not items:return {'provider':'nvd','status':'not_found'}
        item=items[0].get('cve',{})
        return {'provider':'nvd',**r,**{k:item[k] for k in ('id','published','lastModified','vulnStatus','metrics','weaknesses','references') if k in item},
                'description':next((x.get('value') for x in item.get('descriptions',[]) if x.get('lang')=='en'),None)}
    async def epss():
        r=await request('GET','https://api.first.org/data/v1/epss',params={'cve':cve})
        if r['status']!='success':return {'provider':'epss',**r}
        d=r.pop('data');rows=d.get('data',[]) if isinstance(d,dict) else []
        return {'provider':'epss',**r,'status':'success' if rows else 'not_found','estimates':rows,
                'interpretation_note':'EPSS is estimated exploitation probability, not confirmation of exploitation.'}
    async def kev():
        rows=await asyncio.to_thread(search_records,cve,'cve','feed:cisa_kev',1,None,True)
        statuses=await asyncio.to_thread(feed_status)
        entry=next((s for s in statuses if s['source']=='feed:cisa_kev'),None)
        if not entry or __import__('time').time()-entry['updated']>3600:
            await sync_feed('cisa_kev')
            rows=await asyncio.to_thread(search_records,cve,'cve','feed:cisa_kev',1,None,True)
            statuses=await asyncio.to_thread(feed_status);entry=next((s for s in statuses if s['source']=='feed:cisa_kev'),None)
        if rows:return {'provider':'cisa_kev','status':'success','known_exploited':True,'record':rows[0]['data'],'source_url':rows[0]['source_url']}
        return {'provider':'cisa_kev','status':'not_found' if entry and entry['status']=='success' else 'unavailable',
                'known_exploited':False if entry and entry['status']=='success' else None,
                'interpretation_note':'Absence from KEV does not establish that exploitation has not occurred.'}
    results=await asyncio.gather(nvd(),epss(),kev(),return_exceptions=True)
    results=[r if isinstance(r,dict) else {'provider':p,'status':'internal_error'} for p,r in zip(('nvd','epss','cisa_kev'),results)]
    return {'indicator':cve,'indicator_type':'cve','status':'completed' if all(r['status'] in ('success','not_found') for r in results) else 'partial',
            'sources':results,'known_exploited':next(r.get('known_exploited') for r in results if r['provider']=='cisa_kev'),
            'limitations':['CVSS severity, EPSS probability and CISA-confirmed exploitation are different measures and are not averaged.']}
