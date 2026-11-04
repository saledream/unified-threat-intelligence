"""Authenticated Shodan host reports. No search, scan submission, or target connection."""
import os
from urllib.parse import quote
from app.providers.http import request
from app.services.indicators import validate_indicator

async def check_host(ip:str)->dict:
    check=validate_indicator(ip,'ip')
    if not check.get('external_lookup_allowed'):return {'status':'blocked'}
    key=os.getenv('SHODAN_API_KEY','').strip()
    if not key:return {'status':'not_configured'}
    value=check['indicator']
    result=await request('GET','https://api.shodan.io/shodan/host/'+quote(value,safe=''),
        params={'key':key,'history':'false','minify':'false'},max_bytes=2_000_000)
    if result['status']!='success':
        if result['status']=='forbidden':
            result['reason']='The current Shodan token/account does not permit this host report. InternetDB is a separate provider.'
        return result
    data=result.pop('data')
    if not isinstance(data,dict) or data.get('ip_str')!=value:return {'status':'invalid_response'}
    if data.get('error'):return {'status':'provider_error'}
    services=data.get('data',[])
    if not isinstance(services,list) or any(not isinstance(row,dict) for row in services):return {'status':'invalid_response'}
    fields=('ip_str','asn','org','isp','country_code','country_name','city','os','last_update','hostnames','domains','ports','tags')
    out={k:data[k] for k in fields if data.get(k) is not None}
    for field in ('hostnames','domains','ports','tags'):
        if field in out:
            if not isinstance(out[field],list):return {'status':'invalid_response'}
            out[field]=out[field][:100]
    vulns=data.get('vulns',[])
    if not isinstance(vulns,(dict,list)):return {'status':'invalid_response'}
    return {**result,**out,'source_url':'https://www.shodan.io/host/'+quote(value,safe=''),
        'vulns':list(vulns)[:100],
        'services':[{k:row[k] for k in ('port','transport','product','version','timestamp','cpe','cpe23','hostnames','domains') if k in row} for row in services[:30]],
        'services_truncated':len(services)>30,
        'interpretation_note':'Previously observed Shodan service exposure; last_update is the report update time. Listed CVEs are context, not verified vulnerabilities or maliciousness. No new scan was requested.'}
