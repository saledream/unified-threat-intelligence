"""Additional passive sources. These endpoints query provider datasets, never targets."""
import os
import re
from urllib.parse import quote
from app.providers.http import request
from app.services.indicators import validate_indicator


def compact(data,keys):
    return {k:data[k] for k in keys if k in data and data[k] is not None}


async def lookup(value,kind,meta):
    provider=meta['_provider']
    check=validate_indicator(value,kind)
    if not check.get('valid') or not check.get('external_lookup_allowed'):
        return {'status':'blocked','error':'Invalid or prohibited external indicator'}
    value=check['indicator']
    if provider=='shodan':
        if kind!='ip':return {'status':'unsupported_indicator_type'}
        from app.providers.shodan import check_host
        return await check_host(value)
    if provider=='shodan_internetdb':
        r=await request('GET',f'https://internetdb.shodan.io/{quote(value,safe="")}')
        if r['status']!='success':return r
        d=r.pop('data')
        if not isinstance(d,dict):return {'status':'invalid_response'}
        return {**r,**compact(d,('ip','ports','cpes','hostnames','tags','vulns')),
                'interpretation_note':'Previously observed service exposure; not a current scan or vulnerability confirmation. InternetDB is updated weekly.'}
    if provider=='ipinfo':
        r=await request('GET',f'https://api.ipinfo.io/lite/{quote(value,safe="")}',headers={'Authorization':'Bearer '+os.getenv('IPINFO_TOKEN','')})
        if r['status']!='success':return r
        d=r.pop('data')
        if not isinstance(d,dict):return {'status':'invalid_response'}
        return {**r,**compact(d,('ip','asn','as_name','as_domain','country_code','country','continent_code','continent'))}
    if provider=='spur':
        r=await request('GET',f'https://api.spur.us/v2/context/{quote(value,safe="")}',headers={'Token':os.getenv('SPUR_TOKEN','')})
        if r['status']!='success':return r
        d=r.pop('data')
        if not isinstance(d,dict):return {'status':'invalid_response'}
        return {**r,**compact(d,('ip','as','organization','infrastructure','location','risks','services','tunnels','client')),
                'interpretation_note':'Proxy/VPN context does not independently establish maliciousness.'}
    if provider=='pulsedive':
        # value lookup is passive; no analyze.php/scanner request is made.
        r=await request('GET','https://pulsedive.com/api/indicator.php',params={'indicator':value,'key':os.getenv('PULSEDIVE_API_KEY','')})
        if r['status']!='success':return r
        d=r.pop('data')
        if not isinstance(d,dict):return {'status':'invalid_response'}
        if d.get('error'):return {'status':'provider_error','error':'Pulsedive did not return indicator data'}
        return {**r,**compact(d,('iid','indicator','type','risk','risk_recommended','stamp_added','stamp_updated','stamp_seen','threats','feeds','properties','riskfactors'))}
    if provider=='censys':
        headers={'Authorization':'Bearer '+os.getenv('CENSYS_API_TOKEN','')}
        params={'organization_id':os.getenv('CENSYS_ORG_ID')} if os.getenv('CENSYS_ORG_ID') else None
        if kind=='ip':r=await request('GET',f'https://api.platform.censys.io/v3/global/asset/host/{quote(value,safe="")}',headers=headers,params=params)
        else:
            if os.getenv('CENSYS_SEARCH_AUTHORIZED','false').lower()!='true':
                return {'status':'requires_authorization','reason':'Censys search access must be explicitly enabled for this account'}
            # A hostname is quoted; user query syntax is not interpolated.
            r=await request('POST','https://api.platform.censys.io/v3/global/search/query',headers=headers,params=params,
                            json={'query':f'host.dns.names="{value}"','page_size':10})
        if r['status']!='success':return r
        d=r.pop('data')
        if not isinstance(d,dict):return {'status':'invalid_response'}
        return {**r,'record':d,'interpretation_note':'Provider-collected exposure and certificates; no target connection is made.'}
    if provider=='cloudflare_radar':
        if kind=='domain':
            from app.services.cloudflare_radar import domain_rank_raw
            return await domain_rank_raw(value)
        if kind!='ip':return {'status':'unsupported_indicator_type'}
        r=await request('GET','https://api.cloudflare.com/client/v4/radar/entities/ip',
            params={'ip':value},headers={'Authorization':'Bearer '+os.getenv('CLOUDFLARE_API_TOKEN','')})
        if r['status']!='success':return r
        payload=r.pop('data')
        if not isinstance(payload,dict) or payload.get('success') is not True:return {'status':'invalid_response'}
        result=payload.get('result')
        data=result.get('ip') if isinstance(result,dict) else None
        if not isinstance(data,dict):return {'status':'invalid_response'}
        if data.get('ip')!=value:return {'status':'invalid_response','error':'Radar returned a different IP'}
        return {**r,**compact(data,('ip','ipVersion','locationName','location','asn','asnName','asnOrgName','asnLocation')),
            'interpretation_note':'Cloudflare Radar network and country context; not an IP reputation verdict. No account ID or URL Scanner permission is required.'}
    if provider=='cloudflare_urlscanner':
        account=os.getenv('CLOUDFLARE_ACCOUNT_ID','')
        if not re.fullmatch(r'[a-fA-F0-9]{32}',account):return {'status':'not_configured','error':'A valid Cloudflare account ID is required'}
        field={'domain':'page.domain','ip':'page.ip','url':'task.url'}[kind]
        escaped=value.replace('\\','\\\\').replace('"','\\"')
        endpoint=f'https://api.cloudflare.com/client/v4/accounts/{account}/urlscanner/v2/search'
        r=await request('GET',endpoint,params={'q':f'{field}:"{escaped}"','size':20},headers={'Authorization':'Bearer '+os.getenv('CLOUDFLARE_API_TOKEN','')})
        if r['status']!='success':return r
        payload=r.pop('data')
        if isinstance(payload,dict) and payload.get('success') is False:return {'status':'provider_error'}
        rows=payload.get('results') or (payload.get('result') or {}).get('results',[]) if isinstance(payload,dict) else []
        if not isinstance(rows,list):return {'status':'invalid_response'}
        scans=[]
        for row in rows[:20]:
            task,page,verdicts=row.get('task',{}),row.get('page',{}),row.get('verdicts',{})
            scans.append({'scan_id':task.get('uuid'),'scan_time':task.get('time'),'url':task.get('url'),
                          'domain':page.get('domain'),'ip':page.get('ip'),'country':page.get('country'),
                          'malicious':verdicts.get('malicious'),'result_url':row.get('result')})
        return {**r,'status':'success' if scans else 'not_found','historical_count':len(scans),'historical_scans':scans}
    if provider=='certificate_transparency':
        r=await request('GET','https://crt.sh/',params={'q':value,'output':'json'},max_bytes=3_000_000)
        if r['status']!='success':return r
        d=r.pop('data')
        if not isinstance(d,list):return {'status':'invalid_response'}
        return {**r,'status':'success' if d else 'not_found','certificates':[
            compact(row,('id','issuer_name','common_name','name_value','entry_timestamp','not_before','not_after','serial_number'))
            for row in d[:30]],'records_returned':min(len(d),30),'truncated':len(d)>30,
            'interpretation_note':'Certificate issuance is registration context, not proof of ownership or maliciousness.'}
    if provider=='dns_doh':
        queries=[]
        for qtype in ('A','AAAA'):
            r=await dns_query(value,qtype)
            queries.append(r)
        successes=[r for r in queries if r['status'] in ('success','not_found')]
        return {'status':'success' if successes else queries[0]['status'],'queries':queries,
                'addresses':[a['data'] for r in successes for a in r.get('answers',[]) if a.get('type') in (1,28)],
                'interpretation_note':'Resolver answers are context. Only public addresses may be used for a separately bounded intelligence pivot.'}
    if provider=='local_feeds':
        import asyncio
        from app.services.intel_store import search_records,feed_status
        feed_types={'ip':('feodo','sslbl_ip','threatfox','otx'),'domain':('threatfox','otx'),
                    'url':('threatfox','urlhaus','openphish','otx'),'hash':('threatfox','malwarebazaar','otx')}
        eligible={'feed:'+name for name in feed_types[kind]}
        records=await asyncio.to_thread(search_records,value,kind,None,50,None,True)
        records=[r for r in records if r['source'] in eligible][:20]
        if not records:
            feeds=await asyncio.to_thread(feed_status)
            return {'status':'not_found' if any(s['status']=='success' and s['source'] in eligible for s in feeds) else 'not_configured',
                    'reason':'No exact match in locally synchronized feeds; this is not a safety verdict'}
        return {'status':'success','feed_matches':records,'match_count':len(records)}
    return {'status':'unsupported_indicator_type'}


async def dns_query(domain,qtype='A'):
    check=validate_indicator(domain,'domain')
    allowed={'A','AAAA','CNAME','MX','NS','TXT','CAA','SRV','SOA'}
    if not check.get('external_lookup_allowed') or qtype not in allowed:return {'status':'invalid_indicator'}
    r=await request('GET','https://cloudflare-dns.com/dns-query',params={'name':check['indicator'],'type':qtype},headers={'Accept':'application/dns-json'})
    if r['status']!='success':return r
    d=r.pop('data')
    if not isinstance(d,dict):return {'status':'invalid_response'}
    return {**r,'status':'success' if d.get('Status')==0 else 'not_found' if d.get('Status')==3 else 'provider_error',
            'dns_status':d.get('Status'),'dnssec_validated':d.get('AD'),'answers':d.get('Answer',[])[:50]}
