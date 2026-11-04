"""Bounded investigation orchestration; pivots are explicit source observations."""
import asyncio
import re
from app.services.unified import enrich_indicator_all, agent_summary, detect_indicator
from app.services.indicators import validate_indicator

def refang(value):
    if not isinstance(value,str) or len(value)>4096:return ''
    value=value.strip().replace('[.]','.').replace('(.)','.').replace('[:]',':')
    return re.sub(r'^hxxp(s?)://',r'http\1://',value,flags=re.I)

async def bulk_lookup(indicators:list[str]):
    if not isinstance(indicators,list) or not 1<=len(indicators)<=20:
        return {'status':'invalid_parameter','error':'Provide 1 to 20 indicators'}
    if any(not isinstance(v,str) or not 1<=len(v)<=4096 for v in indicators):return {'status':'invalid_parameter'}
    gate=asyncio.Semaphore(4)
    async def run(value):
        async with gate:return agent_summary(await enrich_indicator_all(refang(value)))
    return {'status':'completed','results':await asyncio.gather(*(run(v) for v in dict.fromkeys(refang(v) for v in indicators)))}

async def investigate(indicator:str,max_pivots:int=0)->dict:
    if not isinstance(max_pivots,int) or isinstance(max_pivots,bool) or not 0<=max_pivots<=3:
        return {'status':'invalid_parameter','error':'max_pivots must be 0 to 3'}
    original=refang(indicator)
    report=await enrich_indicator_all(original)
    related=report.get('correlation',{}).get('related_indicators',[])
    # The correlation contract uses related_iocs; never mine arbitrary source prose.
    related=report.get('correlation',{}).get('related_iocs',related)
    if not related:related=report.get('related_indicators',[])
    selected=[]
    for row in related:
        value=row.get('value');kind=row.get('type')
        if kind not in ('ip','domain','url','hash') or not value:continue
        check=validate_indicator(value,kind)
        if check.get('external_lookup_allowed') and value!=original and row.get('inferred') is False:
            selected.append(row)
        if len(selected)>=max_pivots:break
    if max_pivots==0:selected=[]
    pivots=await bulk_lookup([r['value'] for r in selected]) if selected else {'results':[]}
    return {'status':report['status'],'primary':agent_summary(report),'observed_relationships':related,
        'pivot_basis':selected,'pivots':pivots['results'],'limits':{'depth':1,'max_pivots':max_pivots},
        'limitations':['Co-occurrence does not establish shared ownership or maliciousness. Pivots query intelligence providers only.']}

async def provider_lookup(provider:str,indicator:str)->dict:
    from app.services.registry import CAPABILITIES,lookup,load_overrides
    from app.services.provider_runtime import execute
    value=refang(indicator);kind=detect_indicator(value)
    cap=next((c for c in CAPABILITIES if c.name==provider),None)
    if not cap or kind not in cap.types:return {'status':'unsupported_indicator_type'}
    check=validate_indicator(value,kind)
    if not check.get('external_lookup_allowed'):return {'status':'blocked','validation':check}
    if kind=='ip' and check.get('ip_version') not in cap.ip_versions:return {'status':'unsupported_indicator_type'}
    if kind=='hash' and check.get('hash_type') not in cap.hash_types:return {'status':'unsupported_indicator_type'}
    policy=cap.policy_status(load_overrides())
    if policy!='configured':return {'status':policy,'provider':provider}
    async def operation(name,value,kind,meta):return await lookup(cap,value,kind,meta)
    return {'provider':provider,**await execute(cap,check['indicator'],kind,check,operation)}
