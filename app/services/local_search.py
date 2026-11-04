"""Agent-friendly source filters: unknown sources are errors, never false empty results."""
from app.services.intel_store import search_records

def search_local(query:str='',source:str|None=None,kind:str|None=None,limit:int=10)->dict:
    from app.services.feeds import FEEDS
    from app.services.knowledge import CORPORA
    filters={**{name:'feed:'+name for name in FEEDS},**{name:'corpus:'+name for name in CORPORA}}
    valid=set(filters.values())
    canonical=None
    if source:
        normalized=source.strip().lower()
        canonical=filters.get(normalized,normalized)
        if canonical not in valid:
            return {'status':'invalid_parameter','error':'Unknown source filter. Use a listed source, not an arbitrary source label.',
                'allowed_sources':sorted(valid)}
    kinds={'ip','domain','url','hash','cve','ja3','certificate','pulse',*CORPORA}
    if len(query)>256 or (kind is not None and kind not in kinds):return {'status':'invalid_parameter'}
    return {'status':'success','source_filter':canonical,'records':search_records(query,kind,canonical,limit),
        'limitations':['These are locally ingested records. No match is not proof of safety or a contradiction of a different source/query. First-seen dates do not confirm current activity.']}
