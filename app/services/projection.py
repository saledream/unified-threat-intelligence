"""A bounded agent projection; full source reports remain available in the API."""
import json

def compact_result(result,max_chars=28000):
    remaining=max_chars-1000;truncated=False
    def visit(value,depth=0):
        nonlocal remaining,truncated
        if remaining<=0 or depth>10:
            truncated=True;return '[truncated]'
        if isinstance(value,dict):
            out={}
            for key,item in list(value.items())[:60]:
                remaining-=len(str(key))+8
                if remaining<=0:truncated=True;break
                out[key]=visit(item,depth+1)
            if len(value)>60:truncated=True
            return out
        if isinstance(value,(list,tuple)):
            out=[]
            for item in value[:30]:
                if remaining<=0:truncated=True;break
                out.append(visit(item,depth+1))
            if len(value)>30:truncated=True
            return out
        if isinstance(value,str):
            length=min(len(value),4000,max(0,remaining));remaining-=length+4
            if length<len(value):truncated=True
            return value[:length]
        remaining-=len(str(value))+4
        return value
    value=visit(result)
    if isinstance(value,dict) and truncated:
        value['output_truncated']=True
        value['output_note']='Agent projection truncated; narrow the query or inspect source records through the dashboard/API.'
    # Escaping can expand arbitrary Unicode/control strings. Preserve a hard wire bound.
    if len(json.dumps(value,ensure_ascii=True))>max_chars:
        return {'status':result.get('status','success') if isinstance(result,dict) else 'success',
            'output_truncated':True,'output_note':'Result exceeds the agent output bound. Narrow the query or use the dashboard/API.'}
    return value
