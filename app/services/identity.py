"""Opt-in breach context; no recovered passwords, cookies, or credential dumps."""
import os
import re
from urllib.parse import quote
from app.providers.http import request
from app.services.indicators import validate_indicator
from app.services.provider_runtime import execute
from app.services.registry import Capability

async def _paced(name,operation):
    # No identity cache: pacing and request concurrency only.
    cap=Capability(name,(),'',retries=0,cache_ttl_seconds=0,min_interval_seconds=1.5)
    async def run(*args):return await operation()
    return await execute(cap,'private-uncached','identity',{},run)

def disclosure_allowed(allow):
    if os.getenv('ENABLE_IDENTITY_LOOKUPS','false').lower()!='true':return {'status':'disabled'}
    if allow is not True:return {'status':'requires_consent','reason':'This lookup discloses the identifier to the selected provider. Explicitly authorize this lookup.'}

async def password_check_sha1(sha1:str)->dict:
    if not isinstance(sha1,str) or not re.fullmatch(r'[a-fA-F0-9]{40}',sha1):
        return {'status':'invalid_parameter','reason':'Hash the password locally with SHA-1; supply only the 40-character digest. Never put a password in chat.'}
    digest=sha1.upper()
    async def lookup():
        r=await request('GET','https://api.pwnedpasswords.com/range/'+digest[:5],headers={'Add-Padding':'true'},text=True,max_bytes=1_000_000)
        if r['status']!='success':return r
        count=0
        for line in r['data'].splitlines():
            suffix,sep,number=line.partition(':')
            if sep and suffix.upper()==digest[5:] and number.strip().isdigit():count=int(number.strip())
        return {'status':'success','found':count>0,'occurrences':count,'source_url':'https://haveibeenpwned.com/Passwords',
            'disclosed':'Only the first five SHA-1 characters were sent; neither plaintext nor the complete digest was sent.',
            'limitations':['A missing match does not establish password strength or safety.']}
    return await _paced('pwned_passwords',lookup)

async def check_breach(identifier:str,provider:str='hibp',allow_external_disclosure:bool=False)->dict:
    error=disclosure_allowed(allow_external_disclosure)
    if error:return error
    if not isinstance(identifier,str) or len(identifier)>254:return {'status':'invalid_parameter'}
    value=identifier.strip()
    if not re.fullmatch(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',value):return {'status':'invalid_parameter','reason':'Expected an email address'}
    if provider not in ('hibp','leakcheck','hudsonrock'):return {'status':'invalid_provider'}
    if provider in ('hibp','hudsonrock') and not os.getenv('HIBP_API_KEY' if provider=='hibp' else 'HUDSONROCK_API_KEY'):
        return {'status':'not_configured','provider':provider}
    async def lookup():
        if provider=='hibp':
            r=await request('GET','https://haveibeenpwned.com/api/v3/breachedaccount/'+quote(value,safe=''),headers={'hibp-api-key':os.environ['HIBP_API_KEY']})
            if r['status']!='success':return r
            if not isinstance(r['data'],list):return {'status':'invalid_response'}
            return {'status':'success','provider':provider,'breaches':r['data'][:50],'source_url':'https://haveibeenpwned.com/'}
        if provider=='leakcheck':
            r=await request('GET','https://leakcheck.io/api/public',params={'check':value})
            if r['status']!='success':return r
            d=r['data']
            if not isinstance(d,dict) or d.get('success') is not True:return {'status':'provider_error'}
            return {'status':'success','provider':provider,'found':d.get('found'),'fields':d.get('fields',[]),'sources':d.get('sources',[])[:50],
                'attribution':'Powered by LeakCheck','source_url':'https://leakcheck.io/'}
        r=await request('POST','https://api.hudsonrock.com/json/v3/search-by-login/emails',
            headers={'api-key':os.environ['HUDSONROCK_API_KEY']},json={'logins':[value],'limit':10})
        if r['status']!='success':return r
        d=r['data']
        if not isinstance(d,dict) or not isinstance(d.get('data'),list):return {'status':'invalid_response'}
        # Project metadata only. Never return credential/password/session fields.
        rows=[{k:row[k] for k in ('stealer_family','date_compromised','date_uploaded') if k in row} for row in d['data'][:10] if isinstance(row,dict)]
        return {'status':'success','provider':provider,'exposures':rows,'truncated':bool(d.get('nextCursor')),'source_url':'https://www.hudsonrock.com/'}
    return await _paced('identity_'+provider,lookup)

async def domain_breaches(domain:str,allow_external_disclosure:bool=False)->dict:
    'Read HIBP breach metadata for a verified public domain, with explicit disclosure consent and enabled identity policy. Requires an entitled HIBP key; returns counts and breach names, not user aliases.'
    error=disclosure_allowed(allow_external_disclosure)
    if error:return error
    check=validate_indicator(domain,'domain')
    if not check.get('external_lookup_allowed'):return {'status':'invalid_indicator'}
    if not os.getenv('HIBP_API_KEY'):return {'status':'not_configured'}
    async def lookup():
        r=await request('GET','https://haveibeenpwned.com/api/v3/breacheddomain/'+quote(check['indicator'],safe=''),headers={'hibp-api-key':os.environ['HIBP_API_KEY']})
        if r['status']!='success':return r
        d=r['data']
        if not isinstance(d,dict):return {'status':'invalid_response'}
        # Counts and breach names only; avoid sending every user's alias into agent context.
        names=sorted({name for values in d.values() if isinstance(values,list) for name in values if isinstance(name,str)})
        return {'status':'success','affected_alias_count':len(d),'breaches':names[:100],'source_url':'https://haveibeenpwned.com/',
            'limitations':['HIBP requires a verified domain and a subscription with domain-search access.']}
    return await _paced('identity_hibp',lookup)

async def latest_breach()->dict:
    """Read public metadata for the most recently added HIBP breach. Does not query an individual account or establish that an IOC is malicious."""
    r=await request('GET','https://haveibeenpwned.com/api/v3/latestbreach')
    return {'status':r['status'],'breach':r.get('data'),'source_url':'https://haveibeenpwned.com/'}
