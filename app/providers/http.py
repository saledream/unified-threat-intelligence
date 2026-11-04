"""Bounded HTTPS calls to explicitly supported provider hosts. No target URL fetches."""
import json as json_module
import logging
import re

class RedactQueryCredentials(logging.Filter):
    def filter(self,record):
        message=record.getMessage()
        message=re.sub(r'(https://(?:haveibeenpwned\.com|leakcheck\.io|api\.hudsonrock\.com)/)[^\s\"]+',r'\1[PRIVATE-LOOKUP]',message)
        record.msg=re.sub(r"([?&](?:key|token|api_key|apikey)=)[^&\s\"]+",r"\1[REDACTED]",message,flags=re.I)
        record.args=()
        return True

logging.getLogger("httpx").addFilter(RedactQueryCredentials())
from urllib.parse import urlsplit
import httpx

ALLOWED_HOSTS=frozenset({
 'internetdb.shodan.io','api.shodan.io','api.ipinfo.io','pulsedive.com','api.spur.us','api.platform.censys.io',
 'api.cloudflare.com','crt.sh','cloudflare-dns.com','api.first.org','services.nvd.nist.gov',
 'www.cisa.gov','haveibeenpwned.com','api.pwnedpasswords.com','cavalier.hudsonrock.com',
 'leakcheck.io','sslbl.abuse.ch','feodotracker.abuse.ch','openphish.com','yaraify-api.abuse.ch',
 'otx.alienvault.com','threatfox-api.abuse.ch','urlhaus-api.abuse.ch','mb-api.abuse.ch',
 'urlscan.io','www.virustotal.com','raw.githubusercontent.com','api.hudsonrock.com',
})

async def request(method,url,*,params=None,headers=None,data=None,json=None,files=None,text=False,max_bytes=5_000_000,timeout=15):
    parsed=urlsplit(url)
    if parsed.scheme!='https' or parsed.hostname not in ALLOWED_HOSTS or parsed.username or parsed.password or parsed.port not in (None,443):
        return {'status':'blocked','error':'Unsupported external provider destination'}
    safe_headers={'Accept':'application/json','User-Agent':'MMCY-ThreatIntel/2.0',**(headers or {})}
    try:
        async with httpx.AsyncClient(timeout=timeout,follow_redirects=False,trust_env=False) as client:
            async with client.stream(method,url,params=params,headers=safe_headers,data=data,json=json,files=files) as response:
                status=response.status_code
                if status in (401,403):return {'status':'unauthorized' if status==401 else 'forbidden','http_status':status}
                if status==404:return {'status':'not_found'}
                if status==429:return {'status':'rate_limited','retry_after':response.headers.get('Retry-After')}
                if 300<=status<400:return {'status':'skipped','reason':'Provider redirect was not followed'}
                if status>=400:return {'status':'provider_error','http_status':status}
                chunks=[];size=0
                async for chunk in response.aiter_bytes():
                    size+=len(chunk)
                    if size>max_bytes:return {'status':'invalid_response','error':'Provider response exceeds configured size bound'}
                    chunks.append(chunk)
                raw=b''.join(chunks)
                payload=raw.decode('utf-8-sig') if text else json_module.loads(raw)
                return {'status':'success','data':payload,'source_url':url,'http_status':status}
    except httpx.TimeoutException:return {'status':'timeout'}
    except (httpx.RequestError,OSError):return {'status':'connection_error'}
    except (ValueError,UnicodeError):return {'status':'invalid_response'}
