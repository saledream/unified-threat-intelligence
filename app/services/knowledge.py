"""Versioned local reference imports. Source content is data, never instructions.

Archives are read in memory, never extracted or executed. License text and source
commit are retained beside the local index; downloaded corpora are not shipped.
"""
import asyncio
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import zipfile
import httpx
import yaml
from app.services import intel_store as store

CORPORA={
    'sigma':{'repo':'SigmaHQ/sigma','branch':'master','prefix':('rules/','rules-emerging-threats/'),'extensions':('.yml','.yaml')},
    'lolbas':{'repo':'LOLBAS-Project/LOLBAS','branch':'master','prefix':('yml/',),'extensions':('.yml','.yaml')},
    'gtfobins':{'repo':'GTFOBins/GTFOBins.github.io','branch':'master','prefix':('_gtfobins/',),'extensions':('',)},
    'hijacklibs':{'repo':'wietze/HijackLibs','branch':'main','prefix':('yml/',),'extensions':('.yml','.yaml')},
    'wadcoms':{'repo':'WADComs/WADComs.github.io','branch':'master','prefix':('_wadcoms/',),'extensions':('.md',)},
    'attack':{'repo':'mitre-attack/attack-stix-data','branch':'master'},
    'd3fend':{'url':'https://d3fend.mitre.org/ontologies/d3fend.json'},
}

async def _download(url,max_bytes=80_000_000):
    # All callers build URLs from the fixed catalog and validated commit IDs.
    async with httpx.AsyncClient(timeout=60,follow_redirects=False,trust_env=False) as client:
        async with client.stream('GET',url,headers={'User-Agent':'MMCY-ThreatIntel/2.0'}) as r:
            r.raise_for_status(); chunks=[]; size=0
            async for chunk in r.aiter_bytes():
                size+=len(chunk)
                if size>max_bytes:raise ValueError('Reference download exceeds size bound')
                chunks.append(chunk)
            return b''.join(chunks)

def parse_archive(name,raw,sha):
    spec=CORPORA[name];rows=[];notices={};total=0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if len(archive.infolist())>50000:raise ValueError('Too many reference files')
        for info in archive.infolist():
            relative='/'.join(PurePosixPath(info.filename).parts[1:])
            if not relative or info.is_dir():continue
            if '..' in PurePosixPath(relative).parts:raise ValueError('Unsafe reference member')
            if info.file_size>2_000_000:continue
            is_notice=Path(relative).name.upper().startswith(('LICENSE','COPYING','NOTICE'))
            eligible=relative.startswith(spec['prefix']) and relative.endswith(spec['extensions'])
            if not eligible and not is_notice:continue
            total+=info.file_size
            if total>100_000_000:raise ValueError('Expanded references exceed size bound')
            text=archive.read(info).decode('utf-8-sig')
            if is_notice:notices[relative]=text;continue
            # Markdown frontmatter is the dataset; the body remains untrusted reference text.
            if name=='gtfobins':
                document=yaml.safe_load(text)
            elif relative.endswith('.md'):
                parts=text.split('---',2)
                if len(parts)<3:continue
                document=yaml.safe_load(parts[1])
            else:document=yaml.safe_load(text)
            if not isinstance(document,dict):continue
            document=json.loads(json.dumps(document,default=str))
            title=str(document.get('title') or document.get('Name') or document.get('name') or Path(relative).stem)
            source=f"https://github.com/{spec['repo']}/blob/{sha}/{relative}"
            rows.append({'id':relative,'kind':name,'value':title,'title':title,
                'data':{'reference':document,'commit':sha,'path':relative,'content_sha256':hashlib.sha256(text.encode()).hexdigest()},'source_url':source})
    if not rows:raise ValueError('No matching references; source layout may have changed')
    if not notices:raise ValueError('Source license/notice is missing')
    return rows,notices

def parse_graph(name,data,source):
    rows=[]
    objects=data.get('objects',[]) if name=='attack' else data.get('@graph',[])
    if not isinstance(objects,list):raise ValueError('Expected reference graph')
    for obj in objects:
        if not isinstance(obj,dict) or obj.get('revoked') or obj.get('x_mitre_deprecated'):continue
        if name=='attack':
            if obj.get('type')!='attack-pattern':continue
            ref=next((r for r in obj.get('external_references',[]) if r.get('source_name')=='mitre-attack'),{})
            ident=ref.get('external_id') or obj.get('id');title=obj.get('name',ident);url=ref.get('url',source)
        else:
            ident=obj.get('@id');label=obj.get('rdfs:label') or obj.get('http://www.w3.org/2000/01/rdf-schema#label')
            if not ident or not label:continue
            if isinstance(label,list):label=label[0] if label else ''
            if isinstance(label,dict):label=label.get('@value','')
            title=str(label);url=source
        rows.append({'id':ident,'kind':name,'value':str(ident),'title':title,'data':obj,'source_url':url})
    if not rows:raise ValueError('No reference objects found')
    return rows

async def sync_corpus(name):
    if name not in CORPORA:return {'status':'invalid_parameter'}
    from app.services.feeds import claim_sync
    lease=await asyncio.to_thread(claim_sync,name,86400,'corpus:')
    if lease:return lease
    spec=CORPORA[name];folder=Path('data/corpora')/name
    try:
        notices={};sha=None
        if name=='d3fend':
            raw=await _download(spec['url']);rows=parse_graph(name,json.loads(raw),spec['url'])
            notices={'source':'https://d3fend.mitre.org/about/','notice':'MITRE D3FEND ontology; retain source attribution and review its terms.'}
        else:
            meta=json.loads(await _download(f"https://api.github.com/repos/{spec['repo']}/commits/{spec['branch']}",2_000_000))
            sha=meta['sha']
            if not re.fullmatch(r'[a-f0-9]{40}',sha):raise ValueError('Invalid source commit')
            if name=='attack':
                source=f"https://raw.githubusercontent.com/{spec['repo']}/{sha}/enterprise-attack/enterprise-attack.json"
                raw=await _download(source);document=json.loads(raw);rows=parse_graph(name,document,source)
                for notice in ('LICENSE.txt',):
                    notices[notice]=(await _download(f"https://raw.githubusercontent.com/{spec['repo']}/{sha}/{notice}",200000)).decode()
                target=Path('data/mitre/enterprise-attack.json');target.parent.mkdir(parents=True,exist_ok=True)
                temporary=target.with_suffix('.tmp');temporary.write_bytes(raw);temporary.replace(target)
                from app.services.mitre_attack import load_attack_data
                load_attack_data.cache_clear()
            else:
                raw=await _download(f"https://codeload.github.com/{spec['repo']}/zip/{sha}")
                rows,notices=await asyncio.to_thread(parse_archive,name,raw,sha)
        folder.mkdir(parents=True,exist_ok=True)
        (folder/'provenance.json').write_text(json.dumps({'source':spec,'commit':sha,'sha256':hashlib.sha256(raw).hexdigest(),'notices':notices},indent=2),encoding='utf-8')
        count=await asyncio.to_thread(store.upsert_records,'corpus:'+name,rows,True)
        return {'status':'success','corpus':name,'records':count,'commit':sha,'provenance':str(folder/'provenance.json')}
    except Exception:
        await asyncio.to_thread(store.sync_status,'corpus:'+name,'error',0,'Reference import failed; previous index preserved')
        return {'status':'error','corpus':name,'reason':'Import failed; previous index preserved. Check provider availability, format and license files.'}

def search_reference(corpus:str,query:str,limit:int=10)->dict:
    if corpus not in CORPORA:return {'status':'invalid_parameter'}
    if not isinstance(query,str) or not 1<=len(query)<=256:return {'status':'invalid_parameter'}
    rows=store.search_records(query,source='corpus:'+corpus,limit=limit)
    exists=any(s['source']=='corpus:'+corpus for s in store.feed_status())
    return {'status':'success' if rows else 'not_found' if exists else 'dataset_missing','corpus':corpus,'records':rows,
        'limitations':['Reference associations require analyst verification. Retrieved commands and rules are never executed.']}

def command_context(command:str,limit:int=5)->dict:
    if not isinstance(command,str) or not 1<=len(command)<=4096:return {'status':'invalid_parameter'}
    # Search executable names only; full command strings may contain secrets.
    tokens=re.findall(r'[A-Za-z][A-Za-z0-9_.-]{1,80}',command)[:12]
    results=[];seen=set()
    for token in tokens:
        for corpus in ('lolbas','gtfobins','wadcoms','hijacklibs'):
            rows=store.search_records(token,source='corpus:'+corpus,limit=min(max(limit,1),10))
            for row in rows:
                key=(corpus,row['record_id'])
                if key not in seen:seen.add(key);results.append(row)
        if len(results)>=20:break
    return {'status':'success' if results else 'not_found','records':results[:20],
        'limitations':['Lexical reference matches only; this is not command execution or proof of malicious intent.']}

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('corpus',choices=CORPORA);args=parser.parse_args()
    print(asyncio.run(sync_corpus(args.corpus)))
