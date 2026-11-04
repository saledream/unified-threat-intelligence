"use client";
import { useRef, useState, type FormEvent } from "react";
import { ArrowUpRight, ArrowRight, LoaderCircle, Search, Shield } from "lucide-react";
import Link from "next/link";

type Source = Record<string, unknown> & { provider: string; status: string };
type Evidence = { provider: string; kind?: string; malware?: string; classification?: string; reference?: string; first_seen?: string; last_seen?: string };
type Report = { indicator: string; indicator_type?: string; status: string; assessment?: string; assessment_reason?: string; error?: string; providers_checked?: number; providers_eligible?: number; evidence?: Evidence[]; provider_results?: Source[] };
const readable = (s: string) => s.replaceAll("_", " ");
const sourceName = (s: string) => ({virustotal:"VirusTotal",abuseipdb:"AbuseIPDB",greynoise:"GreyNoise",otx:"AlienVault OTX",ipinfo:"IPinfo",cloudflare_radar:"Cloudflare Radar",shodan_internetdb:"Shodan InternetDB",urlscan:"urlscan",rdap:"RDAP",dns_doh:"DNS",certificate_transparency:"Certificate transparency",local_feeds:"Local feeds",malwarebazaar:"MalwareBazaar",threatfox:"ThreatFox",urlhaus:"URLhaus",shodan:"Shodan",pulsedive:"Pulsedive",censys:"Censys",spur:"Spur"}[s] || readable(s));
const statusName = (s: string) => ({success:"Record found",not_found:"No match",no_result:"No match",not_configured:"No API key",requires_authorization:"Access required",forbidden:"Access denied",rate_limited:"Rate limited"}[s] || readable(s));
function safeUrl(value: string) { try { const u=new URL(value); return u.protocol==="https:" && !u.username && !u.password; } catch { return false; } }
function Value({value,depth=0}:{value:unknown;depth?:number}) {
  if(value===null || value===undefined || value==="") return null;
  if(depth>4) return <span>Further detail omitted</span>;
  if(Array.isArray(value)) return <ul>{value.slice(0,20).map((v,i)=><li key={i}><Value value={v} depth={depth+1}/></li>)}</ul>;
  if(typeof value==="object") return <dl>{Object.entries(value).filter(([,v])=>v!==null && v!==undefined && v!=="").map(([k,v])=><div key={k}><dt>{readable(k)}</dt><dd><Value value={v} depth={depth+1}/></dd></div>)}</dl>;
  if(typeof value==="string" && safeUrl(value)) return <a href={value} target="_blank" rel="noopener noreferrer">{value}<ArrowUpRight size={12}/></a>;
  return <span>{String(value)}</span>;
}
export default function Home() {
  const [input,setInput]=useState("");
  const [report,setReport]=useState<Report|null>(null);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState("");
  const inputRef=useRef<HTMLInputElement>(null);
  async function search(event:FormEvent) {
    event.preventDefault(); if(!input.trim() || busy) return;
    setBusy(true);setError("");setReport(null);
    try {
      const response=await fetch('/api/enrichment/unified',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({indicator:input.trim()}),signal:AbortSignal.timeout(65000)});
      const data=await response.json();
      if(!response.ok) throw new Error(typeof data.detail==='string'?data.detail:'Search could not be completed. Try again.');
      if(data.error && !data.provider_results) setError(data.error); else setReport(data);
    } catch(e) {setError(e instanceof Error && (e.name==='TimeoutError' || e.name==='AbortError')?'Search timed out. Please try again.':e instanceof Error?e.message:'Search could not be completed.');}
    finally {setBusy(false);}
  }
  const sources=report?.provider_results || [];
  const visible=sources.filter(s=>!['disabled','unsupported_indicator_type','not_configured','requires_authorization'].includes(s.status));
  const unavailable=sources.filter(s=>!visible.includes(s));
  const verdict=report?.assessment || report?.status || '';
  return <main className={report?'app has-results':'app'}>
    <header className="topbar"><Link href="/" className="wordmark" aria-label="Threat Intelligence home"><span className="brand-icon"><Shield size={17}/></span>Threat Intelligence</Link></header>
    <div className="content">
      <section className="search-section">
        <h1>Investigate an indicator.</h1>
        <form onSubmit={search} className="search-box" aria-label="Indicator search">
          <Search size={21} className="search-icon"/>
          <label className="sr-only" htmlFor="indicator">IP address, domain, URL, or file hash</label>
          <input ref={inputRef} id="indicator" value={input} onChange={e=>setInput(e.target.value)} placeholder="IP address, domain, URL, or file hash" autoComplete="off" spellCheck={false} maxLength={4096} required disabled={busy}/>
          <button type="submit" disabled={busy || !input.trim()} aria-label={busy?'Searching':'Search'}>{busy?<LoaderCircle size={20} className="spin"/>:<ArrowRight size={21}/>}</button>
        </form>
      </section>
      {busy && <div className="loading-state" role="status"><LoaderCircle size={19} className="spin"/>Checking sources…</div>}
      {error && <div className="error-state" role="alert">{error}</div>}
      {report && <section className="results" aria-label="Search results" aria-live="polite">
        <div className="result-heading"><div><span className="eyebrow">{report.indicator_type || 'INDICATOR'}</span><h2>{report.indicator}</h2></div><span className={`verdict ${['suspicious','malicious'].includes(verdict)?'warning':''}`}>{readable(verdict)}</span></div>
        <p className="assessment">{report.assessment_reason || report.error}</p>
        <div className="result-meta"><span>{report.providers_checked ?? 0} / {report.providers_eligible ?? sources.length} sources completed</span><span>Passive lookup</span></div>
        {!!report.evidence?.length && <div className="evidence-list">{report.evidence.map((e,i)=><article className="evidence" key={i}><span className="evidence-dot"/><div><strong>{e.malware || e.classification || readable(e.kind || 'Threat evidence')}</strong><p>{sourceName(e.provider)}{e.first_seen?` · First seen ${e.first_seen}`:''}{e.last_seen?` · Last seen ${e.last_seen}`:''}</p></div>{e.reference && safeUrl(e.reference) && <a href={e.reference} target="_blank" rel="noopener noreferrer" aria-label="Open evidence source"><ArrowUpRight size={18}/></a>}</article>)}</div>}
        <div className="source-list">{visible.map((source,i)=><details className="source" key={i}><summary><span className="source-symbol">{source.provider.slice(0,1).toUpperCase()}</span><strong>{sourceName(source.provider)}</strong><span className={`source-status ${source.status==='success'?'found':''}`}>{statusName(source.status)}</span><span className="expand">+</span></summary><div className="source-detail"><Value value={Object.fromEntries(Object.entries(source).filter(([k])=>!['provider','status','source_reliability','provenance_group'].includes(k)))}/></div></details>)}</div>
        {!!unavailable.length && <details className="unavailable"><summary>{unavailable.length} unavailable sources</summary><div>{unavailable.map((s,i)=><p key={i}><span>{sourceName(s.provider)}</span><span>{statusName(s.status)}</span></p>)}</div></details>}
        {!visible.length && <p className="empty-result">No source reports are available for this search.</p>}
        <p className="result-footnote">No match does not establish safety. Expand a source to review its evidence.</p>
      </section>}
    </div>
    <footer>Passive intelligence. Indicators are shared with connected providers.</footer>
  </main>;
}
