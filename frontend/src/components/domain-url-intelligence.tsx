"use client";

import { useState } from "react";
import { Globe2, Search, ShieldCheck, AlertTriangle, ExternalLink } from "lucide-react";

type Props = { apiFetch: (path: string, init?: RequestInit) => Promise<Response>; role: string };
type Data = Record<string, unknown>;

function pretty(k: string) { return k.replaceAll("_", " ").replace(/\b\w/g, c => c.toUpperCase()); }
function show(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (Array.isArray(v)) return v.length ? v.map(x => typeof x === "object" ? JSON.stringify(x) : String(x)).join(", ") : "None";
  if (typeof v === "object") return JSON.stringify(v, null, 2);
  return String(v);
}

export default function DomainUrlIntelligence({ apiFetch, role }: Props) {
  const [indicator, setIndicator] = useState("");
  const [kind, setKind] = useState<"domain" | "url">("domain");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [validation, setValidation] = useState<Data | null>(null);
  const [result, setResult] = useState<Data | null>(null);
  const canInvestigate = role === "admin" || role === "analyst";

  async function request(path: string, body: Data) {
    const response = await apiFetch(path, { method: "POST", body: JSON.stringify(body) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
    return data as Data;
  }

  async function investigate(e: React.FormEvent) {
    e.preventDefault();
    if (!canInvestigate || !indicator.trim()) return;
    setBusy(true); setError(""); setResult(null); setValidation(null);
    try {
      const checked = await request("/api/indicators/validate", { indicator: indicator.trim(), indicator_type: kind });
      setValidation(checked);
      if (checked.valid !== true || checked.external_lookup_allowed !== true) {
        setError(String(checked.message || checked.reason || "Indicator validation did not permit an external lookup."));
        return;
      }
      const data = kind === "domain"
        ? await request("/api/enrichment/threatfox", { indicator: indicator.trim(), indicator_type: "domain" })
        : await request("/api/enrichment/urlhaus", { url: indicator.trim() });
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The lookup failed.");
    } finally { setBusy(false); }
  }

  return (
    <div className="ip-workspace">
      <section className="search-panel ip-search-panel">
        <div className="search-panel-copy">
          <div className="search-label"><Globe2 size={15}/> DOMAIN AND URL INTELLIGENCE</div>
          <h2>Investigate a domain or URL</h2>
          <p>Query ThreatFox for domain indicators and URLhaus for malicious URL intelligence.</p>
        </div>
        <form className="ip-form" onSubmit={investigate}>
          <label htmlFor="domain-kind">INDICATOR TYPE</label>
          <div className="domain-type-tabs">
            <button type="button" className={kind === "domain" ? "domain-tab-active" : ""} onClick={() => {setKind("domain");setIndicator("");setResult(null);setError("");}}>Domain · ThreatFox</button>
            <button type="button" className={kind === "url" ? "domain-tab-active" : ""} onClick={() => {setKind("url");setIndicator("");setResult(null);setError("");}}>HTTPS URL · URLhaus</button>
          </div>
          <label htmlFor="domain-indicator">{kind === "domain" ? "DOMAIN NAME" : "HTTPS URL"}</label>
          <div className="investigation-search">
            <Globe2 size={18}/>
            <input id="domain-indicator" value={indicator} onChange={e => setIndicator(e.target.value)} placeholder={kind === "domain" ? "e.g. suspicious-example.com" : "https://example.com/path"} autoComplete="off"/>
            <button type="submit" disabled={!indicator.trim() || busy || !canInvestigate}>{busy ? "Searching…" : "Investigate"} <Search size={15}/></button>
          </div>
          <div className="ip-form-options"><span>{kind === "domain" ? "Domain IOCs are checked against ThreatFox." : "URLhaus accepts HTTPS URLs only. No URL submission or download is performed."}</span></div>
        </form>
      </section>

      {!canInvestigate && <div className="notice"><AlertTriangle size={18}/><div><strong>Read-only access</strong><span>Your role cannot submit intelligence lookups. Contact an administrator for analyst access.</span></div></div>}
      {error && <div className="notice ip-error"><AlertTriangle size={18}/><div><strong>Lookup could not be completed</strong><span>{error}</span></div></div>}
      {validation && <section className="panel ip-validation">
        <div className="panel-heading"><div><h2>Indicator validation</h2><p>Validation performed before external lookup</p></div><ShieldCheck size={18}/></div>
        <div className="ip-validation-content">
          <span className={`ip-status ${validation.external_lookup_allowed ? "ip-success" : "ip-warning"}`}>{validation.external_lookup_allowed ? "External lookup allowed" : "External lookup blocked"}</span>
          {Object.entries(validation).filter(([k]) => !["valid","external_lookup_allowed"].includes(k)).map(([k,v]) => <span key={k}><b>{pretty(k)}:</b> {show(v)}</span>)}
        </div>
      </section>}
      {busy && <div className="panel ip-loading"><span className="auth-spinner"/> Querying intelligence provider…</div>}
      {result && <section className="panel ip-result-card">
        <div className="panel-heading"><div><h2>{kind === "domain" ? "ThreatFox result" : "URLhaus result"}</h2><p>Live provider response · {indicator}</p></div><span className={`ip-status ${result.status === "success" ? "ip-success" : "ip-warning"}`}>{pretty(String(result.status ?? "unknown"))}</span></div>
        {typeof result.error === "string" && <p className="ip-provider-error">{result.error}</p>}
        <div className="ip-result-grid">{Object.entries(result).filter(([k,v]) => k !== "status" && k !== "provider" && v !== null && v !== undefined && v !== "").map(([k,v]) => <div className="ip-result-field" key={k}><span>{pretty(k)}</span><strong>{show(v)}</strong></div>)}</div>
        {typeof result.url === "string" && result.url.startsWith("https://") && <a className="ip-external-link" href={result.url} target="_blank" rel="noreferrer">Open reference <ExternalLink size={13}/></a>}
      </section>}
      {!result && !busy && !error && <section className="panel ip-empty"><div className="coming-icon"><ShieldCheck size={25}/></div><h2>Ready for investigation</h2><p>Select a domain or HTTPS URL, enter the indicator and query the corresponding intelligence provider.</p></section>}
      <div className="ip-readonly-note"><ShieldCheck size={15}/> Read-only intelligence. No URL submissions, downloads, blocking or remediation.</div>
    </div>
  );
}
