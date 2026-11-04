"use client";

import { useState } from "react";
import { Search, RefreshCw, ShieldCheck, AlertTriangle, Globe2, Activity, ExternalLink } from "lucide-react";

type Result = Record<string, unknown>;
type Props = { apiFetch: (path: string, init?: RequestInit) => Promise<Response>; role: string };

const providers = [
  { key: "abuseipdb", name: "AbuseIPDB", path: "/api/enrichment/ip/abuseipdb" },
  { key: "greynoise", name: "GreyNoise", path: "/api/enrichment/ip/greynoise" },
  { key: "otx", name: "AlienVault OTX", path: "/api/enrichment/ip/otx" },
] as const;

function label(key: string) {
  return key.replaceAll("_", " ").replace(/\b\w/g, c => c.toUpperCase());
}
function display(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.length ? value.map(v => typeof v === "object" ? JSON.stringify(v) : String(v)).join(", ") : "None";
  if (typeof value === "object") return JSON.stringify(value, null, 2);
  return String(value);
}
function ResultCard({ name, data }: { name: string; data: Result }) {
  const status = String(data.status ?? "unknown");
  const entries = Object.entries(data).filter(([k, v]) => k !== "provider" && k !== "status" && v !== null && v !== undefined && v !== "");
  return (
    <section className="panel ip-result-card">
      <div className="panel-heading">
        <div><h2>{name}</h2><p>Provider response</p></div>
        <span className={`ip-status ${status === "success" ? "ip-success" : status === "not_found" ? "ip-neutral" : "ip-warning"}`}>{label(status)}</span>
      </div>
      {status !== "success" && data.error ? <p className="ip-provider-error">{String(data.error)}</p> : null}
      <div className="ip-result-grid">
        {entries.map(([key, value]) => (
          <div className="ip-result-field" key={key}>
            <span>{label(key)}</span>
            <strong>{typeof value === "object" ? display(value) : display(value)}</strong>
          </div>
        ))}
      </div>
      {typeof data.link === "string" && data.link.startsWith("https://") ? <a className="ip-external-link" href={data.link} target="_blank" rel="noreferrer">Open provider record <ExternalLink size={13}/></a> : null}
    </section>
  );
}

export default function IpIntelligence({ apiFetch, role }: Props) {
  const [ip, setIp] = useState("");
  const [maxAge, setMaxAge] = useState("90");
  const [results, setResults] = useState<Record<string, Result> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [validation, setValidation] = useState<Result | null>(null);
  const canInvestigate = role === "admin" || role === "analyst";

  async function lookup(path: string, body: Record<string, unknown>) {
    const response = await apiFetch(path, { method: "POST", body: JSON.stringify(body) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
    return data;
  }

  async function run(mode: "all" | "abuseipdb" | "greynoise" | "otx") {
    if (!canInvestigate) return;
    setBusy(true); setError(""); setResults(null); setValidation(null);
    try {
      const check = await lookup("/api/indicators/validate", { indicator: ip.trim(), indicator_type: "ip" });
      setValidation(check);
      if (check.valid !== true || check.external_lookup_allowed !== true) {
        setError(String(check.message || check.reason || "This IP is not eligible for external intelligence lookup."));
        return;
      }
      const body = { ip: ip.trim(), max_age_days: Number(maxAge) };
      if (mode === "all") {
        const data = await lookup("/api/enrichment/ip", body);
        setResults(data.results ?? data);
      } else {
        const data = await lookup(providers.find(p => p.key === mode)!.path, body);
        setResults({ [mode]: data });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "The lookup could not be completed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="ip-workspace">
      <section className="search-panel ip-search-panel">
        <div className="search-panel-copy">
          <div className="search-label"><Activity size={15}/> MULTI-SOURCE IP INVESTIGATION</div>
          <h2>Investigate a public IP address</h2>
          <p>Query AbuseIPDB, GreyNoise and AlienVault OTX. Lookups are read-only.</p>
        </div>
        <form className="ip-form" onSubmit={e => { e.preventDefault(); void run("all"); }}>
          <label htmlFor="ip-address">IP ADDRESS</label>
          <div className="investigation-search">
            <Globe2 size={18}/>
            <input id="ip-address" value={ip} onChange={e => setIp(e.target.value)} placeholder="e.g. 8.8.8.8" autoComplete="off" />
            <button type="submit" disabled={!ip.trim() || busy || !canInvestigate}>{busy ? "Investigating…" : "Enrich IP"} <Search size={15}/></button>
          </div>
          <div className="ip-form-options">
            <label htmlFor="max-age">AbuseIPDB report window</label>
            <select id="max-age" value={maxAge} onChange={e => setMaxAge(e.target.value)} disabled={busy}>
              <option value="30">30 days</option><option value="90">90 days</option><option value="180">180 days</option><option value="365">365 days</option>
            </select>
            <span>Only globally routable public IPs are queried.</span>
          </div>
        </form>
      </section>

      {!canInvestigate && <div className="notice"><AlertTriangle size={18}/><div><strong>Read-only access</strong><span>Your account role can view this page but cannot submit intelligence lookups. Contact an administrator if you need analyst access.</span></div></div>}
      {error && <div className="notice ip-error"><AlertTriangle size={18}/><div><strong>Lookup could not be completed</strong><span>{error}</span></div></div>}
      {validation && <section className="panel ip-validation">
        <div className="panel-heading"><div><h2>Indicator validation</h2><p>Backend validation before external provider requests</p></div><ShieldCheck size={18}/></div>
        <div className="ip-validation-content">
          <span className={`ip-status ${validation.external_lookup_allowed ? "ip-success" : "ip-warning"}`}>{validation.external_lookup_allowed ? "External lookup allowed" : "External lookup blocked"}</span>
          {Object.entries(validation).filter(([k]) => !["valid", "external_lookup_allowed"].includes(k)).map(([k,v]) => <span key={k}><b>{label(k)}:</b> {display(v)}</span>)}
        </div>
      </section>}
      <div className="ip-provider-actions">
        <div><h2>Provider lookups</h2><p>Run a combined investigation or query an individual source.</p></div>
        {providers.map(provider => <button key={provider.key} className="ip-secondary-button" disabled={!ip.trim() || busy || !canInvestigate} onClick={() => void run(provider.key)}>{provider.name}</button>)}
        <button className="ip-secondary-button" disabled={!ip.trim() || busy || !canInvestigate} onClick={() => void run("all")}><RefreshCw size={14}/> Run all</button>
      </div>
      {busy && <div className="panel ip-loading"><span className="auth-spinner"/> Querying intelligence providers. Please wait…</div>}
      {results && <div className="ip-results">
        <div className="section-title-row"><div><h2>Intelligence results</h2><p>Live provider responses for {ip.trim()}</p></div><span className="demo-label">LIVE LOOKUP</span></div>
        <div className="ip-result-cards">
          {providers.filter(p => results[p.key]).map(p => <ResultCard key={p.key} name={p.name} data={results[p.key]}/>)}
        </div>
        {Object.keys(results).length === 0 && <div className="panel ip-loading">The API returned no provider results.</div>}
      </div>}
      {!results && !busy && !error && <section className="panel ip-empty">
        <div className="coming-icon"><ShieldCheck size={25}/></div>
        <h2>Ready for investigation</h2>
        <p>Enter a public IP address and run a combined lookup to retrieve independent intelligence from the configured providers.</p>
      </section>}
      <div className="ip-readonly-note"><ShieldCheck size={15}/> Read-only intelligence. No blocking, remediation, or endpoint actions are performed.</div>
    </div>
  );
}
