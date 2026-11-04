"use client";

import { useState } from "react";
import { FileSearch, Search, ShieldCheck, AlertTriangle, ExternalLink, Fingerprint } from "lucide-react";

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

export default function FileHashIntelligence({ apiFetch, role }: Props) {
  const [hash, setHash] = useState("");
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
    if (!canInvestigate || !hash.trim()) return;
    setBusy(true); setError(""); setResult(null); setValidation(null);
    try {
      const checked = await request("/api/indicators/validate", { indicator: hash.trim(), indicator_type: "hash" });
      setValidation(checked);
      if (checked.valid !== true || checked.external_lookup_allowed !== true) {
        setError(String(checked.message || checked.reason || "Hash validation failed or external lookup is not permitted."));
        return;
      }
      setResult(await request("/api/enrichment/hash", { file_hash: hash.trim() }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "The lookup failed.");
    } finally { setBusy(false); }
  }

  const hashLength = hash.trim().length;
  const hashType = hashLength === 32 ? "MD5" : hashLength === 40 ? "SHA-1" : hashLength === 64 ? "SHA-256" : "Unknown hash format";

  return (
    <div className="ip-workspace">
      <section className="search-panel ip-search-panel">
        <div className="search-panel-copy">
          <div className="search-label"><FileSearch size={15}/> FILE HASH INTELLIGENCE</div>
          <h2>Investigate a file hash</h2>
          <p>Look up known file indicators using MalwareBazaar. Only the hash is queried; no file is uploaded.</p>
        </div>
        <form className="ip-form" onSubmit={investigate}>
          <label htmlFor="file-hash">FILE HASH · MD5 / SHA-1 / SHA-256</label>
          <div className="investigation-search">
            <Fingerprint size={18}/>
            <input id="file-hash" value={hash} onChange={e => setHash(e.target.value)} placeholder="Paste a file hash…" autoComplete="off" spellCheck={false}/>
            <button type="submit" disabled={!hash.trim() || busy || !canInvestigate}>{busy ? "Searching…" : "Investigate"} <Search size={15}/></button>
          </div>
          <div className="ip-form-options"><span>Detected format: <strong>{hashType}</strong> · {hashLength} characters</span><span>Provider: MalwareBazaar</span></div>
        </form>
      </section>

      {!canInvestigate && <div className="notice"><AlertTriangle size={18}/><div><strong>Read-only access</strong><span>Your role cannot submit intelligence lookups. Contact an administrator for analyst access.</span></div></div>}
      {error && <div className="notice ip-error"><AlertTriangle size={18}/><div><strong>Lookup could not be completed</strong><span>{error}</span></div></div>}
      {validation && <section className="panel ip-validation">
        <div className="panel-heading"><div><h2>Hash validation</h2><p>Validation performed before external lookup</p></div><ShieldCheck size={18}/></div>
        <div className="ip-validation-content">
          <span className={`ip-status ${validation.external_lookup_allowed ? "ip-success" : "ip-warning"}`}>{validation.external_lookup_allowed ? "External lookup allowed" : "External lookup blocked"}</span>
          {Object.entries(validation).filter(([k]) => !["valid","external_lookup_allowed"].includes(k)).map(([k,v]) => <span key={k}><b>{pretty(k)}:</b> {show(v)}</span>)}
        </div>
      </section>}
      {busy && <div className="panel ip-loading"><span className="auth-spinner"/> Querying MalwareBazaar…</div>}
      {result && <section className="panel ip-result-card">
        <div className="panel-heading"><div><h2>MalwareBazaar result</h2><p>Live provider response · {hash}</p></div><span className={`ip-status ${result.status === "success" ? "ip-success" : "ip-warning"}`}>{pretty(String(result.status ?? "unknown"))}</span></div>
        {typeof result.error === "string" && <p className="ip-provider-error">{result.error}</p>}
        <div className="ip-result-grid">{Object.entries(result).filter(([k,v]) => k !== "status" && k !== "provider" && v !== null && v !== undefined && v !== "").map(([k,v]) => <div className="ip-result-field" key={k}><span>{pretty(k)}</span><strong>{show(v)}</strong></div>)}</div>
        {typeof result.permalink === "string" && result.permalink.startsWith("https://") && <a className="ip-external-link" href={result.permalink} target="_blank" rel="noreferrer">Open MalwareBazaar reference <ExternalLink size={13}/></a>}
      </section>}
      {!result && !busy && !error && <section className="panel ip-empty"><div className="coming-icon"><FileSearch size={25}/></div><h2>Ready for hash lookup</h2><p>Paste an MD5, SHA-1 or SHA-256 hash to check MalwareBazaar for available file intelligence.</p></section>}
      <div className="ip-readonly-note"><ShieldCheck size={15}/> Read-only lookup. Files are never uploaded, executed, downloaded or quarantined.</div>
    </div>
  );
}
