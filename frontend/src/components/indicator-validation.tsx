"use client";

import { useState } from "react";
import { ShieldCheck, Search, AlertTriangle, CheckCircle2, XCircle, Fingerprint } from "lucide-react";

type Props = { apiFetch: (path: string, init?: RequestInit) => Promise<Response>; role: string };
type Data = Record<string, unknown>;

const types = [
  { value: "ip", label: "IP address" },
  { value: "domain", label: "Domain" },
  { value: "url", label: "URL" },
  { value: "hash", label: "File hash" },
];

function pretty(k: string) { return k.replaceAll("_", " ").replace(/\b\w/g, c => c.toUpperCase()); }
function show(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—";
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (Array.isArray(v)) return v.length ? v.map(x => typeof x === "object" ? JSON.stringify(x) : String(x)).join(", ") : "None";
  if (typeof v === "object") return JSON.stringify(v, null, 2);
  return String(v);
}

export default function IndicatorValidation({ apiFetch, role }: Props) {
  const [indicator, setIndicator] = useState("");
  const [kind, setKind] = useState("ip");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Data | null>(null);
  const canValidate = role === "admin" || role === "analyst";

  async function validate(e: React.FormEvent) {
    e.preventDefault();
    if (!canValidate || !indicator.trim()) return;
    setBusy(true); setError(""); setResult(null);
    try {
      const response = await apiFetch("/api/indicators/validate", {
        method: "POST",
        body: JSON.stringify({ indicator: indicator.trim(), indicator_type: kind }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
      setResult(data as Data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Validation failed.");
    } finally { setBusy(false); }
  }

  return (
    <div className="ip-workspace">
      <section className="search-panel ip-search-panel">
        <div className="search-panel-copy">
          <div className="search-label"><ShieldCheck size={15}/> INDICATOR VALIDATION</div>
          <h2>Validate an indicator</h2>
          <p>Check syntax, normalization, indicator type and whether external intelligence lookups are permitted.</p>
        </div>
        <form className="ip-form" onSubmit={validate}>
          <label htmlFor="validation-type">INDICATOR TYPE</label>
          <div className="domain-type-tabs">
            {types.map(t => <button key={t.value} type="button" className={kind === t.value ? "domain-tab-active" : ""} onClick={() => {setKind(t.value);setResult(null);setError("");}}>{t.label}</button>)}
          </div>
          <label htmlFor="validation-indicator">INDICATOR VALUE</label>
          <div className="investigation-search">
            <Fingerprint size={18}/>
            <input id="validation-indicator" value={indicator} onChange={e => setIndicator(e.target.value)} placeholder="Enter indicator to validate…" autoComplete="off" spellCheck={false}/>
            <button type="submit" disabled={!indicator.trim() || busy || !canValidate}>{busy ? "Validating…" : "Validate"} <Search size={15}/></button>
          </div>
          <div className="ip-form-options"><span>Validation only · No external provider is queried.</span></div>
        </form>
      </section>

      {!canValidate && <div className="notice"><AlertTriangle size={18}/><div><strong>Read-only access</strong><span>Your role cannot submit validation requests. Contact an administrator for analyst access.</span></div></div>}
      {error && <div className="notice ip-error"><AlertTriangle size={18}/><div><strong>Validation request failed</strong><span>{error}</span></div></div>}
      {busy && <div className="panel ip-loading"><span className="auth-spinner"/> Validating indicator…</div>}

      {result && <section className="panel ip-result-card">
        <div className="panel-heading">
          <div><h2>Validation result</h2><p>{indicator}</p></div>
          {result.valid === true
            ? <span className="ip-status ip-success"><CheckCircle2 size={12}/> Valid</span>
            : <span className="ip-status ip-warning"><XCircle size={12}/> Invalid</span>}
        </div>
        <div className="ip-validation-content">
          <span className={`ip-status ${result.external_lookup_allowed === true ? "ip-success" : "ip-warning"}`}>
            {result.external_lookup_allowed === true ? "External lookup allowed" : "External lookup not allowed"}
          </span>
        </div>
        <div className="ip-result-grid">
          {Object.entries(result).map(([k,v]) => <div className="ip-result-field" key={k}><span>{pretty(k)}</span><strong>{show(v)}</strong></div>)}
        </div>
      </section>}

      {!result && !busy && !error && <section className="panel ip-empty"><div className="coming-icon"><ShieldCheck size={25}/></div><h2>Ready to validate</h2><p>Choose an indicator type and enter a value. Validation does not contact external intelligence providers.</p></section>}
      <div className="ip-readonly-note"><ShieldCheck size={15}/> Validation is separate from enrichment. A valid indicator is not necessarily malicious or safe.</div>
    </div>
  );
}
