"use client";
import { useState, type FormEvent } from "react";
import { useAuth } from "@/lib/auth";

type RecordData = Record<string, unknown>;
type Evidence = { provider: string; kind?: string; malware?: string; classification?: string; confidence?: number; reference?: string; first_seen?: string; last_seen?: string };
type ProviderResult = RecordData & { provider: string; status: string; query_indicator?: string; query_type?: string };
type Intelligence = { indicator: string; indicator_type?: string; indicator_subtype?: string; request_id?: string; generated_at?: string; assessment?: string; assessment_reason?: string; status: string; error?: string; evidence?: Evidence[]; provider_results?: ProviderResult[]; providers_skipped?: ProviderResult[]; providers_checked?: number; providers_eligible?: number; limitations?: string[]; recommended_steps?: string[]; normalized_representations?: Record<string, string> };
const label = (value: string) => value.replaceAll("_", " ");
const states: Record<string, string> = { success: "Record returned", not_found: "No match", no_result: "No match", not_configured: "Not configured", requires_authorization: "Requires authorization", disabled: "Disabled", unsupported_indicator_type: "Unsupported type", skipped: "Skipped", timeout: "Timed out", rate_limited: "Rate limited" };
function safeLink(value: string) {
  try { const u = new URL(value); return u.protocol === "https:" && !u.username && !u.password; } catch { return false; }
}
function Details({ value, depth = 0 }: { value: unknown; depth?: number }) {
  if (value === null || value === undefined || value === "") return null;
  if (depth > 5) return <span>Open the source record for further detail.</span>;
  if (Array.isArray(value)) return <ul className="intel-detail-list">{value.slice(0, 20).map((v, i) => <li key={i}><Details value={v} depth={depth + 1} /></li>)}</ul>;
  if (typeof value === "object") return <dl className="intel-details">{Object.entries(value).filter(([, v]) => v !== null && v !== undefined && v !== "").map(([k, v]) => <div key={k}><dt>{label(k)}</dt><dd><Details value={v} depth={depth + 1} /></dd></div>)}</dl>;
  return <span>{String(value)}</span>;
}
export default function UnifiedIntelligence({ initialIndicator = "" }: { initialIndicator?: string }) {
  const { apiFetch, user } = useAuth();
  const [indicator, setIndicator] = useState(initialIndicator);
  const [result, setResult] = useState<Intelligence | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const allowed = user?.role === "admin" || user?.role === "analyst";
  async function investigate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!indicator.trim() || loading || !allowed) return;
    setLoading(true); setResult(null); setError("");
    try {
      const response = await apiFetch("/api/enrichment/unified", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ indicator: indicator.trim() }), signal: AbortSignal.timeout(65000) });
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : `Request failed (${response.status})`);
      setResult(data);
    } catch (err) { setError(err instanceof Error ? err.message : "Investigation failed"); }
    finally { setLoading(false); }
  }
  return <section className="intel-workspace" aria-label="Unified investigation" aria-busy={loading}>
    <section className="search-panel">
      <div className="search-panel-copy"><div className="search-label">UNIFIED INVESTIGATION</div><h2>One indicator. All applicable sources.</h2><p>Enter an IP, public hostname, HTTP/HTTPS URL, MD5, SHA1 or SHA256. Type detection and routing are automatic.</p></div>
      <form onSubmit={investigate} className="intel-form">
        <label htmlFor="ioc">Indicator to investigate</label>
        <div className="intel-input-row"><input id="ioc" value={indicator} onChange={e => setIndicator(e.target.value)} placeholder="Enter an indicator" maxLength={4096} disabled={loading || !allowed} autoComplete="off" spellCheck={false} required /><button className="primary-button" type="submit" disabled={loading || !indicator.trim() || !allowed}>{loading ? "Checking sources…" : "Investigate"}</button></div>
        <p className="intel-note">Passive lookups share this indicator with eligible external providers. Submit only indicators approved for external disclosure.</p>
        {!allowed && <p role="status">An analyst or administrator role is required to investigate indicators.</p>}
      </form>
    </section>
    {loading && <div role="status" className="panel intel-status">Querying applicable sources and correlating evidence. Results include any failures; the search has a bounded deadline.</div>}
    {error && <div className="notice" role="alert">{error}</div>}
    {!loading && !result && !error && <div className="panel intel-status"><h3>Ready to investigate</h3><p>Source records, threat evidence and coverage gaps will appear here.</p></div>}
    {result && <div className="intel-workspace" aria-live="polite">
      <section className="panel intel-status"><div className="search-label">{result.indicator_subtype || result.indicator_type || "Unknown type"} · {label(result.status)}</div><h2>{label(result.assessment || result.status)}</h2><p>{result.assessment_reason || result.error}</p><p className="intel-note">{result.providers_checked ?? 0} providers completed / {result.providers_eligible ?? 0} eligible · Request {result.request_id}</p>{result.generated_at && <p className="intel-note">Report generated {result.generated_at}</p>}
        {result.normalized_representations && <Details value={result.normalized_representations} />}
      </section>
      <section className="panel intel-status"><h3>Threat evidence ({result.evidence?.length || 0})</h3>{!result.evidence?.length && <p>No actionable threat evidence returned. This does not establish safety.</p>}
        {result.evidence?.map((item, index) => <article className="intel-evidence" key={index}><strong>{item.provider}</strong><p>{label(item.kind || "Source evidence")}{item.malware && ` · ${item.malware}`}{item.classification && ` · ${item.classification}`}</p>{item.confidence !== undefined && <p>Source confidence: {item.confidence}</p>}{item.first_seen && <p>First seen: {item.first_seen}</p>}{item.last_seen && <p>Last seen: {item.last_seen}</p>}{item.reference && safeLink(item.reference) && <a href={item.reference} target="_blank" rel="noopener noreferrer">Original source reference ↗</a>}</article>)}
      </section>
      <section><h3>Source results</h3><div className="intel-source-grid">{result.provider_results?.map((item, index) => <article className="panel intel-source" key={index}><div className="intel-source-heading"><h3>{item.provider}</h3><span className={`ip-status ${item.status === "success" ? "ip-neutral" : "ip-warning"}`}>{states[item.status] || label(item.status)}</span></div><p className="intel-query">{item.query_type}: {item.query_indicator}</p><p className="intel-note">{item.status === "success" ? "A source record is available. Review its evidence and observation dates." : ["not_found", "no_result"].includes(item.status) ? "No matching record returned; this is not a safety verdict." : "This lookup did not supply an assessment."}</p><details><summary>View source details</summary><Details value={Object.fromEntries(Object.entries(item).filter(([k]) => !["provider", "query_indicator", "query_type"].includes(k)))} /><details><summary>Normalized response JSON</summary><pre>{JSON.stringify(item, null, 2)}</pre></details></details></article>)}</div></section>
      {!!result.providers_skipped?.length && <details className="panel intel-status"><summary>Providers outside this indicator’s capabilities</summary><Details value={result.providers_skipped} /></details>}
      <section className="panel intel-status"><h3>Interpretation and next steps</h3>{result.limitations?.map((item, index) => <p key={index}>{item}</p>)}{result.recommended_steps?.map((item, index) => <p key={index}>{item}</p>)}</section>
    </div>}
  </section>;
}
