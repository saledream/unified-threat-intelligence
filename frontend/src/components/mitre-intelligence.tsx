"use client";

import { useState } from "react";
import { Crosshair, Search, ExternalLink, ChevronRight, ShieldCheck, Target, Layers3 } from "lucide-react";

type Props = { apiFetch: (path: string, init?: RequestInit) => Promise<Response> };
type Technique = {
  technique_id?: string; name?: string; description?: string;
  platforms?: string[]; tactics?: string[]; url?: string;
  is_subtechnique?: boolean; references?: unknown[];
  detection_strategies?: unknown[]; mitigations?: unknown[];
  used_by?: unknown[]; subtechniques?: unknown[]; parent_techniques?: unknown[];
  [key: string]: unknown;
};

const platforms = ["", "Windows", "Linux", "macOS", "Network", "Cloud", "Containers", "Office 365", "SaaS"];

export default function MitreIntelligence({ apiFetch }: Props) {
  const [query, setQuery] = useState("");
  const [platform, setPlatform] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [results, setResults] = useState<Technique[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [selected, setSelected] = useState<Technique | null>(null);
  const [detailBusy, setDetailBusy] = useState(false);

  async function search(e: React.FormEvent) {
    e.preventDefault();
    if (!query.trim()) return;
    setBusy(true); setError(""); setSelected(null); setResults([]); setTotal(null);
    try {
      const params = new URLSearchParams({ query: query.trim(), limit: "20" });
      if (platform) params.set("platform", platform);
      const response = await apiFetch(`/api/mitre/search?${params.toString()}`);
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || `Search failed (${response.status})`);
      setResults(Array.isArray(data.results) ? data.results : []);
      setTotal(typeof data.total_matches === "number" ? data.total_matches : (data.result_count ?? 0));
    } catch (err) {
      setError(err instanceof Error ? err.message : "MITRE search failed.");
    } finally { setBusy(false); }
  }

  async function openTechnique(id: string) {
    setDetailBusy(true); setError("");
    try {
      const response = await apiFetch(`/api/mitre/techniques/${encodeURIComponent(id)}`);
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || `Technique request failed (${response.status})`);
      setSelected(data as Technique);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load technique details.");
    } finally { setDetailBusy(false); }
  }

  function renderValue(value: unknown): string {
    if (value === null || value === undefined || value === "") return "—";
    if (Array.isArray(value)) return value.map(v => typeof v === "object" && v !== null ? Object.entries(v).map(([k,x]) => `${k}: ${String(x)}`).join(" · ") : String(v)).join("\n");
    if (typeof value === "object") return JSON.stringify(value, null, 2);
    return String(value);
  }

  return (
    <div className="ip-workspace">
      <section className="search-panel ip-search-panel">
        <div className="search-panel-copy">
          <div className="search-label"><Crosshair size={15}/> MITRE ATT&CK KNOWLEDGE BASE</div>
          <h2>Search adversary techniques</h2>
          <p>Explore tactics, techniques, sub-techniques, platforms and detection context from the local ATT&CK dataset.</p>
        </div>
        <form className="ip-form" onSubmit={search}>
          <label htmlFor="mitre-query">SEARCH TECHNIQUES</label>
          <div className="investigation-search">
            <Search size={18}/>
            <input id="mitre-query" value={query} onChange={e => setQuery(e.target.value)} placeholder="e.g. credential dumping, T1059, persistence…" />
            <button type="submit" disabled={!query.trim() || busy}>{busy ? "Searching…" : "Search"} <Search size={15}/></button>
          </div>
          <div className="ip-form-options">
            <label htmlFor="mitre-platform">PLATFORM</label>
            <select id="mitre-platform" value={platform} onChange={e => setPlatform(e.target.value)}>
              {platforms.map(p => <option key={p} value={p}>{p || "All platforms"}</option>)}
            </select>
            <span>Source: locally maintained MITRE ATT&CK dataset</span>
          </div>
        </form>
      </section>

      {error && <div className="notice ip-error">{error}</div>}
      {detailBusy && <div className="panel ip-loading">Loading technique details…</div>}

      {selected && <section className="panel ip-result-card mitre-detail">
        <div className="panel-heading">
          <div><div className="search-label"><Target size={14}/> TECHNIQUE DETAILS</div><h2>{selected.name || "Technique"}</h2><p>{selected.technique_id || ""}</p></div>
          <button className="ip-secondary-button" onClick={() => setSelected(null)}>Back to results</button>
        </div>
        {typeof selected.description === "string" && <p className="mitre-description">{selected.description}</p>}
        <div className="mitre-detail-grid">
          {(["platforms", "tactics", "detection_strategies", "mitigations", "used_by", "subtechniques", "parent_techniques", "references"] as const).map(key => {
            const value = selected[key];
            if (value === undefined || value === null || (Array.isArray(value) && value.length === 0)) return null;
            return <div className="ip-result-field" key={key}><span>{key.replaceAll("_", " ")}</span><strong>{renderValue(value)}</strong></div>;
          })}
        </div>
        {typeof selected.url === "string" && selected.url.startsWith("https://") && <a className="ip-external-link" href={selected.url} target="_blank" rel="noreferrer">Open MITRE ATT&CK reference <ExternalLink size={13}/></a>}
      </section>}

      {!selected && results.length > 0 && <section className="panel">
        <div className="panel-heading"><div><h2>Search results</h2><p>{total ?? results.length} matching techniques</p></div><span className="ip-status ip-success">{results.length} shown</span></div>
        <div className="mitre-results">
          {results.map((item, index) => <button className="mitre-result" key={item.technique_id || index} onClick={() => item.technique_id && openTechnique(item.technique_id)}>
            <div className="mitre-result-icon"><Target size={17}/></div>
            <div className="mitre-result-copy"><strong>{item.name || "Unnamed technique"}</strong><span>{item.technique_id || "No technique ID"}{item.is_subtechnique ? " · Sub-technique" : ""}</span><small>{(item.tactics || []).join(" · ")}</small></div>
            <ChevronRight size={17}/>
          </button>)}
        </div>
      </section>}

      {!selected && !busy && results.length === 0 && !error && <section className="panel ip-empty"><div className="coming-icon"><Layers3 size={25}/></div><h2>Explore ATT&CK techniques</h2><p>Search by technique name, ATT&CK ID, tactic or keyword. Select a result to inspect its details.</p></section>}
      <div className="ip-readonly-note"><ShieldCheck size={15}/> Reference intelligence only. Technique data does not imply that an attack occurred in your environment.</div>
    </div>
  );
}
