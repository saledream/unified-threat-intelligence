"use client";
import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
type Source = { source: string; status: string; stored_count: number; updated: number };
export default function ResearchWorkbench() {
  const { apiFetch, user } = useAuth();
  const [sources, setSources] = useState<Source[]>([]);
  const [feeds, setFeeds] = useState<string[]>([]);
  const [corpora, setCorpora] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [source, setSource] = useState("");
  const [indicators, setIndicators] = useState("");
  const [cve, setCve] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    apiFetch("/api/intelligence/sources").then(r => { if (!r.ok) throw new Error("Could not load sources"); return r.json(); })
      .then(data => { if (active) { setSources(data.sources); setFeeds(data.feeds); setCorpora(data.corpora); } })
      .catch(e => { if (active) setError(String(e)); });
    return () => { active = false; };
  }, [apiFetch]);
  async function run(path: string, init?: RequestInit) {
    setBusy(true); setError("");
    try {
      const response = await apiFetch(path, init); const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Request failed");
      setResult(data);
      const status = await apiFetch("/api/intelligence/sources"); if (status.ok) setSources((await status.json()).sources);
    } catch(e) { setError(e instanceof Error ? e.message : "Request failed"); } finally { setBusy(false); }
  }
  return <section className="panel research-forms" style={{ padding: 24 }}>
    <div className="eyebrow">RESEARCH & FEEDS</div><h2>Reference and intelligence workbench</h2>
    <p>Search local source records, enrich up to 20 IOCs, or compare NVD, EPSS and CISA KEV evidence for a CVE. Dataset updates download public reference data; retrieved commands and rules are never executed.</p>
    <form style={{ display: "grid", gap: 12, marginTop: 24 }} onSubmit={e => { e.preventDefault(); run(`/api/intelligence/search?query=${encodeURIComponent(query)}&limit=10${source ? `&source=${encodeURIComponent(source)}` : ""}`); }}>
      <label>Search reference or feed<input value={query} onChange={e => setQuery(e.target.value)} style={{ width: "100%" }} /></label>
      <label>Source <select value={source} onChange={e => setSource(e.target.value)}><option value="">All local sources</option>{[...feeds.map(f => `feed:${f}`), ...corpora.map(c => `corpus:${c}`)].map(s => <option key={s} value={s}>{s}</option>)}</select></label>
      <button className="primary-button" disabled={busy}>Search local intelligence</button>
    </form>
    <form style={{ display: "grid", gap: 12, marginTop: 24 }} onSubmit={e => { e.preventDefault(); run("/api/intelligence/bulk", { method: "POST", body: JSON.stringify({ indicators: indicators.split(/\r?\n/).map(v => v.trim()).filter(Boolean) }) }); }}>
      <label>Bulk IOC lookup (one per line, maximum 20)<textarea required value={indicators} onChange={e => setIndicators(e.target.value)} rows={4} style={{ display: "block", width: "100%" }} /></label>
      <button className="primary-button" disabled={busy}>Look up IOC list</button>
    </form>
    <form style={{ display: "flex", gap: 12, marginTop: 24 }} onSubmit={e => { e.preventDefault(); run(`/api/intelligence/cve/${encodeURIComponent(cve.trim())}`); }}>
      <label>CVE identifier <input required placeholder="CVE-2024-3400" value={cve} onChange={e => setCve(e.target.value)} /></label><button disabled={busy}>Enrich CVE</button>
    </form>
    <h3 style={{ marginTop: 32 }}>Local source status</h3>
    <p>Event dates are retained in source records. The times below indicate local retrieval. A missing match is never a safety verdict.</p>
    {sources.map(s => <p key={s.source}><strong>{s.source}</strong> · {s.status} · {s.stored_count} records · {new Date(s.updated * 1000).toLocaleString()}</p>)}
    {user?.role === "admin" && <details><summary>Update feeds and reference datasets</summary><p>Provider keys and terms gates still apply. Each source has a minimum update interval.</p>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>{feeds.map(f => <button key={f} disabled={busy} onClick={() => run(`/api/intelligence/feeds/${f}/sync`, { method: "POST" })}>Update {f}</button>)}</div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 16 }}>{corpora.map(c => <button key={c} disabled={busy} onClick={() => run(`/api/intelligence/corpora/${c}/sync`, { method: "POST" })}>Import {c}</button>)}</div>
    </details>}
    {busy && <p role="status">Working…</p>}{error && <p role="alert">{error}</p>}
    {result != null && <details open style={{ marginTop: 24 }}><summary>Source results</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 700, overflow: "auto" }}>{JSON.stringify(result, null, 2)}</pre></details>}
  </section>;
}
