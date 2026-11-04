"use client";
import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";

type Submission = { id: string; status: string; digest: string; requester: string; expires: number; disclosure: string; submission: Record<string, string | number>; result?: unknown };
export default function SubmissionReview() {
  const { apiFetch, user } = useAuth();
  const [rows, setRows] = useState<Submission[]>([]);
  const [url, setUrl] = useState("");
  const [provider, setProvider] = useState("virustotal");
  const [file, setFile] = useState<File | null>(null);
  const [selected, setSelected] = useState<Submission | null>(null);
  const [password, setPassword] = useState("");
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [analysis, setAnalysis] = useState<unknown>(null);
  const load = useCallback(async () => {
    const r = await apiFetch("/api/submissions");
    if (!r.ok) throw new Error("Could not load submission requests");
    setRows((await r.json()).requests);
  }, [apiFetch]);
  useEffect(() => {
    let active = true;
    apiFetch("/api/submissions").then(async r => {
      if (!r.ok) throw new Error("Could not load submission requests");
      return r.json();
    }).then(data => { if (active) setRows(data.requests); }).catch(e => { if (active) setMessage(String(e)); });
    return () => { active = false; };
  }, [apiFetch]);
  async function run(action: () => Promise<Response>) {
    setBusy(true); setMessage("");
    try {
      const response = await action(); const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Request failed");
      setMessage(`Status: ${data.status}. ${data.reason ?? ""}`);
      if (data.analysis) setAnalysis(data.analysis);
      setSelected(null); setAck(false); await load();
    } catch(e) { setMessage(e instanceof Error ? e.message : "Request failed"); }
    finally { setBusy(false); setPassword(""); }
  }
  return <section className="panel research-forms" style={{ padding: 24 }}>
    <div className="eyebrow">HUMAN APPROVAL</div><h2>External analysis submissions</h2>
    <p>Request an analysis here or through MCP. An administrator must review the exact submission and confirm their password before anything is sent. Files stay encrypted locally while pending and are removed after execution, rejection, or expiry.</p>
    <form onSubmit={e => { e.preventDefault(); run(() => apiFetch("/api/submissions/url", { method: "POST", body: JSON.stringify({ url, provider }) })); }} style={{ display: "grid", gap: 12, margin: "24px 0" }}>
      <label>URL to submit<input required type="url" value={url} onChange={e => setUrl(e.target.value)} style={{ width: "100%" }} /></label>
      <label>Analysis provider <select value={provider} onChange={e => setProvider(e.target.value)}><option value="virustotal">VirusTotal</option><option value="urlscan">urlscan (unlisted)</option><option value="cloudflare">Cloudflare (unlisted)</option></select></label>
      <button className="primary-button" disabled={busy}>Request URL analysis approval</button>
    </form>
    <form onSubmit={e => { e.preventDefault(); if (!file) return; const body = file; run(() => apiFetch("/api/submissions/file", { method: "POST", headers: { "Content-Type": "application/octet-stream", "X-Filename": file.name.replace(/[^A-Za-z0-9._ -]/g, "_") }, body })); }} style={{ display: "grid", gap: 12 }}>
      <label>File for VirusTotal (maximum 16 MiB)<input type="file" required onChange={e => setFile(e.target.files?.[0] ?? null)} /></label>
      <button className="primary-button" disabled={busy || !file || file.size > 16 * 1024 * 1024}>Request file analysis approval</button>
    </form>
    {message && <p role="status">{message}</p>}
    {analysis != null && <details open><summary>Analysis result</summary><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 600, overflow: "auto" }}>{JSON.stringify(analysis, null, 2)}</pre></details>}
    <button onClick={() => load().catch(e => setMessage(String(e)))} disabled={busy} style={{ marginTop: 24 }}>Refresh requests</button>
    {rows.map(row => <article key={row.id} className="panel" style={{ padding: 16, marginTop: 16 }}>
      <strong>{row.submission.provider ?? "Submission"} · {row.status}</strong>
      <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{JSON.stringify(row.submission, null, 2)}</pre>
      <p>Requester: {row.requester} · Expires: {new Date(row.expires * 1000).toLocaleString()}</p>
      {row.status === "pending" && user?.role === "admin" && <button onClick={() => { setSelected(row); setAck(false); setPassword(""); }}>Review submission</button>}
      {row.status === "submitted" && <button disabled={busy} onClick={() => run(() => apiFetch(`/api/submissions/${row.id}/poll`, { method: "POST" }))}>Check analysis result</button>}
      {row.result != null && <pre style={{ whiteSpace: "pre-wrap" }}>{JSON.stringify(row.result, null, 2)}</pre>}
    </article>)}
    {selected && <form className="panel" style={{ padding: 20, marginTop: 20, border: "1px solid #c78642" }} onSubmit={e => { e.preventDefault(); const body = JSON.stringify({ digest: selected.digest, password, acknowledge_disclosure: ack, approve: true }); run(() => apiFetch(`/api/submissions/${selected.id}/decision`, { method: "POST", body })); }}>
      <h3>Review exact operation</h3><pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{JSON.stringify(selected.submission, null, 2)}</pre>
      <p>{selected.disclosure}</p>
      <label style={{ display: "block", margin: "16px 0" }}><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} /> I approve disclosure of this exact URL or file to this provider.</label>
      <label>Confirm administrator password<input type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} /></label>
      <div style={{ display: "flex", gap: 12, marginTop: 16 }}><button className="primary-button" disabled={busy || !ack || !password}>Approve and send once</button>
      <button type="button" disabled={busy || !password} onClick={() => { const body = JSON.stringify({ digest: selected.digest, password, acknowledge_disclosure: false, approve: false }); run(() => apiFetch(`/api/submissions/${selected.id}/decision`, { method: "POST", body })); }}>Reject request</button>
      <button type="button" onClick={() => { setSelected(null); setPassword(""); }}>Cancel review</button></div>
    </form>}
  </section>;
}
