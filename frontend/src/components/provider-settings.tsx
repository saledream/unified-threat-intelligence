"use client";
import { useCallback, useEffect, useState } from "react";
type Provider = { name: string; types: string[]; status: string; enabled: boolean; licensing: string; timeout_seconds: number; retries: number; cache_ttl_seconds: number; health?: { status: string; retrieved_at: string } };
type Props = { apiFetch: (path: string, init?: RequestInit) => Promise<Response> };
export default function ProviderSettings({ apiFetch }: Props) {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [scope, setScope] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState("");
  const load = useCallback(async () => {
    try {
      const response = await apiFetch("/api/providers/registry");
      const data = await response.json();
      if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Unable to load registry");
      setProviders(data.providers); setScope(data.health_scope);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to load registry"); }
    finally { setLoading(false); }
  }, [apiFetch]);
  useEffect(() => {
    let active = true;
    apiFetch("/api/providers/registry").then(async response => {
      if (!response.ok) throw new Error("Unable to load registry");
      return response.json();
    }).then(data => { if (active) { setProviders(data.providers); setScope(data.health_scope); } })
      .catch(e => { if (active) setError(e instanceof Error ? e.message : "Unable to load registry"); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [apiFetch]);
  async function toggle(provider: Provider) {
    setSaving(provider.name); setError("");
    try {
      const response = await apiFetch(`/api/providers/${provider.name}`, { method: "PATCH", body: JSON.stringify({ enabled: !provider.enabled }) });
      if (!response.ok) throw new Error("Unable to update provider policy");
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Update failed"); }
    finally { setSaving(""); }
  }
  return <section className="intel-workspace"><section className="panel intel-status"><h2>Provider settings</h2><p>Enable or disable unified lookups across the dashboard and MCP. Environment policy, credential requirements and commercial authorization gates still apply.</p><p className="intel-note">{scope}</p><button className="ip-secondary-button" disabled={loading} onClick={() => void load()}>Refresh</button></section>
    {error && <p role="alert" className="notice">{error}</p>}{loading && <p role="status">Loading provider registry…</p>}
    <div className="intel-source-grid">{providers.map(provider => <article className="panel intel-source" key={provider.name}><div className="intel-source-heading"><h3>{provider.name}</h3><span className="ip-status ip-neutral">{provider.status.replaceAll("_", " ")}</span></div><p>{provider.types.join(" · ")}</p><p className="intel-note">{provider.licensing}</p><p className="intel-note">Timeout {provider.timeout_seconds}s · retries {provider.retries} · cache {provider.cache_ttl_seconds}s</p><p className="intel-note">{provider.health ? `Last lookup: ${provider.health.status} at ${provider.health.retrieved_at}` : "No lookup observed in this worker"}</p><button className="ip-secondary-button" onClick={() => void toggle(provider)} disabled={!!saving} aria-pressed={provider.enabled}>{saving === provider.name ? "Saving…" : provider.enabled ? "Disable provider" : "Enable provider"}</button></article>)}</div>
  </section>;
}
