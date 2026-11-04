"use client";

import { useCallback, useEffect, useState } from "react";
import { Activity, RefreshCw, Search, ChevronLeft, ChevronRight, ShieldCheck, AlertTriangle, Filter } from "lucide-react";

type Props = { apiFetch: (path: string, init?: RequestInit) => Promise<Response> };
type Event = {
  id: number;
  user_id: number | null;
  username: string | null;
  action: string;
  indicator_type: string | null;
  indicator_digest: string | null;
  outcome: string | null;
  source_ip: string | null;
  created_at: string;
};
type Result = { total: number; limit: number; offset: number; events: Event[] };

const PAGE_SIZE = 50;

export default function AuditLogs({ apiFetch }: Props) {
  const [data, setData] = useState<Result>({ total: 0, limit: PAGE_SIZE, offset: 0, events: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState("");
  const [userId, setUserId] = useState("");
  const [offset, setOffset] = useState(0);

  const loadEvents = useCallback(async (nextOffset = offset) => {
    setLoading(true); setError("");
    try {
      const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(nextOffset) });
      if (action.trim()) params.set("action", action.trim());
      if (outcome) params.set("outcome", outcome);
      if (userId.trim()) {
        if (!/^[1-9]\d*$/.test(userId.trim())) throw new Error("Employee ID must be a positive whole number.");
        params.set("user_id", userId.trim());
      }
      const response = await apiFetch(`/api/audit/events?${params.toString()}`);
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.detail || `Could not load audit events (${response.status}).`);
      setData(result);
      setOffset(nextOffset);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load audit events.");
    } finally {
      setLoading(false);
    }
  }, [apiFetch, action, outcome, userId, offset]);

  useEffect(() => {
    const controller = new AbortController();
    async function initialLoad() {
      try {
        const response = await apiFetch(`/api/audit/events?limit=${PAGE_SIZE}&offset=0`, { signal: controller.signal });
        if (!response.ok) throw new Error("Could not load audit events.");
        const result = await response.json();
        if (!controller.signal.aborted) setData(result);
      } catch (err) {
        if (!controller.signal.aborted) setError(err instanceof Error ? err.message : "Could not load audit events.");
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void initialLoad();
    return () => controller.abort();
  }, [apiFetch]);

  function applyFilters(e: React.FormEvent) {
    e.preventDefault();
    void loadEvents(0);
  }

  const first = data.total === 0 ? 0 : data.offset + 1;
  const last = Math.min(data.offset + data.events.length, data.total);

  return (
    <div className="ip-workspace">
      <section className="search-panel ip-search-panel">
        <div className="search-panel-copy">
          <div className="search-label"><Activity size={15}/> SECURITY GOVERNANCE</div>
          <h2>Audit logs</h2>
          <p>Review employee activity, authentication events, account changes, and intelligence lookup records.</p>
        </div>
        <div className="ip-form-options">
          <span><ShieldCheck size={14}/> Administrator access only</span>
          <button className="ip-secondary-button" onClick={() => void loadEvents(0)} disabled={loading}>
            <RefreshCw size={13}/> Refresh
          </button>
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading"><div><h2><Filter size={16}/> Filter events</h2><p>Use exact action names or filter by outcome and employee ID.</p></div></div>
        <form className="audit-filter-form" onSubmit={applyFilters}>
          <div className="user-form-field">
            <label htmlFor="audit-action">ACTION</label>
            <input id="audit-action" value={action} onChange={e => setAction(e.target.value)} maxLength={100} placeholder="e.g. auth.login.failure"/>
          </div>
          <div className="user-form-field">
            <label htmlFor="audit-outcome">OUTCOME</label>
            <select id="audit-outcome" value={outcome} onChange={e => setOutcome(e.target.value)}>
              <option value="">All outcomes</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="blocked">Blocked</option>
            </select>
          </div>
          <div className="user-form-field">
            <label htmlFor="audit-user">EMPLOYEE ID</label>
            <input id="audit-user" inputMode="numeric" value={userId} onChange={e => setUserId(e.target.value)} placeholder="All employees"/>
          </div>
          <button className="primary-button user-create-button" type="submit" disabled={loading}><Search size={15}/> Apply filters</button>
        </form>
      </section>

      {error && <div className="notice ip-error"><AlertTriangle size={18}/><div><strong>Unable to load audit logs</strong><span>{error}</span></div></div>}

      <section className="panel">
        <div className="panel-heading">
          <div><h2>Activity records</h2><p>{data.total.toLocaleString()} matching events</p></div>
          <span className="ip-status ip-neutral">{loading ? "Loading…" : `${first}–${last} of ${data.total}`}</span>
        </div>
        {loading ? <div className="ip-loading">Retrieving audit records…</div> : data.events.length === 0 ? (
          <div className="ip-empty"><p>No audit events match these filters.</p></div>
        ) : (
          <div className="user-table-wrap">
            <table className="user-table audit-table">
              <thead><tr><th>TIME</th><th>EMPLOYEE</th><th>ACTION</th><th>OUTCOME</th><th>INDICATOR</th><th>SOURCE IP</th></tr></thead>
              <tbody>{data.events.map(event => <tr key={event.id}>
                <td>{new Date(event.created_at).toLocaleString()}</td>
                <td>{event.username || (event.user_id ? `User #${event.user_id}` : "System / unauthenticated")}</td>
                <td><code>{event.action}</code></td>
                <td><span className={`ip-status ${event.outcome === "success" ? "ip-success" : event.outcome === "failure" || event.outcome === "blocked" ? "ip-warning" : "ip-neutral"}`}>{event.outcome || "—"}</span></td>
                <td>{event.indicator_type ? <span title={event.indicator_digest || ""}>{event.indicator_type}{event.indicator_digest ? ` · ${event.indicator_digest.slice(0, 12)}…` : ""}</span> : "—"}</td>
                <td>{event.source_ip || "—"}</td>
              </tr>)}</tbody>
            </table>
          </div>
        )}
        <div className="audit-pagination">
          <span>Showing {first}–{last} of {data.total}</span>
          <div>
            <button className="ip-secondary-button" disabled={loading || offset === 0} onClick={() => void loadEvents(Math.max(0, offset - PAGE_SIZE))}><ChevronLeft size={14}/> Previous</button>
            <button className="ip-secondary-button" disabled={loading || offset + PAGE_SIZE >= data.total} onClick={() => void loadEvents(offset + PAGE_SIZE)}>Next <ChevronRight size={14}/></button>
          </div>
        </div>
      </section>
      <div className="ip-readonly-note"><ShieldCheck size={15}/> Audit records are read-only. Raw indicators and passwords are never displayed in this view.</div>
    </div>
  );
}
