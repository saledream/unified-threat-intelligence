"use client";

import { useCallback, useEffect, useState } from "react";
import { Users, UserPlus, RefreshCw, ShieldCheck, UserCheck, UserX, AlertTriangle } from "lucide-react";

type Props = {
  apiFetch: (path: string, init?: RequestInit) => Promise<Response>;
  currentUserId: number;
};
type Account = {
  id: number;
  username: string;
  role: "admin" | "analyst" | "viewer";
  is_active: boolean;
  created_at?: string;
};

const roles = ["admin", "analyst", "viewer"] as const;

export default function UserManagement({ apiFetch, currentUserId }: Props) {
  const [users, setUsers] = useState<Account[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Account["role"]>("viewer");
  const [creating, setCreating] = useState(false);

  const loadUsers = useCallback(async () => {
    try {
      const response = await apiFetch("/api/auth/users");
      const data = await response.json().catch(() => []);
      if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
      setUsers(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load user accounts.");
    } finally {
      setLoading(false);
    }
  }, [apiFetch]);

  useEffect(() => {
    let active = true;
    apiFetch("/api/auth/users").then(async response => {
      if (!response.ok) throw new Error("Could not load user accounts.");
      return response.json();
    }).then(data => { if (active) setUsers(Array.isArray(data) ? data : []); })
      .catch(e => { if (active) setError(e instanceof Error ? e.message : "Could not load user accounts."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [apiFetch]);

  async function createAccount(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true); setError(""); setMessage("");
    try {
      const response = await apiFetch("/api/auth/users", {
        method: "POST",
        body: JSON.stringify({ username: username.trim(), password, role }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || `Account creation failed (${response.status})`);
      setUsername(""); setPassword(""); setRole("viewer");
      setMessage(`Account "${data.username}" created successfully.`);
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create account.");
    } finally {
      setCreating(false);
    }
  }

  async function updateRole(account: Account, nextRole: Account["role"]) {
    if (account.role === nextRole) return;
    setBusyId(account.id); setError(""); setMessage("");
    try {
      const response = await apiFetch(`/api/auth/users/${account.id}/role`, {
        method: "PATCH",
        body: JSON.stringify({ role: nextRole }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || `Role update failed (${response.status})`);
      setMessage(`Role updated for ${account.username}. Their existing sessions have been revoked.`);
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update role.");
    } finally {
      setBusyId(null);
    }
  }

  async function toggleActive(account: Account) {
    const action = account.is_active ? "deactivate" : "activate";
    if (!window.confirm(`Are you sure you want to ${action} ${account.username}?`)) return;
    setBusyId(account.id); setError(""); setMessage("");
    try {
      const response = await apiFetch(`/api/auth/users/${account.id}/active?active=${!account.is_active}`, {
        method: "PATCH",
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || `Account update failed (${response.status})`);
      setMessage(`Account "${account.username}" ${action}d. Existing sessions have been revoked.`);
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update account.");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="ip-workspace">
      <section className="search-panel ip-search-panel">
        <div className="search-panel-copy">
          <div className="search-label"><Users size={15}/> ADMINISTRATION</div>
          <h2>User management</h2>
          <p>Create and manage employee access to the Unified Threat Intelligence workspace.</p>
        </div>
        <div className="ip-form-options">
          <span><ShieldCheck size={14}/> Administrator access only</span>
          <button className="ip-secondary-button" onClick={() => void loadUsers()} disabled={loading}>
            <RefreshCw size={13}/> Refresh accounts
          </button>
        </div>
      </section>

      {error && <div className="notice ip-error"><AlertTriangle size={18}/><div><strong>Action failed</strong><span>{error}</span></div></div>}
      {message && <div className="notice"><ShieldCheck size={18}/><div><strong>Success</strong><span>{message}</span></div></div>}

      <section className="panel">
        <div className="panel-heading"><div><h2><UserPlus size={16}/> Create employee account</h2><p>New accounts are active immediately.</p></div></div>
        <form className="user-create-form" onSubmit={createAccount}>
          <div className="user-form-field">
            <label htmlFor="new-username">USERNAME</label>
            <input id="new-username" value={username} onChange={e => setUsername(e.target.value)} minLength={3} maxLength={80} pattern="[a-zA-Z0-9._-]+" required placeholder="e.g. employee.name"/>
          </div>
          <div className="user-form-field">
            <label htmlFor="new-password">TEMPORARY PASSWORD</label>
            <input id="new-password" type="password" value={password} onChange={e => setPassword(e.target.value)} minLength={12} maxLength={256} required autoComplete="new-password" placeholder="At least 12 characters"/>
          </div>
          <div className="user-form-field">
            <label htmlFor="new-role">ACCESS ROLE</label>
            <select id="new-role" value={role} onChange={e => setRole(e.target.value as Account["role"])}>
              {roles.map(r => <option key={r} value={r}>{r.toUpperCase()}</option>)}
            </select>
          </div>
          <button className="primary-button user-create-button" type="submit" disabled={creating}>
            <UserPlus size={15}/> {creating ? "Creating…" : "Create account"}
          </button>
        </form>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div><h2>Employee accounts</h2><p>{users.length} registered accounts</p></div>
          <span className="ip-status ip-neutral">{users.filter(u => u.is_active).length} active</span>
        </div>
        {loading ? <div className="ip-loading">Loading employee accounts…</div> : users.length === 0 ? (
          <div className="ip-empty"><p>No employee accounts found.</p></div>
        ) : (
          <div className="user-table-wrap">
            <table className="user-table">
              <thead><tr><th>EMPLOYEE</th><th>ROLE</th><th>STATUS</th><th>CREATED</th><th>ACTIONS</th></tr></thead>
              <tbody>
                {users.map(account => <tr key={account.id}>
                  <td><strong>{account.username}</strong>{account.id === currentUserId && <small>YOU</small>}</td>
                  <td>
                    <select aria-label={`Role for ${account.username}`} value={account.role} disabled={busyId === account.id} onChange={e => void updateRole(account, e.target.value as Account["role"])}>
                      {roles.map(r => <option key={r} value={r}>{r.toUpperCase()}</option>)}
                    </select>
                  </td>
                  <td><span className={`ip-status ${account.is_active ? "ip-success" : "ip-warning"}`}>{account.is_active ? "Active" : "Inactive"}</span></td>
                  <td>{account.created_at ? new Date(account.created_at).toLocaleDateString() : "—"}</td>
                  <td>
                    <button className="ip-secondary-button" disabled={busyId === account.id || account.id === currentUserId} onClick={() => void toggleActive(account)}>
                      {account.is_active ? <><UserX size={13}/> Deactivate</> : <><UserCheck size={13}/> Activate</>}
                    </button>
                  </td>
                </tr>)}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <div className="ip-readonly-note"><ShieldCheck size={15}/> Role changes and account status changes revoke existing access tokens. You cannot deactivate your own administrator account.</div>
    </div>
  );
}
