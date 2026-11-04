"use client";

import { FormEvent, useState } from "react";
import { Activity, ArrowRight, Eye, EyeOff, LockKeyhole, Shield, ShieldCheck } from "lucide-react";
import { useAuth } from "@/lib/auth";

export default function AuthGate({ children }: { children: React.ReactNode }) {
  const { user, loading, login, error } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState("");

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError("");
    setSubmitting(true);
    try {
      await login(username.trim(), password);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : error || "Sign-in failed.");
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return <div className="auth-loading"><div className="auth-spinner" /><span>Verifying your session...</span></div>;
  }

  if (user) return <>{children}</>;

  return (
    <main className="login-screen">
      <section className="login-brand-side">
        <div className="login-brand">
          <div className="login-brand-icon"><Shield size={25} /></div>
          <div><strong>THREAT<span>INTEL</span></strong><small>THREAT INTELLIGENCE</small></div>
        </div>
        <div className="login-message">
          <div className="login-overline"><span /> INTELLIGENCE. CLARITY. CONTROL.</div>
          <h1>Understand the<br /><span>threat landscape.</span></h1>
          <p>A unified intelligence workspace for investigating indicators, enriching threat data, and exploring adversary techniques.</p>
          <div className="login-feature"><ShieldCheck size={17} /><span>Centralized threat intelligence</span></div>
          <div className="login-feature"><Activity size={17} /><span>Multiple intelligence sources</span></div>
          <div className="login-feature"><LockKeyhole size={17} /><span>Role-based access control</span></div>
        </div>
        <div className="login-side-footer">UNIFIED INTELLIGENCE WORKSPACE</div>
      </section>

      <section className="login-form-side">
        <div className="login-form-wrap">
          <div className="login-mobile-brand">
            <div className="login-brand-icon"><Shield size={22} /></div>
            <strong>THREAT<span>INTEL</span></strong>
          </div>
          <div className="login-form-heading">
            <div className="login-form-icon"><LockKeyhole size={20} /></div>
            <div className="login-overline">SECURE ACCESS</div>
            <h2>Welcome back</h2>
            <p>Sign in with your workspace account.</p>
          </div>

          <form onSubmit={handleSubmit} className="login-form">
            <label htmlFor="login-username">Username</label>
            <input
              id="login-username"
              type="text"
              autoComplete="username"
              placeholder="Enter your username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
              minLength={3}
              maxLength={80}
            />
            <div className="password-label-row">
              <label htmlFor="login-password">Password</label>
            </div>
            <div className="password-input-wrap">
              <input
                id="login-password"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                placeholder="Enter your password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
                minLength={12}
                maxLength={256}
              />
              <button type="button" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? "Hide password" : "Show password"}>
                {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
            </div>

            {formError && <div className="login-error" role="alert">{formError}</div>}

            <button className="login-submit" type="submit" disabled={submitting || !username.trim() || password.length < 12}>
              {submitting ? "Signing in..." : "Sign in to workspace"}
              {!submitting && <ArrowRight size={17} />}
            </button>
          </form>

          <div className="login-security"><LockKeyhole size={13} /><span>Your session is protected by workspace authentication controls.</span></div>
          <div className="login-bottom">UNIFIED THREAT INTELLIGENCE <span>·</span> INTERNAL USE ONLY</div>
        </div>
      </section>
    </main>
  );
}
