"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

type Role = "admin" | "analyst" | "viewer";
type User = { id: number; username: string; role: Role; is_active?: boolean };

type AuthContextValue = {
  user: User | null;
  token: string | null;
  loading: boolean;
  error: string;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  apiFetch: (path: string, init?: RequestInit) => Promise<Response>;
};

const AuthContext = createContext<AuthContextValue | null>(null);
const TOKEN_KEY = "mmcy_ti_access_token";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const apiFetch = useCallback(async (path: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    const activeToken = token ?? sessionStorage.getItem(TOKEN_KEY);
    if (activeToken) headers.set("Authorization", `Bearer ${activeToken}`);
    if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    return fetch(path, { ...init, headers, cache: "no-store" });
  }, [token]);

  const clearSession = useCallback(() => {
    sessionStorage.removeItem(TOKEN_KEY);
    setToken(null);
    setUser(null);
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function restore() {
      const saved = sessionStorage.getItem(TOKEN_KEY);
      if (!saved) {
        setLoading(false);
        return;
      }

      setToken(saved);
      try {
        const response = await fetch("/api/auth/me", {
          headers: { Authorization: `Bearer ${saved}` },
          cache: "no-store",
        });
        if (!response.ok) throw new Error("Session expired");
        const currentUser = await response.json();
        if (!cancelled) setUser(currentUser);
      } catch {
        if (!cancelled) clearSession();
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    restore();
    return () => { cancelled = true; };
  }, [clearSession]);

  const login = useCallback(async (username: string, password: string) => {
    setError("");
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
      cache: "no-store",
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = typeof payload.detail === "string"
        ? payload.detail
        : "Unable to sign in. Check your credentials and try again.";
      setError(message);
      throw new Error(message);
    }

    sessionStorage.setItem(TOKEN_KEY, payload.access_token);
    setToken(payload.access_token);
    setUser(payload.user);
  }, []);

  const logout = useCallback(async () => {
    try {
      if (token) {
        await fetch("/api/auth/logout", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          cache: "no-store",
        });
      }
    } finally {
      clearSession();
    }
  }, [token, clearSession]);

  const value = useMemo(() => ({
    user, token, loading, error, login, logout, apiFetch,
  }), [user, token, loading, error, login, logout, apiFetch]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}
