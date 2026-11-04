"use client";

import { useEffect, useState } from "react";
import {
  Activity, ShieldCheck, Search, LayoutDashboard, Globe2, Network,
  Fingerprint, Crosshair, Settings2, Users, FileClock, ChevronDown,
  ChevronRight, Menu, X, ArrowUpRight, ArrowRight, Shield,
  Server, AlertCircle, Zap, LockKeyhole, LogOut,
} from "lucide-react";
import { useAuth } from "@/lib/auth";
import UnifiedIntelligence from "@/components/unified-intelligence";
import IpIntelligence from "@/components/ip-intelligence";
import DomainUrlIntelligence from "@/components/domain-url-intelligence";
import FileHashIntelligence from "@/components/file-hash-intelligence";
import IndicatorValidation from "@/components/indicator-validation";
import MitreIntelligence from "@/components/mitre-intelligence";
import UserManagement from "@/components/user-management";
import AuditLogs from "@/components/audit-logs";
import ProviderSettings from "@/components/provider-settings";
import SubmissionReview from "@/components/submission-review";
import ResearchWorkbench from "@/components/research-workbench";

const navigation = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Unified Investigation", icon: Search },
  { label: "Indicator Validation", icon: ShieldCheck },
  { label: "MITRE ATT&CK", icon: Crosshair },
  { label: "Analysis Approvals", icon: ShieldCheck },
  { label: "Research & Feeds", icon: Search },
];

const administration = [
  { label: "User Management", icon: Users },
  { label: "Audit Logs", icon: FileClock },
  { label: "Provider Settings", icon: Settings2 },
];

const providerDefinitions = [
  { key: "abuseipdb", name: "AbuseIPDB", category: "IP reputation", initials: "A" },
  { key: "greynoise", name: "GreyNoise", category: "Internet scanner intelligence", initials: "G" },
  { key: "otx", name: "AlienVault OTX", category: "Threat intelligence", initials: "O" },
  { key: "malwarebazaar", name: "MalwareBazaar", category: "Malware samples", initials: "M" },
  { key: "threatfox", name: "ThreatFox", category: "IOC database", initials: "T" },
  { key: "urlhaus", name: "URLhaus", category: "Malicious URLs", initials: "U" },
  { key: "mitre_attack", name: "MITRE ATT&CK", category: "Adversary knowledge base", initials: "M" },
  { key: "rdap", name: "RDAP", category: "Registration context", initials: "R" },
  { key: "urlscan", name: "urlscan", category: "Historical scans", initials: "U" },
  { key: "virustotal", name: "VirusTotal", category: "Multi-engine intelligence", initials: "V" },
  { key: "shodan", name: "Shodan API", category: "Authenticated host reports", initials: "S" },
  { key: "shodan_internetdb", name: "Shodan InternetDB", category: "Historical exposure", initials: "S" },
  { key: "ipinfo", name: "IPinfo", category: "Network context", initials: "I" },
  { key: "pulsedive", name: "Pulsedive", category: "Threat context", initials: "P" },
  { key: "spur", name: "Spur", category: "Proxy and VPN context", initials: "S" },
  { key: "censys", name: "Censys", category: "Exposure intelligence", initials: "C" },
  { key: "cloudflare_radar", name: "Cloudflare Radar", category: "IP network context", initials: "C" },
  { key: "cloudflare_urlscanner", name: "Cloudflare URL Scanner", category: "Optional historical scans", initials: "C" },
  { key: "certificate_transparency", name: "crt.sh", category: "Certificate transparency", initials: "C" },
  { key: "dns_doh", name: "DNS over HTTPS", category: "Optional resolver context", initials: "D" },
  { key: "local_feeds", name: "Local feeds", category: "Synchronized intelligence", initials: "F" },
] as const;

type ProviderStatus = Record<string, string>;

function statusLabel(status?: string) {
  switch (status) {
    case "configured": return "Configured";
    case "available": return "Available";
    case "not_configured": return "Not configured";
    case "dataset_missing": return "Dataset missing";
    case "disabled_pending_license_review": return "Disabled";
    case "requires_authorization": return "Requires authorization";
    case "disabled": return "Disabled";
    default: return "Unknown";
  }
}

function statusClass(status?: string) {
  if (status === "configured" || status === "available") return "status-good";
  if (status === "not_configured" || status === "dataset_missing") return "status-warning";
  return "status-muted";
}

export default function Home() {
  const { user, apiFetch, logout } = useAuth();
  const [active, setActive] = useState("Unified Investigation");
  const [mobileOpen, setMobileOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [providers, setProviders] = useState<ProviderStatus | null>(null);
  const [apiState, setApiState] = useState<"loading" | "connected" | "error">("loading");
  const [providerError, setProviderError] = useState("");
  const [loggingOut, setLoggingOut] = useState(false);

  const isAdmin = user?.role === "admin";

  useEffect(() => {
    let cancelled = false;

    async function loadOverview() {
      try {
        const response = await apiFetch("/api/providers/status");
        if (!response.ok) {
          throw new Error(response.status === 401 ? "Your session has expired." : "Unable to load provider configuration.");
        }
        const data = await response.json();
        if (!cancelled) {
          setProviders(data);
          setApiState("connected");
          setProviderError("");
        }
      } catch (error) {
        if (!cancelled) {
          setApiState("error");
          setProviderError(error instanceof Error ? error.message : "API request failed.");
        }
      }
    }

    loadOverview();
    return () => { cancelled = true; };
  }, [apiFetch]);

  const selectPage = (label: string) => {
    setActive(label);
    setMobileOpen(false);
  };

  const handleLogout = async () => {
    setLoggingOut(true);
    try {
      await logout();
    } finally {
      setLoggingOut(false);
    }
  };

  const navItem = (item: { label: string; icon: typeof Activity }) => {
    const Icon = item.icon;
    const selected = active === item.label;
    return (
      <button
        key={item.label}
        onClick={() => selectPage(item.label)}
        className={`nav-item ${selected ? "nav-active" : ""}`}
      >
        <Icon size={17} strokeWidth={1.8} />
        <span>{item.label}</span>
        {selected && <span className="nav-indicator" />}
      </button>
    );
  };

  const configuredCount = providers
    ? providerDefinitions.filter((provider) =>
        ["configured", "available"].includes(providers[provider.key] ?? "")
      ).length
    : null;

  return (
    <div className="app-shell">
      {mobileOpen && <button className="mobile-backdrop" onClick={() => setMobileOpen(false)} aria-label="Close navigation" />}
      <aside className={`sidebar ${mobileOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><Shield size={23} strokeWidth={2.1} /></div>
          <div>
            <div className="brand-name">THREAT<span>INTEL</span></div>
            <div className="brand-caption">THREAT INTELLIGENCE</div>
          </div>
          <button className="mobile-close" onClick={() => setMobileOpen(false)} aria-label="Close menu"><X size={19} /></button>
        </div>

        <div className="workspace-switch">
          <div className="workspace-avatar">M</div>
          <div className="workspace-copy"><strong>Intelligence Workspace</strong><span>Internal environment</span></div>
          <ChevronDown size={15} className="muted-icon" />
        </div>

        <div className="nav-section">
          <div className="nav-heading">WORKSPACE</div>
          {navigation.map(navItem)}
        </div>

        {isAdmin && (
          <div className="nav-section admin-section">
            <div className="nav-heading">ADMINISTRATION</div>
            {administration.map(navItem)}
          </div>
        )}

        <div className="sidebar-bottom">
          <div className="environment-card">
            <div className="environment-top"><span className="live-dot" /> INTERNAL ENVIRONMENT</div>
            <div className="environment-text">Intelligence services workspace</div>
            <div className="environment-foot"><LockKeyhole size={12} /> Access controlled</div>
          </div>
          <div className="profile">
            <div className="profile-avatar">{user?.username?.charAt(0).toUpperCase() ?? "U"}</div>
            <div className="profile-info">
              <strong>{user?.username ?? "User"}</strong>
              <span>{user?.role ?? "Unknown role"}</span>
            </div>
            <button className="icon-button" onClick={handleLogout} disabled={loggingOut} title="Sign out" aria-label="Sign out">
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <button className="mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open menu"><Menu size={21} /></button>
            <div className="breadcrumb">Workspace <ChevronRight size={14} /> <strong>{active}</strong></div>
          </div>
          <div className="topbar-right">
            <div className="system-status">
              <span className={`live-dot ${apiState === "error" ? "status-dot-error" : ""}`} />
              {apiState === "connected" ? "API CONNECTED" : apiState === "error" ? "API UNAVAILABLE" : "CONNECTING TO API"}
            </div>
            <div className="top-avatar">{user?.username?.charAt(0).toUpperCase() ?? "U"}</div>
          </div>
        </header>

        <div className="page-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow"><span className="eyebrow-line" /> THREAT INTELLIGENCE PLATFORM</div>
              <h1>{active === "Overview" ? "Intelligence Overview" : active}</h1>
              <p className="page-description">
                {active === "Overview"
                  ? "Your unified workspace for external threat intelligence and indicator investigation."
                  : `Explore ${active.toLowerCase()} through the threat intelligence services.`}
              </p>
            </div>
            <div className="heading-date"><Activity size={15} /> INTERNAL WORKSPACE</div>
          </div>

          {active === "Unified Investigation" ? <UnifiedIntelligence initialIndicator={query} /> : active === "Overview" ? (
            <>
              {apiState === "error" && (
                <div className="notice">
                  <div className="notice-icon"><AlertCircle size={18} /></div>
                  <div><strong>Unable to retrieve provider configuration</strong><span>{providerError}</span></div>
                </div>
              )}

              <section className="search-panel">
                <div className="search-panel-copy">
                  <div className="search-label"><Zap size={15} /> QUICK INVESTIGATION</div>
                  <h2>What would you like to investigate?</h2>
                  <p>Search an IP address, domain, URL, or file hash.</p>
                </div>
                <div className="investigation-search">
                  <Search size={19} />
                  <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Enter an indicator, e.g. 8.8.8.8" />
                  <button onClick={() => selectPage("Unified Investigation")} disabled={!query.trim()}>Investigate <ArrowRight size={15} /></button>
                </div>
                <div className="search-types"><span>SUPPORTED INDICATORS</span><i>IP ADDRESS</i><i>DOMAIN</i><i>URL</i><i>FILE HASH</i></div>
              </section>

              <div className="section-title-row">
                <div><h2>Intelligence workspace</h2><p>Live platform configuration and capabilities</p></div>
                <span className="demo-label">LIVE API DATA</span>
              </div>

              <section className="stats-grid">
                <div className="stat-card">
                  <div className="stat-top"><span>CONFIGURED / AVAILABLE</span><div className="stat-icon cyan"><Server size={18} /></div></div>
                  <div className="stat-value">{configuredCount === null ? "—" : String(configuredCount).padStart(2, "0")}</div>
                  <div className="stat-foot">Provider configuration states</div>
                </div>
                <div className="stat-card">
                  <div className="stat-top"><span>INDICATOR TYPES</span><div className="stat-icon violet"><Crosshair size={18} /></div></div>
                  <div className="stat-value">04</div>
                  <div className="stat-foot">IP · Domain · URL · Hash</div>
                </div>
                <div className="stat-card">
                  <div className="stat-top"><span>EXTERNAL PROVIDERS</span><div className="stat-icon blue"><Globe2 size={18} /></div></div>
                  <div className="stat-value">09</div>
                  <div className="stat-foot">Registry-backed passive intelligence adapters</div>
                </div>
                <div className="stat-card">
                  <div className="stat-top"><span>KNOWLEDGE BASE</span><div className="stat-icon amber"><ShieldCheck size={18} /></div></div>
                  <div className="stat-value">ATT&CK</div>
                  <div className="stat-foot">Local Enterprise dataset</div>
                </div>
              </section>

              <div className="content-grid">
                <section className="panel providers-panel">
                  <div className="panel-heading">
                    <div><h2>Intelligence providers</h2><p>Backend-reported configuration states</p></div>
                    <button className="text-action" onClick={() => selectPage("Provider Settings")}>Provider details <ArrowUpRight size={14} /></button>
                  </div>
                  <div className="provider-list">
                    {providerDefinitions.map((provider) => {
                      const status = providers?.[provider.key];
                      return (
                        <div className="provider-row" key={provider.key}>
                          <div className="provider-logo" style={{ "--provider-color": "#22c55e" } as React.CSSProperties}>{provider.initials}</div>
                          <div className="provider-copy"><strong>{provider.name}</strong><span>{provider.category}</span></div>
                          <div className={`provider-state ${statusClass(status)}`}>
                            <span className="live-dot" />{providers ? statusLabel(status) : "Loading"}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  <div className="panel-footer"><span>Configuration status only · Provider connectivity is not tested</span><ChevronRight size={15} /></div>
                </section>

                <section className="panel activity-panel">
                  <div className="panel-heading">
                    <div><h2>Investigation workspace</h2><p>Available intelligence operations</p></div>
                    <ShieldCheck size={17} className="muted-icon" />
                  </div>
                  <div className="activity-list">
                    <div className="activity-row">
                      <div className="activity-symbol symbol-0"><Network size={15} /></div>
                      <div className="activity-copy"><strong>IP intelligence</strong><span>Combined and individual provider lookups</span><small>AbuseIPDB · GreyNoise · OTX</small></div>
                    </div>
                    <div className="activity-row">
                      <div className="activity-symbol symbol-1"><Fingerprint size={15} /></div>
                      <div className="activity-copy"><strong>File hash intelligence</strong><span>MalwareBazaar hash lookup</span><small>MD5 · SHA1 · SHA256</small></div>
                    </div>
                    <div className="activity-row">
                      <div className="activity-symbol symbol-2"><Globe2 size={15} /></div>
                      <div className="activity-copy"><strong>Domain and URL intelligence</strong><span>ThreatFox and URLhaus lookups</span><small>Read-only intelligence queries</small></div>
                    </div>
                  </div>
                  <div className="panel-footer"><span>Investigation history will be available in a later phase</span><FileClock size={15} /></div>
                </section>
              </div>

              <section className="bottom-banner">
                <div className="banner-icon"><Crosshair size={21} /></div>
                <div><strong>Explore the MITRE ATT&CK knowledge base</strong><span>Search adversary tactics, techniques, platforms and related intelligence.</span></div>
                <button onClick={() => selectPage("MITRE ATT&CK")}>Explore ATT&CK <ArrowRight size={15} /></button>
              </section>
            </>
          ) : active === "IP Intelligence" ? (
            <IpIntelligence apiFetch={apiFetch} role={user?.role ?? "viewer"} />
          ) : active === "Domain & URL" ? (
            <DomainUrlIntelligence apiFetch={apiFetch} role={user?.role ?? "viewer"} />
          ) : active === "File Hash" ? (
            <FileHashIntelligence apiFetch={apiFetch} role={user?.role ?? "viewer"} />
          ) : active === "Indicator Validation" ? (
            <IndicatorValidation apiFetch={apiFetch} role={user?.role ?? "viewer"} />
          ) : active === "MITRE ATT&CK" ? (
            <MitreIntelligence apiFetch={apiFetch} />
          ) : active === "User Management" && user?.role === "admin" ? (
            <UserManagement apiFetch={apiFetch} currentUserId={user.id} />
          ) : active === "Audit Logs" && user?.role === "admin" ? (
            <AuditLogs apiFetch={apiFetch} />
          ) : active === "Research & Feeds" ? (
            <ResearchWorkbench />
          ) : active === "Analysis Approvals" ? (
            <SubmissionReview />
          ) : active === "Provider Settings" && user?.role === "admin" ? (
            <ProviderSettings apiFetch={apiFetch} />
          ) : (
            <section className="panel coming-panel">
              <div className="coming-icon"><Settings2 size={25} /></div>
              <div className="eyebrow">WORKSPACE MODULE</div>
              <h2>{active}</h2>
              <p>This module is being connected to the authenticated intelligence API. Access is controlled by your account role.</p>
              <button className="primary-button" onClick={() => selectPage("Overview")}>Return to overview <ArrowRight size={15} /></button>
            </section>
          )}

          <footer className="page-footer"><span>UNIFIED THREAT INTELLIGENCE</span><span>INTERNAL USE ONLY <i /> AUTHENTICATED WORKSPACE</span></footer>
        </div>
      </main>
    </div>
  );
}
