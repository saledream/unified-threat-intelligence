# Connect an AI agent to the local threat intelligence MCP

## Current personal configuration: no authentication

MCP is configured with `MCP_AUTH_MODE=none` and bound to `127.0.0.1` for the current local test service. Agents need no username, password, bearer token or token refresh. There is no MCP session expiry caused by authentication. Provider API keys remain on the server and are still required by those providers.

Hermes profile `config.yaml`:

```yaml
mcp_servers:
  threat_intelligence:
    url: http://127.0.0.1:18545/mcp
```

No `headers` block or `AGENT_TOKEN` variable is needed. Port 18545 is the running local test harness; the Compose host endpoint is port 3002. This does not change your normal Hermes profile automatically. A client on another machine cannot reach this machine through its own localhost.

The dashboard/API still requires its normal login. Human approval for URL/file submissions is preserved. MCP exposes no approval tool; a dashboard administrator reviews the exact payload and disclosure before sending. Unauthenticated local MCP clients share the `local:anonymous` request principal, so there is no per-agent identity isolation in this mode. Tool calls continue to be audited as anonymous local calls.

## Optional authenticated deployments

`MCP_AUTH_MODE=platform` restores analyst/admin JWT authentication with the platform expiry/revocation rules. `MCP_AUTH_MODE=oidc` uses the separately configured identity provider. These modes remain available for deployments that need identifiable users; neither is used by the current personal no-auth MCP.

## Evidence and compatibility

The server exposes 44 typed, described tools. A real Hermes AIAgent programmatic run using the existing configured MiniMax model previously completed an IOC investigation. A follow-up model run hit the provider's HTTP 429 concurrency limit. The Windows Hermes CLI gateway reports `service_manager_unavailable`; that separate gateway setup does not affect the successful programmatic agent run or direct MCP connectivity.

The current no-auth mode was tested with an HTTP MCP client without credentials: discovery and Cloudflare Radar lookup succeeded, private IP lookup remained blocked, and no approval tool was exposed. The dashboard's unauthenticated identity endpoint still returned 401. No active scans or uploads were submitted.

Source searches accept `threatfox`, `ThreatFox` or `feed:threatfox` and report unknown filters explicitly. Treat first-seen dates as first observations, not proof of current activity; network context is not a maliciousness verdict.
