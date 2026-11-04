# MMCY Unified Threat Intelligence Platform

This repository extends the uploaded application. The FastAPI dashboard API and FastMCP tools share `app/services/unified.py`. Existing provider APIs, user administration, audits and local ATT&CK operations remain available. See `ARCHITECTURE_ASSESSMENT.md` for the baseline assessment and `IMPLEMENTATION_STATUS.md` for verification and release blockers.

## Expanded MCP (November 2026)

The server now offers 44 tools, 20 passive source capabilities, local reference/feed search, bulk investigations, optional breach metadata and a human approval queue for URL/file analysis. See [EXPANDED_MCP_GUIDE.md](EXPANDED_MCP_GUIDE.md) for capabilities, credentials, dataset imports, approval guarantees and remaining external dependencies. Passive IOC lookups never submit scans; optional DNS is policy-controlled.

## What changed

- Unified search is the dashboard's initial workflow. URLs route both full URL and hostname representations to capable adapters. Public IP URL literals also route to eligible IP adapters; target hostnames are not resolved by default; optional DoH is policy-controlled.
- The capability registry controls input types, IP versions/hash algorithms, adapter method, credentials, commercial gates, passive policy, reliability tiers, deadlines, retries, cache TTLs and pacing.
- Database provider switches apply to unified and legacy lookups, including MCP. Environment kill switches and licensing gates cannot be overridden in the UI.
- Provider execution isolates failures, uses bounded concurrency/deadlines, one bounded retry for transient failures, an in-memory TTL/LRU cache, request coalescing and Retry-After cooldowns. Search deadline is 55 seconds plus bounded policy loading. Cache, health and quotas are per worker, not distributed; split vendor quotas between API/MCP and workers before production.
- The normalized report has `schema_version: 1.0`, request IDs, query representations, per-lookup status and source detail, evidence and conservative assessment. MCP receives a compact projection with coverage/failures and investigation steps.
- Correlation separates contextual registration/history/pulse associations from threat evidence, collapses duplicate source records, groups shared references and feed ownership, and extracts related IOCs only from explicit IOC fields. Independent upstream provenance is not verified, so evidence yields `suspicious`, not an automatic `malicious` verdict. Source confidence is never averaged into a fabricated system score.
- HTTP MCP requires an active analyst/admin platform identity and checks revocable token versions. Its tool calls are audited without raw arguments. This intentionally closes prior unauthenticated HTTP access.

## Local setup

Use Python 3.12+ and Node 24. Install backend dependencies into a virtual environment:

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt
.venv/Scripts/python -m pytest -q
npm ci --prefix frontend
npm run lint --prefix frontend
npm run build --prefix frontend
```

Copy `.env.example` to a protected `.env` and supply database/JWT secrets through approved secret management. Never commit it. JWT_SECRET_KEY must be at least 32 characters. Configure `INTERNAL_DOMAIN_SUFFIXES` with MMCY's internal namespaces, including internal hosts beneath public DNS suffixes. The platform cannot infer whether an arbitrary public-looking URL contains confidential information; submit only indicators approved for third-party disclosure.

All network lookups are passive. HTTP IOC strings are supported as provider data; the application never connects to the target HTTP URL. Public IP checks reject multicast, reserved, private, link-local, mapped and transition addresses. RDAP service endpoints must be HTTPS, resolve exclusively to permitted public addresses, and are pinned to a checked address with the original TLS certificate hostname. Redirects/referrals are skipped. No certificate validation is disabled.

## Docker deployment

1. Make Docker's Linux daemon available and populate `.env` securely.
2. Optionally supply an approved ATT&CK STIX bundle as `data/mitre/enterprise-attack.json`. The archive does not contain a dataset. Its absence is reported clearly.
3. Run `docker compose build` and `docker compose up -d`. API startup creates missing tables, including the additive `provider_settings` table. Back up PostgreSQL before upgrades; no existing table is dropped.
4. Bootstrap the first admin interactively with `docker compose exec threat-intel-api python -m app.api.bootstrap_admin`.
5. Open the loopback frontend at `http://localhost:3005`. API listens on loopback port 8000, MCP on loopback port 3002. Configure an authenticated TLS reverse proxy for enterprise access, trusted hosts and allowed origins. Use HSTS only once HTTPS is configured.
6. Confirm `docker compose ps`, API health, login, roles, provider policy, a permitted passive lookup, source attribution and MCP authentication. Never enable active submissions as part of this workflow.

The frontend bind address/port is configurable; the uploaded hardcoded private address was removed. Do not expose PostgreSQL or plain HTTP bearer tokens on untrusted networks. Provider authorization and admin switches are separate: enabling a provider does not supply keys or approve licenses.

Compose configuration can be checked without a local `.env` by setting nonsecret test database values in the shell and running `docker compose --env-file .env.example config --no-env-resolution --quiet`. This is a configuration check, not deployment validation.

## Hermes and other MCP clients

HTTP endpoint: `http://127.0.0.1:3002/mcp` (or the approved TLS reverse-proxy address).

Use a dedicated analyst account. Obtain its short-lived access token from the existing `POST /api/auth/login` using approved credential handling, and configure the MCP client's Authorization header as a bearer token. Token expiry defaults to 30 minutes; the client must reauthenticate when it expires. Logout, deactivation and role changes revoke existing sessions. No permanent shared service secret or unauthenticated fallback was added.

The primary tool remains:

```text
enrich_indicator_all(indicator="https://public-host.example.org/path")
```

Legacy provider-specific tools remain registered with their original signatures. The unified tool is registered before module startup enters the HTTP server. Hermes itself was not supplied or connected; the offline MCP client/HTTP authentication tests are not a Hermes connectivity claim. Adapt the approved Hermes configuration to its supported HTTP/header mechanism rather than copying invented client configuration keys.

## Adding a provider

1. Verify official API documentation, terms, supported types/algorithms and passive operation. Record source links in `PROVIDER_REFERENCE.md`. Do not scrape unsupported services.
2. Add an adapter under `app/providers/` that performs passive HTTPS requests to fixed provider endpoints, never to arbitrary target URLs. Keep credentials server-side, avoid redirects/credential forwarding, and return explicit statuses for no-match, malformed responses, errors, rate limits and authorization failures.
3. Add one capability in `services/registry.py` and its module to `MODULES`; `lookup_method` selects the adapter method. Extend the dispatch argument mapping only if the adapter needs additional typed context. Both REST and MCP discover it from the same registry.
4. Add evidence normalization only for actual returned fields. Registry registration alone makes the provider queryable; unrecognized result fields must not create threat claims. Mark contextual records accurately and preserve source references and observation dates.
5. Add mocked HTTP contract tests and routing, failure, privacy and licensing tests. Configure timeout/retry/cache/pacing for MMCY's licensed quota. Verify the shared UI source-detail renderer handles its returned fields.

Provider adapters are not authorized to submit scans, upload files, retrieve malware, remediate or block assets. Those operations require a separately reviewed, explicitly authorized workflow and are absent here.

## Operational boundaries

- Configuration status does not verify a credential, license or live connectivity. Health shows the latest lookup seen by the current worker only.
- API and MCP caches/budgets are independent and memory-only. For multiple workers/replicas, allocate per-worker budgets or add a shared quota/cache service before scaling. Vendor 429 cooldowns are honored locally. The code does not assert compliance with unknown paid plan quotas.
- RDAP queries the exact hostname. A subdomain may have no record even when a parent domain is registered; no guessed parent registration is represented as a match. HTTP-only RDAP services and referrals are explicitly skipped.
- Search progress reports the request's pending state, not fabricated per-provider percentages. Results arrive as a bounded consolidated response; this is not streaming.
- SessionStorage bearer tokens preserve the existing frontend design and are sensitive to XSS. Deploy with reviewed TLS/proxy/content-security policy and dependency controls. A future HttpOnly-cookie migration needs CSRF and MCP separation design.
- Audit indicators now use keyed HMAC-SHA256. Old unkeyed digests remain historical data and are not directly comparable; rotating JWT_SECRET_KEY changes new digest identities and revokes signed sessions.
- Existing create-all startup is preserved. A migration framework, central quota/health service and enterprise SSO remain future operational improvements, not implemented claims.


## Personal VirusTotal testing

For your own personal, non-business use, set `VIRUSTOTAL_USAGE_MODE=personal` and configure `VIRUSTOTAL_API_KEY` privately in `.env`. Keep `VIRUSTOTAL_COMMERCIAL_AUTHORIZED=false`. The default usage mode remains commercial, preserving the original MMCY deployment guard. Unsupported/empty modes fail closed.

The adapter reserves each real personal API request against a persistent SQLite quota file (`VIRUSTOTAL_QUOTA_DB`, default `data/virustotal-personal-quota.sqlite3`), enforcing 4 requests per rolling minute and 500 per rolling 24 hours. Retries count too; cache hits do not. Store the quota file on a persistent writable location shared by local API/MCP processes using the same key. A missing/unwritable quota store blocks calls. The counter cannot observe requests made with your key by unrelated tools, so VirusTotal's own remaining quota and HTTP 429 response remain authoritative. Do not delete/reset the quota file to bypass limits.

A personal-mode Docker deployment needs a persistent writable quota volume; the default read-only commercial Compose setup does not provide one. No URL submissions, file uploads or sample downloads are added. The key is sent only server-side in the provider's API header and is never displayed by the dashboard. Never paste it in chat or commit it. See VirusTotal's current terms at https://docs.virustotal.com/reference/public-vs-premium-api .


IP endpoints such as `124.221.142.210:443` and `[2606:4700:4700::1111]:443` preserve the original input and port context. Providers that accept IP reports receive only the canonical IP. A port is not interpreted as a scan request, a confirmed open service, or a URL scheme.


For personal community use of ThreatFox/URLhaus/MalwareBazaar, set `ABUSECH_USAGE_MODE=personal` and supply `ABUSECH_API_KEY`. The commercial authorization flag remains false. The default mode for deployed business use stays commercial and still requires an explicit permitted-access attestation. Keys remain required in either mode.

Agent compatibility and connection checks are documented in [AGENT_COMPATIBILITY.md](AGENT_COMPATIBILITY.md). All 44 tools now include descriptions. The authenticated analyst-client workflow and a real Hermes AIAgent model run passed. Source-filter normalization and conservative evidence guidance were strengthened afterward; the follow-up model run encountered an external HTTP 429. The Windows Hermes gateway remains a separate setup limitation.

For the current personal setup, MCP authentication is disabled (`MCP_AUTH_MODE=none`, loopback binding). Agents connect by URL without a token or expiry. Dashboard login and human submission approval remain enabled. See `AGENT_COMPATIBILITY.md`.
