# Unified Threat Intelligence

A single search page for public IPs, domains, URLs, and file hashes. Search an indicator and review the results underneath. Expand a provider to see its source details.

There are no accounts, passwords, roles, login sessions, or tokens for the application or MCP. Provider API credentials stay on the server. Anyone who can reach the search endpoint can use the installation's configured providers and their quotas.

## Run locally

Install Docker with Compose and clone this repository:

```sh
git clone https://github.com/saledream/unified-threat-intelligence.git
cd unified-threat-intelligence
```

Copy `.env.example` to `.env` (`cp .env.example .env` on Linux/macOS, or `Copy-Item .env.example .env` in PowerShell). Fill in your provider credentials and usage modes, then start:

```sh
docker compose up -d --build
```

Open http://localhost:3005. No administrator bootstrap or database account is needed. Local MCP is available at http://127.0.0.1:3002/mcp. The API health endpoint is http://localhost:8000/api/health.

Authenticated Shodan and Censys are paused after access failures; certificate transparency is paused after repeated timeouts, and Spur until a usable token is configured. These integrations are disabled by default. Keyless Shodan InternetDB remains available. Disabled providers are omitted from search results; credentials are retained server-side for a future access check.

## Provider keys

Edit `.env` locally, or the Environment editor when using Dokploy. Leave unused providers blank.

| Provider | Variable |
|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` |
| AbuseIPDB | `ABUSEIPDB_API_KEY` |
| GreyNoise | `GREYNOISE_API_KEY` |
| AlienVault OTX | `OTX_API_KEY` |
| ThreatFox / URLhaus / MalwareBazaar | `ABUSECH_API_KEY` |
| Shodan host reports | `SHODAN_API_KEY` |
| IPinfo Lite | `IPINFO_TOKEN` |
| Pulsedive | `PULSEDIVE_API_KEY` |
| Spur | `SPUR_TOKEN` |
| Censys | `CENSYS_API_TOKEN` |
| Cloudflare Radar | `CLOUDFLARE_API_TOKEN` |
| urlscan | `URLSCAN_API_KEY` for account-dependent operations |

Certificate transparency, Shodan InternetDB, and public datasets have keyless capabilities, subject to their terms and policy gates. Cloudflare Radar does not need an account ID. The optional Cloudflare URL Scanner history integration needs its own permissions, account ID, and enable switch.

For your own non-business use:

```dotenv
INTEL_USAGE_MODE=personal
VIRUSTOTAL_USAGE_MODE=personal
ABUSECH_USAGE_MODE=personal
```

These modes do not grant access or override provider terms. Business use requires permitted subscriptions and the applicable authorization flags. A 403 or rate limit is displayed as an unavailable result, never as proof of safety.

Recreate services after changing environment values:

```sh
docker compose up -d --force-recreate
```

Keep `.env` out of source control. Provider switches use `PROVIDER_<NAME>_ENABLED`, for example `PROVIDER_OTX_ENABLED=false`.

## Dokploy

Follow [DOKPLOY.md](DOKPLOY.md). Select **Docker Compose**, repository branch `main`, and `./compose.dokploy.yaml`. Paste `.env.dokploy.example` into Environment, set `PUBLIC_HOSTNAME`, and add a HTTPS domain for `threat-intel-frontend` on port `3000`. Deploy and open the domain directly. There is no sign-in step.

## AI agents

Hermes configuration:

```yaml
mcp_servers:
  threat_intelligence:
    url: http://127.0.0.1:3002/mcp
```

Other Streamable HTTP MCP clients use the same URL without an authorization header. The server exposes 41 passive research tools, including `enrich_indicator_all`, `provider_lookup`, CVE context, local references, and bounded bulk investigations. It exposes no scan submission or approval tools.

## Data and scope

The browser shows one search and its results. All compatible providers are queried through the shared enrichment engine. Missing credentials, unsupported capabilities, errors, and rate limits are reported explicitly. Unavailable providers are collapsed in the interface.

Passive searches send indicators to selected intelligence providers; they do not connect to the target URL or request a new scan. Private/reserved IPs and configured internal domain suffixes remain blocked. Use `INTERNAL_DOMAIN_SUFFIXES` to list your private namespaces. An empty report does not establish safety.

PostgreSQL, user administration, dashboard audits, and the human submission workflow are no longer part of the deployed application. Previously created PostgreSQL volumes are not deleted by this change. Source and provider configuration are controlled server-side. Legacy submission service code remains unexposed for compatibility testing, not as a callable API.

The `intel_data` volume retains imported feeds/references and personal VirusTotal request counters. Reference datasets are not bundled; import through the container CLI:

```sh
docker compose exec threat-intel-api python -m app.services.feeds --once
docker compose exec threat-intel-api python -m app.services.knowledge attack
```

For optional encrypted persistent caches, configure `INTEL_STORAGE_KEY` with a Fernet key and preserve it. The legacy `JWT_SECRET_KEY` value can still derive an encryption key for existing records; it is not used for authentication. Provider quotas and caches are per process, so allocate budgets when scaling.

## Development

Use Python 3.12+ and Node.js 24. Create and activate a virtual environment, then:

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q
npm ci --prefix frontend
npm run lint --prefix frontend
npm run build --prefix frontend
```

The native API starts with `uvicorn app.api.main:app --host 127.0.0.1 --port 8000`; native HTTP MCP starts with `python -m app.main` on port 3000. Docker maps MCP to host port 3002.

Older assessment and expansion documents are historical development notes. This README and the Dokploy guide describe the current minimal search deployment.
