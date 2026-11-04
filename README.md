# Unified Threat Intelligence Platform

Investigate public IP addresses, domains, URLs, and file hashes from a web dashboard or an AI agent using the Model Context Protocol (MCP).

The platform combines provider reports, local threat feeds, vulnerability context, and security reference search in one service. Provider failures and missing credentials are shown explicitly. Network ownership, open ports, popularity, and historical observations are presented as context rather than automatic proof of malicious activity.

## Features

- **Unified IOC enrichment:** query compatible sources together, or choose a specific provider.
- **44 MCP tools:** typed tools for IOC enrichment, source lookups, bounded bulk investigations and pivots, CVE research, and local search.
- **20 registered source capabilities:** including VirusTotal, AbuseIPDB, GreyNoise, AlienVault OTX, ThreatFox, URLhaus, MalwareBazaar, Shodan, IPinfo, Pulsedive, Spur, Censys, Cloudflare Radar, RDAP, and certificate transparency.
- **Local intelligence:** synchronize feeds and import ATT&CK, Sigma, LOLBAS, GTFOBins, HijackLibs, WADComs, and D3FEND references.
- **Vulnerability context:** NVD, FIRST EPSS, and CISA Known Exploited Vulnerabilities.
- **Dashboard administration:** accounts, provider controls, source details, audit records, and submission review.
- **Optional URL/file analysis:** requests require administrator review before anything is sent to a provider. Disabled by default.
- **Optional exposure tools:** breach metadata and password-hash checks, with separate consent and configuration requirements.

Not every provider supports every indicator type. Credentials, account permissions, terms, and quotas determine which capabilities are available.

## Quick start with Docker

### 1. Get the source

Install Git and Docker with the Compose plugin. On Windows or macOS, start Docker Desktop and use Linux containers.

```sh
git clone https://github.com/saledream/mmcy-threat-intelligence.git threat-intelligence
cd threat-intelligence
```

Copy the configuration template:

```sh
# Linux / macOS
cp .env.example .env
```

```powershell
# Windows PowerShell
Copy-Item .env.example .env
```

### 2. Configure your installation

Edit `.env`. Supply your own database password and a random JWT secret of at least 32 characters. For example, generate a secret with Python:

```sh
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Use separate random values for the password and JWT secret. A minimal configuration is:

```dotenv
POSTGRES_DB=threat_intel
POSTGRES_USER=threat_intel
POSTGRES_PASSWORD=REPLACE_WITH_A_RANDOM_DATABASE_PASSWORD
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
JWT_SECRET_KEY=REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_CHARACTERS

MCP_AUTH_MODE=none
MCP_HOST=127.0.0.1
```

Keep the other template settings unless you need to change them. No provider keys are included in this repository. You can start without paid integrations and add credentials later.

For your own non-business use, set:

```dotenv
INTEL_USAGE_MODE=personal
VIRUSTOTAL_USAGE_MODE=personal
ABUSECH_USAGE_MODE=personal
```

These settings select application policy; they do not grant provider access or change provider terms. For business use, retain commercial mode and enable authorization flags only after confirming that your subscription permits the intended use.

### 3. Build and start

```sh
docker compose up -d --build
docker compose ps
```

After the API is healthy, create the first dashboard administrator:

```sh
docker compose exec threat-intel-api python -m app.api.bootstrap_admin
```

Follow the prompts. The password must contain at least 12 characters. Bootstrap refuses to create another administrator once one exists.

### 4. Open the dashboard

| Service | Local address |
|---|---|
| Dashboard | http://localhost:3005 |
| API health | http://localhost:8000/api/health |
| MCP endpoint | http://127.0.0.1:3002/mcp |

Log in with the administrator account you created. Review provider settings, then search for a public indicator such as `8.8.8.8`.

The Compose configuration publishes services on loopback. Inside the MCP container, Compose sets `MCP_HOST=0.0.0.0` so that port forwarding works; the host port remains bound to `127.0.0.1`.

## Add provider API keys

Store credentials in your local `.env`, never in source code or an agent prompt.

| Provider / capability | Configuration |
|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` |
| AbuseIPDB | `ABUSEIPDB_API_KEY` |
| GreyNoise | `GREYNOISE_API_KEY` |
| AlienVault OTX | `OTX_API_KEY` |
| ThreatFox, URLhaus, MalwareBazaar | `ABUSECH_API_KEY`; review usage mode |
| Shodan authenticated host reports | `SHODAN_API_KEY` |
| IPinfo Lite | `IPINFO_TOKEN` |
| Pulsedive | `PULSEDIVE_API_KEY` |
| Spur | `SPUR_TOKEN` |
| Censys Platform | `CENSYS_API_TOKEN`; optional `CENSYS_ORG_ID` |
| Cloudflare Radar | `CLOUDFLARE_API_TOKEN`; no account ID required |
| Cloudflare URL Scanner | Token, `CLOUDFLARE_ACCOUNT_ID`, and `PROVIDER_CLOUDFLARE_URLSCANNER_ENABLED=true` |
| urlscan | `URLSCAN_API_KEY` for account-dependent operations |
| NVD | Optional `NVD_API_KEY` |
| Optional breach lookups | `HIBP_API_KEY` / `HUDSONROCK_API_KEY`, as applicable; separate identity opt-in required |

RDAP, certificate transparency, Shodan InternetDB, and several public datasets do not require a provider key, although terms, policy gates, and rate limits still apply. Local feed search needs imported data. DNS-over-HTTPS and Cloudflare URL Scanner are disabled by default.

After changing `.env`, recreate services so they receive the new values:

```sh
docker compose up -d --force-recreate
```

A configured key is not proof of permission to every endpoint. A `forbidden` response may indicate insufficient account access; a rate limit or provider error is not a clean result.

VirusTotal personal mode maintains a persistent request counter and enforces 4 requests per rolling minute and 500 per rolling 24 hours. Requests from unrelated tools using the same key are outside that local counter.

## Connect an AI agent

The template selects **local MCP without authentication**. Agents need only the MCP URL; no bearer token or token renewal is required. Dashboard login and administrator submission approval remain enabled.

For Hermes, add this to your own `config.yaml`:

```yaml
mcp_servers:
  threat_intelligence:
    url: http://127.0.0.1:3002/mcp
```

For other clients, add a Streamable HTTP MCP server using the same URL through the client's supported configuration interface. The client must run on the same host, or have an explicitly configured secure connection to it.

Try these agent requests:

- "Show which threat intelligence providers are configured."
- "Investigate 8.8.8.8 and separate threat evidence from network context."
- "Look up this SHA-256 hash without submitting or downloading a file."
- "Explain the available evidence for a CVE using NVD, EPSS, and KEV."

The main unified tool is:

```text
enrich_indicator_all(indicator="8.8.8.8")
```

Provider-specific lookup is also available:

```text
provider_lookup(provider="shodan", indicator="8.8.8.8")
```

Unauthenticated local agents share one anonymous identity. For access by other users or over a network, configure `MCP_AUTH_MODE=platform` or `oidc`, authentication, and TLS before changing the loopback bindings. Provider API keys stay on the server in every mode.

## Import feeds and references

Downloaded intelligence and reference corpora are not bundled with the source. A fresh installation starts without those local datasets.

Synchronize feeds once:

```sh
docker compose exec threat-intel-api python -m app.services.feeds --once
```

Or run the optional recurring feed worker:

```sh
docker compose --profile feeds up -d
```

Import reference corpora through the dashboard, or import individual supported corpora from the container:

```sh
docker compose exec threat-intel-api python -m app.services.knowledge attack
docker compose exec threat-intel-api python -m app.services.knowledge sigma
```

Some feeds require credentials. OpenPhish requires reviewing its terms and setting `OPENPHISH_TERMS_ACCEPTED=true`. Dataset licenses and notices remain those of their upstream publishers.

## Optional URL and file submissions

Passive lookups retrieve existing reports; they do not submit a scan or upload a sample.

To allow submission requests, explicitly set `ENABLE_SUBMISSIONS=true` and configure the relevant provider. An administrator must review the exact payload and disclosure acknowledgement in **Analysis Approvals** before execution. MCP tools can request analysis but cannot approve it.

Supported workflows include VirusTotal URL/file analysis and urlscan or Cloudflare URL analysis. Files are limited to 16 MiB. Pending payloads are encrypted, expire after 15 minutes, and bind approval to the exact operation. Interrupted submissions can be marked uncertain and are not automatically resubmitted.

Provider sharing rules still apply: standard VirusTotal submissions may be shared, and unlisted URL reports are not confidential storage. Submit only data you are authorized to disclose.

## Data, privacy, and operation

- Never commit `.env`, API keys, passwords, or local intelligence databases.
- Configure `INTERNAL_DOMAIN_SUFFIXES` for private namespaces before investigating sensitive indicators. Private and reserved IP inputs are rejected for external enrichment.
- URL indicators are sent as data to selected providers; passive enrichment does not fetch the target URL. Optional DNS resolution is separately controlled.
- PostgreSQL accounts and audit data persist in `postgres_data`; intelligence state, imports, and quota files persist in `intel_data`.
- Back up both data volumes and protect configuration secrets. Changing encryption keys can make existing encrypted records unreadable.
- `docker compose down` stops the stack while preserving volumes. Adding `-v` deletes those volumes.
- Provider caches, pacing, and cooldowns are per process. Multi-worker deployments need a quota allocation strategy.
- Results are investigative evidence, not a guarantee that an indicator is safe or malicious. Preserve source attribution and distinguish first-seen dates from current activity.

## Development and checks

For development outside Docker, use Python 3.12+ and Node.js 24. The Docker images use Python 3.13 and Node.js 24.

```sh
python -m venv .venv
```

Activate the virtual environment using your shell, then run:

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q
npm ci --prefix frontend
npm run lint --prefix frontend
npm run build --prefix frontend
```

For a native backend process, configure a reachable PostgreSQL host and port in `.env`. The Compose database is exposed locally at `127.0.0.1:5433`. Run the API with `uvicorn app.api.main:app --host 127.0.0.1 --port 8000`. Run HTTP MCP with `python -m app.main`; its native default port is 3000. Set `MCP_TRANSPORT=stdio` for a local stdio client.

The automated suite previously passed 144 tests. This does not establish that every provider account, Docker environment, or identity provider is operational. Test your own deployment and required integrations.

## Troubleshooting

| Symptom | What to check |
|---|---|
| Docker cannot connect | Start Docker Desktop or the Linux Docker daemon. |
| API startup fails | Database credentials, PostgreSQL health, and a JWT secret of at least 32 characters. |
| Dashboard cannot reach the API | `docker compose logs threat-intel-api threat-intel-frontend`; internal API URL and allowed origins. |
| Provider is not configured | Add its key in `.env` and recreate services. |
| Provider requires authorization | Review its usage mode, terms, and authorization flags. |
| Provider returns 403 | Account permissions or endpoint entitlement; do not interpret this as no threat found. |
| Provider returns 429 | Wait for its quota window; reduce requests and check other applications using the key. |
| Local reference search is empty | Import the required reference corpus or synchronize feeds. |
| Agent cannot connect | Use port 3002 for Compose, confirm the client can reach the host, and check MCP logs/authentication mode. |

More adapter and dataset details are in [the expanded capability guide](EXPANDED_MCP_GUIDE.md). Historical implementation and test notes describe earlier development environments; use the setup and endpoint instructions above for a fresh installation.
