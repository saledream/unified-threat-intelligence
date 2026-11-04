# Repository assessment and implementation roadmap

Assessment date: 2026-11-04. Baseline commit: `6fbb843`. The original uploaded ZIP remains unchanged. Historical PHASE documents describe prior work and are not current verification evidence.

## Existing architecture

FastAPI (`app/api/main.py`) serves JWT authenticated REST routes, SQLAlchemy/PostgreSQL users, revocable token versions, roles, audit events and database-backed login throttling. FastMCP (`app/main.py`) exposes legacy enrichment and local ATT&CK tools. Both already call `services/unified.py`; adapters use async HTTPX. Next.js/React uses a same-origin API rewrite and sessionStorage bearer tokens. Compose defines separate API, MCP, frontend and PostgreSQL services with non-root application containers.

## Existing provider capabilities (before changes)

| Adapter | Advertised types | Configuration | Concern |
|---|---|---|---|
| AbuseIPDB | IP | ABUSEIPDB_API_KEY | reputation is contextual, not proof |
| GreyNoise | IP | GREYNOISE_API_KEY | malicious classification ignored by correlation |
| OTX | IP/domain/URL/hash | OTX_API_KEY | pulse association is not independent proof |
| ThreatFox | IP/domain/URL/hash | ABUSECH_API_KEY | hash uses wrong query operation; verify formats |
| URLhaus | URL | ABUSECH_API_KEY | HTTP IOCs rejected by shared validator |
| MalwareBazaar | MD5/SHA1/SHA256 | ABUSECH_API_KEY | shared feed ownership matters for independence |
| RDAP | domain | no key | unrestricted redirects; no bootstrap cache; subdomain misses |
| urlscan | IP/domain/URL | optional API key | historical records are context, not malicious matches |
| VirusTotal | IP/domain/URL/hash | key + commercial authorization | keep commercial gate |
| MITRE ATT&CK | local search | data/mitre/enterprise-attack.json | dataset absent from upload |

## Findings and technical debt

- MCP unified tool is registered after the blocking `mcp.run`, so direct module startup omits it. MCP HTTP has no authentication.
- Docker copies missing `data/`. Compose hardcodes the organization's private frontend bind address. `.env.example` omits database, JWT and existing adapter keys.
- Existing tests include a mock with the wrong function signature and interpret arbitrary two providers as independent corroboration. Related IOC extraction scans source references and prose, inventing relationships.
- URL searches query only the URL representation for multi-type providers, missing hostname intelligence. HTTP IOC strings, IDNs and several special-address forms need explicit validation policy.
- Registry lacks configuration/licensing/input/retry metadata; no caching, quota pacing or operational health.
- UI starts on overview, retains fragmented search navigation, and presents only raw JSON details. Administration status diverges from the expanded registry.
- Audit digests are unkeyed, authentication has no automated coverage, and no enrichment quota controls exist. SessionStorage remains an XSS-sensitive design tradeoff.
- No provider credentials, Hermes configuration, dataset or running Docker daemon is supplied. Live provider/Hermes/deployment verification depends on those resources.

## Staged roadmap

1. Preserve baseline and run available offline checks; record environment limitations.
2. Harden validation and make registry authoritative for passive routing, policy status, timeouts, bounded retries, cache/pacing and coverage. Preserve legacy APIs/tools.
3. Correct documented provider contracts; constrain RDAP destinations and redirects. Keep external commercial integrations gated; do not add unsupported Talos scraping.
4. Correct evidence provenance, deduplication and conservative assessment. Return source-linked structured MCP summaries from the shared engine; secure HTTP MCP.
5. Make unified search the default, show readable source details and honest loading/coverage states; retain user/audit/knowledge-base administration.
6. Add meaningful offline routing, provider-contract, security, auth and MCP tests; build frontend and validate Compose. Document operations, provider extension, verified results and external dependencies.

No active scans, uploads, malware downloads, containment or live IOC disclosure is authorized by this implementation workflow.
