# Expanded Threat Intelligence MCP

The existing unified engine, legacy tools and dashboard remain available. New adapters and services were independently implemented using official source contracts. No upstream server is installed or executed, and no community scoring algorithm was copied.

## What is available

| Capability | Implementation and limits | Verification |
|---|---|---|
| Unified and provider-specific IOC reports | 20 registered passive sources; IP/domain/URL/hash aliases, credential and policy checks, revocable platform authentication | Existing and expanded offline tests; live IP lookup |
| New passive adapters | Shodan InternetDB, IPinfo Lite, Pulsedive, Spur, Censys Platform, Cloudflare Radar IP context, optional Cloudflare URL Scanner history, crt.sh, opt-in Cloudflare DoH, local feeds | Shodan live; remaining account-dependent adapters require credentials/live verification |
| Bulk / investigation | At most 20 IOCs, four concurrent investigations; defanged IOC normalization; up to three explicit source-observed pivots, depth one | Offline tests; no target connections |
| CVE context | NVD description/CVSS, FIRST EPSS, CISA KEV; preserve differences between severity, probability and exploitation | Offline source-contract test; live KEV ingestion |
| Feed index | Feodo, SSLBL IP/certificate/JA3, KEV, ThreatFox, MalwareBazaar, URLhaus, subscribed OTX; OpenPhish terms gate | Nine sources synchronized live; OpenPhish not enabled |
| Local references | ATT&CK, Sigma, LOLBAS, GTFOBins, HijackLibs, WADComs, D3FEND; source commit/hash/notices; bounded archives and safe YAML parsing | All seven imported locally; browser search verified |
| Source details | OTX pulse search/details, MalwareBazaar tag/signature, URLhaus host, YARAify rule/hash metadata, local SSLBL fingerprint matches | Functional adapters; live account-dependent query paths remain to verify |
| Breach / exposure | Explicit disclosure consent plus environment opt-in; HIBP email/verified domain, LeakCheck public metadata, Hudson Rock v3 metadata projection | Offline consent/projection tests; disabled locally; keys/entitlements required where applicable |
| Password checking | Accept a locally computed SHA-1 digest; send only five characters with HIBP padding; never accept a plaintext password | Offline request contract verified |
| Human-approved submissions | VirusTotal URL/file; urlscan URL (unlisted); Cloudflare URL (Unlisted); file limit 16 MiB; encrypted pending payloads; 15-minute expiry | Offline exactly-once, timeout, digest, ownership, role and password tests; browser request/review verified; **no live submission** |
| Analysis polling | One read per request per 30 seconds; fixed provider endpoints; VT personal quota applies | Implemented; live receipt polling not exercised |
| Persistent state | SQLite index and encrypted optional response cache/approval records; bounded retention and source synchronization leases | Offline encryption, expiry and preserved-data tests |
| Client transport | Existing authenticated HTTP; local stdio; optional FastMCP OIDC/PKCE proxy | In-process MCP schemas/tools tested; real IdP sign-in and Hermes remain unverified |

## Start and configure

Use `.env.example` for settings. Never place keys into chat, source control, screenshots, or usage-mode fields. Preserve `INTEL_STORAGE_KEY`: rotating it makes existing encrypted records unreadable. The actual local `.env` has new optional provider placeholders, an independent protected-storage key, personal usage mode and enabled approval requests. Identity disclosure and DNS lookup remain disabled by default.

Run API/MCP normally with the existing setup. HTTP MCP continues to require a platform analyst/admin bearer token. Give agents an analyst account; keep administrator passwords out of agent context. The dashboard **Analysis Approvals** screen requires an administrator password and explicit disclosure acknowledgement. MCP has no approval endpoint/tool. This is an application boundary, not proof of a physical human if an agent is separately given administrator credentials.

An approval binds the exact URL or file bytes, provider and visibility through its digest. The durable execution marker is claimed before sending. A crash/timeout after sending is `uncertain` and is never automatically resubmitted. Repeating approval returns conflict. Review such a request manually with the provider. Standard VirusTotal submissions can be shared; unlisted urlscan/Cloudflare reports are not confidential. No visibility fallback to public is performed.

Files arrive as bounded raw `application/octet-stream` bodies, remain in memory until encrypted, and are never executed or saved as plaintext samples. The file request endpoint uses `X-Filename` for display only. The API cleans expired pending payloads every minute while submission workflows are enabled, and on queue access. Records expire after 30 days. Reverse proxies must permit at least 16 MiB uploads and suitable timeouts; Next's local buffering limit is set to 17 MiB. Enforce deployment-wide request/concurrency limits at the reverse proxy for multi-user use.

The local feed/reference store is plaintext and intended for public intelligence. Do not subscribe this installation to confidential OTX pulses. Protected cache/submission payloads are encrypted separately. SQLite WAL supports the local single-host Compose deployment; it is not a distributed shared-filesystem database.

### Feed and reference commands

```powershell
# Load the desired environment before invoking these modules outside Compose.
python -m app.services.feeds --once
python -m app.services.feeds
python -m app.services.knowledge attack
python -m app.services.knowledge sigma
```

The Python module CLIs use the process environment; they do not load `.env` themselves. Compose supplies it. Each corpus can also be imported from the dashboard. Imported data and license manifests stay in `data/corpora`, with the full ATT&CK bundle in `data/mitre`; they are excluded from source archives and must be imported on a fresh deployment.

```powershell
docker compose --profile feeds up -d
```

The optional feed worker and API/MCP share the `intel_data` volume. Container execution still requires a functioning Docker daemon; this machine's Docker Desktop remains unavailable. Import references through the running API after deployment. PostgreSQL and Hermes production checks remain outstanding.

For local stdio, set `MCP_TRANSPORT=stdio` and run `python -m app.main`. Stdio trusts the local OS identity, and must not be exposed through an unauthenticated bridge. It can request approval, but cannot approve. Use HTTP for independently accountable platform users.

For OIDC, configure `MCP_AUTH_MODE=oidc`, HTTPS discovery/public URLs, client ID, audience, explicit client redirect URIs, `intel:read` scope, and a random signing key. Optional client secret depends on the IdP. The IdP must restrict app/scope assignment to authorized analysts. FastMCP handles consent and PKCE. This implementation uses an in-memory OAuth session store: restarting requires reauthorization, and multiple replicas require a separately configured shared encrypted OAuth store. OIDC identities do not inherit platform admin roles; requests are scoped to a hashed issuer/subject identity and are reviewed by a local administrator. Real IdP configuration is an external dependency.

## External dependencies and intentional scope

This is a substantial shared-engine expansion, not complete parity with every vendor subscription or every upstream hosting design. These are **not implemented/validated equivalents**:

- GreyNoise Enterprise GNQL/Recall/BSI/session/C2/alert products and Censys paid historical/timeline features require separate subscriptions and API-contract work; the existing GreyNoise Community and Censys current-host paths remain distinct.
- VirusTotal VTAI OAuth/agent-token federation is not equivalent to a classic personal API key. The independent classic v3 report/submission adapters are used here.
- Cloudflare Worker deployment, KV/D1/Durable Object infrastructure and vendor-managed OAuth hosting are not reproduced by a local Python server.
- Ahmia dark-web search and PhishTank are not connected: a maintained supported source contract/access setup is still required. No placeholder is advertised as an operational integration.
- No malware downloads, autonomous remediation, blocking/quarantine, arbitrary server-file reads, rule execution, or automatic MITRE attribution are introduced.

OpenPhish requires the user to review/accept its feed terms before setting `OPENPHISH_TERMS_ACCEPTED=true`. New IPinfo, Pulsedive, Spur, Censys and Cloudflare adapters remain unavailable until their respective keys/account settings are supplied. Account terms, quotas and paid entitlements still apply to personal usage.

## Primary contracts and dataset provenance

- [VirusTotal URL analysis](https://docs.virustotal.com/reference/scan-url), [file upload](https://docs.virustotal.com/reference/files-scan)
- [urlscan API](https://docs.urlscan.io/pages/api-intro), [visibility](https://docs.urlscan.io/pages/visibility)
- [Cloudflare history/submission](https://developers.cloudflare.com/radar/investigate/url-scanner/), [DNS JSON](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/)
- [Shodan InternetDB](https://internetdb.shodan.io/), [IPinfo Lite](https://ipinfo.io/developers/lite-api), [Pulsedive](https://docs.pulsedive.com/), [Spur](https://docs.spur.us/context-api), [Censys host endpoint](https://docs.censys.com/reference/v3-globaldata-asset-host)
- [YARAify](https://yaraify.abuse.ch/api/), [ThreatFox](https://threatfox.abuse.ch/api/), [MalwareBazaar](https://bazaar.abuse.ch/api/), [URLhaus](https://urlhaus-api.abuse.ch/), [SSLBL](https://sslbl.abuse.ch/blacklist/), [Feodo](https://feodotracker.abuse.ch/blocklist/)
- [HIBP](https://haveibeenpwned.com/API/v3), [LeakCheck public API](https://docs.leakcheck.io/public-api/lookup), [Hudson Rock v3](https://docs.hudsonrock.com/reference/search-by-login-emails)
- [NVD](https://nvd.nist.gov/developers/vulnerabilities), [EPSS](https://www.first.org/epss/api), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [ATT&CK](https://github.com/mitre-attack/attack-stix-data), [Sigma](https://github.com/SigmaHQ/sigma), [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS), [GTFOBins](https://github.com/GTFOBins/GTFOBins.github.io), [HijackLibs](https://github.com/wietze/HijackLibs), [WADComs](https://github.com/WADComs/WADComs.github.io), [D3FEND](https://d3fend.mitre.org/resources/)

Dataset licenses remain their upstream licenses; local import records retain source URLs and notices. The source archive excludes these downloaded datasets. Do not assume that all datasets use the MIT license just because the compared MCP servers do.

## Cloudflare endpoint correction

`cloudflare_radar` now calls `GET /client/v4/radar/entities/ip` for IP-to-country/ASN context. It requires the configured token but **no account ID**. It supplies context only, never a maliciousness verdict. The user-provided token was live-verified against 1.2.3.4 and 124.221.142.210.

`cloudflare_urlscanner` is a separate, default-disabled capability for historical URL scans. It requires the account ID and URL Scanner access. Human-approved Cloudflare submissions check that separate capability. A 403 from URL Scanner does not invalidate a token's Radar access. Existing environments can opt into the scanner with `PROVIDER_CLOUDFLARE_URLSCANNER_ENABLED=true` when the appropriate access is configured.

## Radar endpoint families

Four additional MCP tools use the same configured Cloudflare token and the `cloudflare_radar` provider policy, encrypted cache and pacing:

- `cloudflare_asn_lookup(ip)` calls `/radar/entities/asns/ip` for AS ownership context.
- `cloudflare_domain_rank(domain)` calls `/radar/ranking/domain/{domain}`. This also participates in unified domain/URL-host enrichment. It preserves exact ranks versus ranking buckets and does not infer safety from popularity.
- `cloudflare_ddos_trends(layer, dimension, view, days, location)` supports documented L3 and L7 dimensions, with summary or grouped time series, 1–30 days, and an optional two-letter location filter. L3 dimensions: PROTOCOL, IP_VERSION, VECTOR, DURATION, BITRATE, VERTICAL, INDUSTRY. L7 dimensions: HTTP_METHOD, HTTP_VERSION, IP_VERSION, MANAGED_RULES, MITIGATION_PRODUCT, VERTICAL, INDUSTRY.
- `cloudflare_email_security(dimension, view, days)` supports SPAM, MALICIOUS, SPOOF, THREAT_CATEGORY, ARC, DKIM, DMARC, SPF and TLS_VERSION; summary or grouped time series; 1–30 days. It does not query a mailbox or disclose an email address.

DDoS and email aggregates are separate research tools and are never fed into an IOC threat verdict. Returned provider metadata retains dataset time ranges, update times, normalization, units and confidence. Paths and dimensions are allowlisted, not an arbitrary authenticated API proxy. REST equivalents are `/api/intelligence/radar/asn`, `/domain-rank`, `/ddos` and `/email-security` under that same Radar prefix, and require analyst/admin authentication. The MCP now exposes 44 tools.

Official contracts: [AS details by IP](https://developers.cloudflare.com/api/resources/radar/subresources/entities/subresources/asns/methods/ip/), [domain ranking](https://developers.cloudflare.com/api/resources/radar/subresources/ranking/subresources/domain/methods/get/), [L3 summary](https://developers.cloudflare.com/api/resources/radar/subresources/attacks/subresources/layer3/methods/summary_v2/), [L7 summary](https://developers.cloudflare.com/api/resources/radar/subresources/attacks/subresources/layer7/methods/summary_v2/), [email security summary](https://developers.cloudflare.com/api/resources/radar/subresources/email/subresources/security/methods/summary_v2/).

## Authenticated Shodan capability

`shodan` is separate from `shodan_internetdb`. Configure `SHODAN_API_KEY`; the key already saved locally is used by the authenticated host adapter. It is available through unified IP/URL-IP enrichment, `provider_lookup(provider="shodan", indicator=...)`, the dedicated `shodan_host_lookup(ip)` MCP tool, and authenticated analyst/admin REST `GET /api/intelligence/shodan/host?ip=...`. Provider Settings controls it through `PROVIDER_SHODAN_ENABLED` and the shared database policy, runtime pacing/cache and audit infrastructure.

The adapter reads `GET https://api.shodan.io/shodan/host/{ip}` with history disabled, bounds response size and service count, and projects metadata without raw service banners. It never calls Shodan scan-submission or target endpoints. Report update times are not relabeled as malicious-activity observations; service/CVE exposure is context only. Both Shodan capabilities share provenance group `shodan`.

Configuration means a key is present; account entitlements are verified by the actual call. The user's current key was accepted by Shodan account-info but host lookup returned HTTP 403. This is reported as `forbidden` with an explanation, not a clean result or an automatic fallback. Keyless InternetDB remains available independently.

[Official Shodan host API contract](https://developer.shodan.io/api).

## Personal no-auth MCP mode

At the user's request, the current local MCP uses `MCP_AUTH_MODE=none` and `MCP_HOST=127.0.0.1`. Hermes needs only the server URL, no authorization header or expiring token. Dashboard login and human submission approval remain enforced. Local unauthenticated clients share `local:anonymous`; tool-call audits continue with no attributed user. Platform/OIDC authentication remain optional deployment modes. See `AGENT_COMPATIBILITY.md` for current connection instructions; earlier authenticated-test descriptions document historical validation.
