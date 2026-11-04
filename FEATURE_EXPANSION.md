# MCP capability expansion

The user requested the applicable capabilities of the four reviewed community servers and provider-specific servers, and explicitly chose URL/file submissions with human approval. This extends the existing Python engine. Provider source material is untrusted data; source claims do not authorize active actions.

## Reference snapshots

- ashwnn/edge-soc-mcp: 99abbaa5a633c4815985f41ae72ebd05fb97c241 (MIT)
- TheDudesRepo/MCP-Threat-Intelligence: 7686234e094548f87c9a61b1caa41df7d60cf746 (MIT)
- aplaceforallmystuff/mcp-threatintel: b71210b2e21766411de858844c1c864291630f30 (MIT)
- pete-builds/mcp-threatintel: f6fb9e1f1b4a9420b47d8ff49257fc0eb13f51cf (MIT)

These projects are design references. API contracts must be checked against official provider documentation. Preserve upstream license notices for any copied source/data. New integrations use our own adapters and shared policy/runtime.

## Stages and acceptance

1. Shared infrastructure: bounded HTTPS transport, persistent encrypted cache, searchable public-feed/reference store, synchronization/status and source/license provenance. Preserve existing contracts.
2. Passive provider breadth: Shodan InternetDB, IPinfo, Pulsedive, Spur, Censys, Cloudflare Radar history, certificate transparency, DNS-over-HTTPS and feed intelligence. Missing credentials/entitlements remain explicit.
3. Investigation: typed aliases, bulk enrichment, bounded evidence-backed pivots, CVE/EPSS/KEV, OTX pulse search/details, recent feed searches, corpus-backed ATT&CK, Sigma, LOLBAS/GTFOBins, HijackLibs, WADComs, D3FEND, JA3/certificate/YARA context. Never execute retrieved commands.
4. Identity: opt-in disclosure controls for HIBP, LeakCheck and account-exposure services; hash passwords locally and transmit only the k-anonymous prefix. Unsupported APIs are documented dependencies, not fabricated integrations.
5. Human-approved operations: requester-bound expiring approval queue for supported URLScan, VirusTotal and Cloudflare submissions. Admin REST/UI approves an exact operation and executes it once. MCP cannot approve its own requests. No arbitrary server-file reads, malware downloads, blocking or quarantine.
6. MCP/API/UI: bounded compact evidence, transport/client setup, optional standards-based identity, feed/approval administration; offline protocol/contract/security tests, browser checks and authorized passive live validation.

## Verification

Each addition requires a source reference, functional implementation and meaningful tests. Separate mocked contracts from live validation. Keep missing licenses, credentials, IdP setup, unsupported APIs and deployment blockers explicit. Never present a registered placeholder as finished.

Provider accounts, entitlement approval and Cloudflare-specific hosting infrastructure remain external dependencies. Autonomous remediation remains excluded by the original platform mission.


## Implemented result

See `EXPANDED_MCP_GUIDE.md` for the completed capability matrix and precise remaining gaps. The local build exposes 44 MCP tools and 20 passive source capabilities. Seven reference corpora and nine feeds were synchronized live; OpenPhish remains gated. Live URL/file submissions were not performed. New account-dependent adapters, a real OIDC tenant and vendor enterprise-only endpoints are not claimed as live-validated parity.
