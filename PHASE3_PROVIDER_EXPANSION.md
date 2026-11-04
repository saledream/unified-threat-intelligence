> Historical development notes. The current deployment is an account-free search page with 41 passive MCP tools. See [README.md](README.md) for current behavior; prior authentication, administration, and submission interfaces described below have been removed.

# Phase 3 provider expansion

Implemented passive integrations for OTX multi-indicator lookup, IANA-bootstrap RDAP domain registration, urlscan.io historical search, licensed VirusTotal v3 report lookup.

## Configuration
- `OTX_API_KEY`: enables OTX.
- `URLSCAN_API_KEY`: recommended for urlscan quotas; historical search only, never URL submission.
- `VIRUSTOTAL_API_KEY` plus `VIRUSTOTAL_COMMERCIAL_AUTHORIZED=true`: both are required. Do not set the authorization flag for a Community/public key in an commercial workflow.

RDAP requires no API key. It discovers the authoritative RDAP service through the IANA DNS bootstrap registry.

## Assessment methodology
Evidence carries a source reliability policy tier and a recency band. A malicious overall assessment requires evidence from at least two distinct providers and at least one current/recent high-reliability source. A single provider signal remains suspicious. Scores from different providers are never averaged.

Related IOCs are extracted from successful provider evidence, deduplicated by type/value, attributed to the providers that exposed them, and capped to prevent response explosion. Relationships are labelled `observed_with`; this is correlation context, not a causal claim.
