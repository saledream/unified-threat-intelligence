# Official provider references and decisions

Reviewed 2026-11-04. These links document contracts; offline tests do not prove current subscription entitlements or live account availability.

| Provider | Official reference | Implementation decision |
|---|---|---|
| AbuseIPDB | https://docs.abuseipdb.com/#check-endpoint | GET v2 check, public IPv4/IPv6, max age 1–365 days; key server-side |
| GreyNoise | https://docs.greynoise.io/reference/getcommunityip | Community v3 endpoint supports routable IPv4; IPv6 is marked unsupported; plan quotas apply |
| OTX | https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/OTXv2.py | Indicator type and general section paths; URL observable encoded as a path component; pulse associations remain context |
| ThreatFox | https://threatfox.abuse.ch/api/ | `search_ioc` for observables; `search_hash` for MD5/SHA256 associations; SHA1 not supported by hash search; records older than six months may be absent |
| MalwareBazaar | https://bazaar.abuse.ch/api/ | Passive `get_info` hash lookup; no sample downloads or uploads |
| URLhaus | https://urlhaus.abuse.ch/api/ | Preserve inherited passive URL lookup contract; current bulk API documentation requires account access, so live entitlement/contract verification remains a release gate |
| urlscan | https://docs.urlscan.io/pages/search-api-reference | Historical GET search; exact domain/URL keyword fields; no scan submission or result fetch to target sites |
| urlscan API | https://docs.urlscan.io/apis/urlscan-openapi/search | Search endpoint and pagination/result limits; returned verdicts used only when actually present |
| VirusTotal | https://docs.virustotal.com/reference/public-vs-premium-api | Personal Public API mode supported with 4/minute and 500/day limits; business workflows still require licensed authorization and a server-side key |
| VirusTotal reports | https://docs.virustotal.com/reference/url | Existing report GET only; no analysis submission |
| Cisco | https://developer.cisco.com/threat-grid/ | Supported Secure Malware Analytics APIs exist; no generic public Talos lookup endpoint is assumed. Operators must identify licensed product/access before an adapter is added |

SecurityTrails, Shodan and Censys are deferred pending a concrete intelligence use case, account entitlements, costs, privacy review and quota allocations. No integrations were added simply to increase the provider count.

`VIRUSTOTAL_COMMERCIAL_AUTHORIZED` and `ABUSECH_COMMERCIAL_AUTHORIZED` are operator attestations, not license validators. For business use, leave them false until permitted access is confirmed. Personal VirusTotal testing uses `VIRUSTOTAL_USAGE_MODE=personal` without setting the commercial flag. Commercial flags must not be used as a workaround for community restrictions or missing entitlements.
