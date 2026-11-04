> Historical development notes. The current deployment is an account-free search page with 41 passive MCP tools. See [README.md](README.md) for current behavior; prior authentication, administration, and submission interfaces described below have been removed.

# Phase 2 — Incremental unified IOC engine

Implemented: shared provider capability registry, IOC type detection, validated routing, concurrent execution, bounded per-provider timeouts, failure isolation, unified MCP tool, authenticated REST endpoint `POST /api/enrichment/unified`, and offline regression tests.

**Limitations:** Evidence normalization/correlation, scoring, caching, expanded OTX support, URL historical lookup, and frontend changes remain outstanding. Current assessment is always `inconclusive`, intentionally. Existing URL validator requires HTTPS and resolves DNS, so HTTP IOC support and privacy-safe URL routing require further design. Do not assume all provider integrations support every advertised IOC format in their upstream API; verify with provider documentation before production. Existing provider tools and IP endpoint are preserved.

Run offline tests: `python -m pytest tests/test_unified.py -q` (pytest must be installed).
