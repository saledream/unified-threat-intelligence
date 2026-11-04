# Phase 2: Evidence correlation increment

## Implemented
- `app/services/correlation.py`: conservative source-backed evidence normalization and explainable assessment.
- `app/services/unified.py`: uses the correlation layer for both REST and MCP callers.
- `tests/test_correlation.py`: offline tests for feed matches, duplicates, timeouts and no-match semantics.

## Verified
- `python -m pytest -q tests`: 8 tests passed.
- `python -m compileall -q app`: succeeded.

## Limitations
- This is a source-code increment, not a deployed release.
- Only within-provider ThreatFox duplicates are removed; cross-provider provenance and deduplication remain pending.
- URL DNS validation and SSRF protection need further review before production use.
- No live provider, frontend, Docker, or Hermes connectivity tests were run.
- No overall numerical risk score is fabricated.
