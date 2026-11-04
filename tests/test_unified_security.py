"""Offline safety and classification regression tests."""
from app.services.indicators import validate_indicator
from app.services.unified import detect_indicator

def test_url_validation_is_passive():
    # A valid public domain should not require network/DNS access.
    assert validate_indicator("https://example.org/path", "url")["valid"]

def test_internal_urls_rejected():
    # Block common SSRF and credential leakage patterns.
    for value in ("https://localhost/", "https://127.0.0.1/", "https://10.0.0.1/", "https://foo.local/", "https://user:password@example.org/"):
        assert not validate_indicator(value, "url")["valid"]

def test_invalid_url_ports():
    # Do not permit arbitrary destination ports.
    assert not validate_indicator("https://example.org:8443/", "url")["valid"]

def test_indicator_classification():
    # Ensure the unified entry point recognizes core IOC types.
    assert detect_indicator("8.8.8.8") == "ip"
    assert detect_indicator("https://example.org/a") == "url"
    assert detect_indicator("a" * 64) == "hash"
