import pytest
from app.services.indicators import validate_indicator

@pytest.mark.parametrize('value', ['0.0.0.0','127.0.0.1','10.0.0.1','169.254.169.254','224.0.0.1',
    '192.0.2.1','100.64.0.1','::1','fe80::1','ff02::1','2001:db8::1','::ffff:8.8.8.8','2002:0808:0808::1'])
def test_nonpublic_and_transition_addresses_blocked(value):
    result=validate_indicator(value,'ip')
    assert not result.get('external_lookup_allowed')

@pytest.mark.parametrize('value', ['https://u:p@example.org','https://127.1','https://2130706433',
    'https://[::1]/','https://foo.local/','https://example.org:8443/','https://example.org/#secret',
    'https://example.org/\nsecret','https://example.org\\@localhost/','ftp://example.org/a'])
def test_url_disclosure_bypasses_rejected(value):
    assert not validate_indicator(value,'url')['valid']

def test_configured_enterprise_suffix_is_blocked(monkeypatch):
    monkeypatch.setenv('INTERNAL_DOMAIN_SUFFIXES','example.org')
    assert not validate_indicator('https://private.example.org/a','url')['valid']
    assert validate_indicator('https://notexample.org/a','url')['valid']

def test_idna_and_url_normalization():
    assert validate_indicator('BÜCHER.DE.','domain')['indicator']=='xn--bcher-kva.de'
    assert validate_indicator('HTTP://EXAMPLE.ORG:80/a?x=A','url')['indicator']=='http://example.org/a?x=A'

@pytest.mark.parametrize('value,expected,port', [('124.221.142.210:443','124.221.142.210',443),('[2606:4700:4700::1111]:443','2606:4700:4700::1111',443)])
def test_endpoint_preserves_port_but_normalizes_public_ip(value,expected,port):
    result=validate_indicator(value,'ip')
    assert result['valid'] and result['external_lookup_allowed']
    assert result['indicator']==expected and result['port']==port

@pytest.mark.parametrize('value',['8.8.8.8:0','8.8.8.8:65536','8.8.8.8:https','[8.8.8.8]:443'])
def test_invalid_endpoint_ports_or_brackets(value):
    assert not validate_indicator(value,'ip')['valid']

def test_private_endpoint_remains_blocked():
    assert not validate_indicator('127.0.0.1:443','ip')['external_lookup_allowed']
