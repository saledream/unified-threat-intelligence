"""Keep offline tests independent of any real provider credentials in local .env."""
import pytest

@pytest.fixture(autouse=True)
def offline_provider_environment(monkeypatch,tmp_path):
    monkeypatch.setenv('INTEL_STATE_DB',str(tmp_path/'intel-state.db'))
    monkeypatch.setenv('INTEL_STORAGE_KEY','')
    monkeypatch.setenv('ENABLE_SUBMISSIONS','false')
    monkeypatch.setenv('ENABLE_IDENTITY_LOOKUPS','false')
    monkeypatch.setenv('MCP_AUTH_MODE','platform')
    monkeypatch.setenv('MCP_TRANSPORT','http')
    for name in ('VIRUSTOTAL_API_KEY','ABUSEIPDB_API_KEY','GREYNOISE_API_KEY','OTX_API_KEY','ABUSECH_API_KEY','URLSCAN_API_KEY'):
        monkeypatch.setenv(name,'')
    monkeypatch.setenv('VIRUSTOTAL_USAGE_MODE','commercial')
    monkeypatch.setenv('INTEL_USAGE_MODE','commercial')
    monkeypatch.setenv('INTEL_PERSIST_CACHE','false')
    for key in ('SHODAN_API_KEY','IPINFO_TOKEN','PULSEDIVE_API_KEY','SPUR_TOKEN','CENSYS_API_TOKEN','CLOUDFLARE_API_TOKEN','CLOUDFLARE_ACCOUNT_ID','HIBP_API_KEY','LEAKCHECK_API_KEY','HUDSONROCK_API_KEY'):
        monkeypatch.setenv(key,'')
    monkeypatch.setenv('VIRUSTOTAL_COMMERCIAL_AUTHORIZED','false')
    monkeypatch.setenv('ABUSECH_COMMERCIAL_AUTHORIZED','false')
    monkeypatch.setenv('ABUSECH_USAGE_MODE','commercial')
    monkeypatch.setenv('INTERNAL_DOMAIN_SUFFIXES','')
    for name in ('ABUSEIPDB','GREYNOISE','OTX','THREATFOX','URLHAUS','MALWAREBAZAAR','RDAP','URLSCAN','VIRUSTOTAL'):
        monkeypatch.setenv(f'PROVIDER_{name}_ENABLED','true')
