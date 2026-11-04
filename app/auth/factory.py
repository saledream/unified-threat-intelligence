"""Selectable MCP authentication: no-auth personal access, platform JWT, or configured OIDC."""
import os
from urllib.parse import urlsplit
from app.auth.mcp import PlatformTokenVerifier

def build_auth():
    mode=os.getenv('MCP_AUTH_MODE','platform')
    if mode=='none':return None
    if mode=='platform':return PlatformTokenVerifier()
    if mode!='oidc':raise ValueError('MCP_AUTH_MODE must be none, platform or oidc')
    names=('OIDC_CONFIG_URL','OIDC_CLIENT_ID','MCP_PUBLIC_URL','OIDC_AUDIENCE','OIDC_JWT_SIGNING_KEY','OIDC_CLIENT_REDIRECT_URIS')
    if any(not os.getenv(name) for name in names):raise ValueError('OIDC configuration is incomplete; refusing unauthenticated fallback')
    for name in ('OIDC_CONFIG_URL','MCP_PUBLIC_URL'):
        p=urlsplit(os.environ[name])
        if p.scheme!='https' or not p.hostname or p.username or p.password:raise ValueError(name+' must be an HTTPS URL without credentials')
    if len(os.environ['OIDC_JWT_SIGNING_KEY'])<32:raise ValueError('Use a random OIDC signing key with at least 32 characters')
    scopes=os.getenv('OIDC_REQUIRED_SCOPES','intel:read').split()
    if not scopes or 'intel:read' not in scopes:raise ValueError('OIDC must enforce the intel:read scope')
    from fastmcp.server.auth.oidc_proxy import OIDCProxy
    from key_value.aio.stores.memory import MemoryStore
    return OIDCProxy(config_url=os.environ['OIDC_CONFIG_URL'],client_id=os.environ['OIDC_CLIENT_ID'],
        client_secret=os.getenv('OIDC_CLIENT_SECRET') or None,base_url=os.environ['MCP_PUBLIC_URL'],
        audience=os.environ['OIDC_AUDIENCE'],required_scopes=scopes,
        allowed_client_redirect_uris=os.environ['OIDC_CLIENT_REDIRECT_URIS'].split(','),
        jwt_signing_key=os.environ['OIDC_JWT_SIGNING_KEY'],require_authorization_consent=True,
        client_storage=MemoryStore())
