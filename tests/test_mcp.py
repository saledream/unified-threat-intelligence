import asyncio
import runpy
import sys
from unittest.mock import patch
from fastmcp import Client
from app.main import mcp

async def test_no_auth_mode_accepts_client_without_token(monkeypatch):
    from fastmcp import FastMCP
    from app.auth.factory import build_auth
    monkeypatch.setenv('MCP_AUTH_MODE','none')
    auth=build_auth()
    assert auth is None
    server=FastMCP('local no-auth check',auth=auth)
    @server.tool()
    def ready()->dict:
        """Read readiness."""
        return {'status':'ok'}
    async with Client(server) as client:
        assert (await client.call_tool('ready',{})).data['status']=='ok'

def test_anonymous_requests_have_a_distinct_local_principal(monkeypatch):
    from app.expanded_tools import principal
    monkeypatch.setenv('MCP_AUTH_MODE','none')
    monkeypatch.setattr('app.expanded_tools.get_access_token',lambda:None)
    assert principal()=='local:anonymous'

async def test_mcp_lists_unified_and_legacy_tools():
    async with Client(mcp) as client:
        tools=await client.list_tools()
        assert all(t.description for t in tools), "Every agent-facing tool needs a description"
        names={t.name for t in tools}
        assert {'enrich_indicator_all','enrich_ip_all','enrich_indicator_threatfox','search_attack_techniques'} <= names
        out=await client.call_tool('enrich_indicator_all',{'indicator':'127.0.0.1'})
        assert out.data['status']=='blocked'


def test_module_registers_unified_tool_before_starting_server():
    captured=[]
    def run(self,**kwargs):
        captured.extend(t.name for t in asyncio.run(self.list_tools()))
        assert self.auth is not None
    with patch.dict(sys.modules):
        sys.modules.pop('app.main', None)
        with patch('fastmcp.FastMCP.run',run):
            runpy.run_module('app.main',run_name='__main__')
    assert 'enrich_indicator_all' in captured
