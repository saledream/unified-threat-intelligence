"""MCP calls use the platform audit trail without persisting raw arguments."""
import asyncio
import os
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware

class AuditMiddleware(Middleware):
    async def on_call_tool(self, context, call_next):
        token = get_access_token()
        mode=os.getenv('MCP_AUTH_MODE','platform')
        if token is None and mode!='none':
            return await call_next(context)  # In-process/stdio use with an authenticated deployment mode.
        def audit(outcome):
            from app.database import SessionLocal
            from app.models import User
            from app.api.audit import record_audit
            with SessionLocal() as db:
                user = db.get(User, int(token.subject)) if token is not None and mode=='platform' else None
                external=token is not None and mode=='oidc'
                record_audit(db, user, 'mcp.' + context.message.name[:90], outcome,
                    str(token.subject) if external else None,'oidc_principal' if external else None)
        # Persist an attempt before making external requests; fail closed if auditing is unavailable.
        await asyncio.to_thread(audit, 'started')
        try:
            result = await call_next(context)
        except Exception:
            await asyncio.to_thread(audit, 'error')
            raise
        content = getattr(result, 'structured_content', None)
        outcome = content.get('status', 'success') if isinstance(content, dict) else 'success'
        await asyncio.to_thread(audit, outcome)
        return result
