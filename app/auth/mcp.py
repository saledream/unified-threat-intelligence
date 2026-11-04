"""MCP authentication uses the same revocable user identities as the dashboard."""
import asyncio
import jwt
from fastmcp.server.auth import AccessToken, TokenVerifier
from app.auth.security import decode_access_token


class PlatformTokenVerifier(TokenVerifier):
    def __init__(self):
        super().__init__(required_scopes=['intel:read'])

    async def verify_token(self, token: str):
        try:
            claims = decode_access_token(token)
            def check():
                from app.database import SessionLocal
                from app.models import User
                with SessionLocal() as db:
                    user = db.get(User, int(claims['sub']))
                    version = claims.get('ver')
                    if (user and user.is_active and user.role in ('admin', 'analyst')
                            and isinstance(version, int) and not isinstance(version, bool)
                            and version == user.token_version):
                        return user.id
            user_id = await asyncio.to_thread(check)
            if user_id is None:
                return None
            return AccessToken(token=token, client_id=f'mmcy-user-{user_id}', subject=str(user_id),
                               scopes=['intel:read'], expires_at=int(claims['exp']), claims=claims)
        except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
            return None
