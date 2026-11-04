from collections.abc import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.auth.security import decode_access_token
from app.database import get_db
from app.models import User


bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required or session expired.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise unauthorized

    try:
        payload = decode_access_token(credentials.credentials)
        user_id = int(payload["sub"])
        token_version = payload["ver"]

        if isinstance(token_version, bool) or not isinstance(token_version, int):
            raise ValueError("Invalid token version.")
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
        raise unauthorized

    user = db.get(User, user_id)

    if (
        user is None
        or not user.is_active
        or user.token_version != token_version
    ):
        raise unauthorized

    return user


def require_roles(*allowed_roles: str) -> Callable:
    def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )
        return user

    return role_checker


require_admin = require_roles("admin")
require_analyst = require_roles("admin", "analyst")
require_authenticated = require_roles("admin", "analyst", "viewer")
