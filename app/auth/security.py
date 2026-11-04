import os
from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash

password_hash = PasswordHash.recommended()

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))


def get_jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET_KEY", "")
    if len(secret) < 32:
        raise RuntimeError("JWT_SECRET_KEY must contain at least 32 characters.")
    return secret


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters.")
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)


def create_access_token(
    user_id: int,
    username: str,
    role: str,
    token_version: int = 0,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "ver": token_version,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        get_jwt_secret(),
        algorithms=[JWT_ALGORITHM],
        options={"require": ["sub", "iat", "exp", "ver"]},
    )
