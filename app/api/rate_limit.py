import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.auth.security import get_jwt_secret
from app.models import LoginAttempt


MAX_FAILURES = 5
WINDOW_MINUTES = 15
LOCKOUT_MINUTES = 15


def _key_hash(category: str, value: str) -> str:
    secret = get_jwt_secret().encode("utf-8")
    message = f"{category}:{value.strip().lower()}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def _keys(username: str, source_ip: str) -> list[str]:
    return [
        _key_hash("account", username),
        _key_hash("ip", source_ip or "unknown"),
    ]


def is_login_blocked(db: Session, username: str, source_ip: str) -> bool:
    now = datetime.now(timezone.utc)
    rows = db.scalars(
        select(LoginAttempt).where(
            LoginAttempt.key_hash.in_(_keys(username, source_ip))
        )
    ).all()

    return any(
        row.locked_until is not None and (row.locked_until.replace(tzinfo=timezone.utc) if row.locked_until.tzinfo is None else row.locked_until) > now
        for row in rows
    )


def record_login_failure(db: Session, username: str, source_ip: str) -> None:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=WINDOW_MINUTES)
    lockout_until = now + timedelta(minutes=LOCKOUT_MINUTES)

    for key in _keys(username, source_ip):
        statement = insert(LoginAttempt).values(
            key_hash=key,
            failures=1,
            window_started_at=now,
            locked_until=None,
            updated_at=now,
        )
        excluded = statement.excluded
        expired = LoginAttempt.window_started_at < window_start
        next_failures = case(
            (expired, 1),
            else_=LoginAttempt.failures + 1,
        )

        statement = statement.on_conflict_do_update(
            index_elements=[LoginAttempt.key_hash],
            set_={
                "failures": next_failures,
                "window_started_at": case(
                    (expired, now),
                    else_=LoginAttempt.window_started_at,
                ),
                "locked_until": case(
                    (next_failures >= MAX_FAILURES, lockout_until),
                    (expired, None),
                    else_=LoginAttempt.locked_until,
                ),
                "updated_at": now,
            },
        )
        db.execute(statement)

    db.commit()


def clear_login_failures(db: Session, username: str, source_ip: str) -> None:
    db.execute(
        delete(LoginAttempt).where(
            LoginAttempt.key_hash.in_(_keys(username, source_ip))
        )
    )
    db.commit()
