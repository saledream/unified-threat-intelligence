from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.audit import record_audit
from app.api.rate_limit import (
    is_login_blocked,
    record_login_failure,
    clear_login_failures,
)
from app.api.dependencies import get_current_user, require_admin
from app.api.schemas import (
    LoginRequest,
    UserCreateRequest,
    UserRoleUpdateRequest,
)
from app.auth.security import (
    create_access_token,
    hash_password,
    verify_password,
    JWT_EXPIRE_MINUTES,
)
from app.database import get_db
from app.models import User


router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/login")
def login(
    data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    source_ip = request.client.host if request.client else "unknown"

    if is_login_blocked(db, data.username, source_ip):
        record_audit(
            db, None, "auth.login.rate_limited", "blocked", request=request
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again in 15 minutes.",
            headers={"Retry-After": "900"},
        )

    user = db.scalar(
        select(User).where(User.username == data.username)
    )

    if (
        user is None
        or not user.is_active
        or not verify_password(
            data.password.get_secret_value(), user.password_hash
        )
    ):
        record_login_failure(db, data.username, source_ip)
        record_audit(
            db, None, "auth.login.failure", "failure", request=request
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    clear_login_failures(db, data.username, source_ip)
    record_audit(db, user, "auth.login.success", request=request)

    token = create_access_token(
        user.id, user.username, user.role, user.token_version
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRE_MINUTES * 60,
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
        },
    }


@router.get("/me")
def current_user(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at,
    }


@router.post("/logout")
def logout(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    user.token_version += 1
    record_audit(db, user, "auth.logout", request=request)
    return {"message": "All sessions have been revoked. Discard the access token."}


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    users = db.scalars(select(User).order_by(User.id)).all()

    return [
        {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": user.created_at,
        }
        for user in users
    ]


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(
    data: UserCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    existing = db.scalar(
        select(User).where(User.username == data.username)
    )

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists.",
        )

    user = User(
        username=data.username,
        password_hash=hash_password(data.password.get_secret_value()),
        role=data.role,
        is_active=True,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    record_audit(db, admin, "user.create", request=request)

    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
    }


@router.patch("/users/{user_id}/role")
def update_user_role(
    user_id: int,
    data: UserRoleUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target = db.get(User, user_id)

    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")

    if target.id == admin.id and data.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot remove your own administrator role.",
        )

    if target.role != data.role:
        target.role = data.role
        target.token_version += 1
        db.commit()
        record_audit(db, admin, "user.role.update", request=request)

    return {
        "id": target.id,
        "username": target.username,
        "role": target.role,
    }


@router.patch("/users/{user_id}/active")
def set_user_active(
    user_id: int,
    active: bool,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    target = db.get(User, user_id)

    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")

    if target.id == admin.id and not active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account.",
        )

    if target.is_active != active:
        target.is_active = active
        target.token_version += 1
        db.commit()
        record_audit(db, admin, "user.active.update", request=request)

    return {
        "id": target.id,
        "username": target.username,
        "is_active": target.is_active,
    }
