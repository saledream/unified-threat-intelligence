import os
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import Response

from app.database import init_db
from app.api.auth_routes import router as auth_router
from app.api.intel_routes import router as intel_router
from app.api.audit_routes import router as audit_router
from app.api.provider_routes import router as provider_router
from app.api.submission_routes import router as submission_router
from app.api.expanded_routes import router as expanded_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from app.services.submissions import cleanup_forever,enabled
    task=asyncio.create_task(cleanup_forever()) if enabled() else None
    try:yield
    finally:
        if task:
            task.cancel()
            await asyncio.gather(task,return_exceptions=True)


app = FastAPI(
    title="Unified Threat Intelligence API",
    description="Human-facing API for unified threat intelligence.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ALLOWED_ORIGINS", "http://localhost:3000"
    ).split(",")
    if origin.strip()
]

allowed_hosts = [
    host.strip()
    for host in os.getenv(
        "ALLOWED_HOSTS", "localhost,127.0.0.1"
    ).split(",")
    if host.strip()
]

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=allowed_hosts,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    response.headers["Cache-Control"] = "no-store"
    if os.getenv("ENABLE_HSTS", "false").lower() == "true":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


app.include_router(auth_router)
app.include_router(intel_router)
app.include_router(audit_router)
app.include_router(provider_router)
app.include_router(submission_router)
app.include_router(expanded_router)


@app.get("/")
def root():
    return {
        "service": "Unified Threat Intelligence API",
        "status": "ready",
        "docs": "/api/docs",
    }
