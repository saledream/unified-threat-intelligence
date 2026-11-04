from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator


Role = Literal["admin", "analyst", "viewer"]
IndicatorType = Literal["ip", "domain", "url", "hash"]


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: SecretStr = Field(min_length=12, max_length=256)


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9._-]+$")
    password: SecretStr = Field(min_length=12, max_length=256)
    role: Role = "viewer"


class UserRoleUpdateRequest(BaseModel):
    role: Role


class IndicatorValidationRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=4096)
    indicator_type: IndicatorType


class IpEnrichmentRequest(BaseModel):
    ip: str = Field(min_length=1, max_length=64)
    max_age_days: int = Field(default=90, ge=1, le=365)


class HashEnrichmentRequest(BaseModel):
    file_hash: str = Field(min_length=32, max_length=64)


class ThreatFoxRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=4096)
    indicator_type: Literal["ip", "domain", "url", "hash"]


class UrlhausRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class MitreSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=200)
    platform: str | None = Field(default=None, max_length=80)
    limit: int = Field(default=10, ge=1, le=25)

    @field_validator("query")
    @classmethod
    def query_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Search query cannot be blank.")
        return value.strip()


class UnifiedEnrichmentRequest(BaseModel):
    # The server detects and validates the IOC type automatically.
    indicator: str = Field(min_length=1, max_length=4096)
