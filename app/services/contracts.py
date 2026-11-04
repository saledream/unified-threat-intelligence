"""Versioned, extensible normalized report contracts."""
from pydantic import BaseModel, ConfigDict, Field

class ProviderResult(BaseModel):
    model_config = ConfigDict(extra='allow')
    provider: str
    status: str
    query_type: str | None = None
    query_indicator: str | None = None
    retrieved_at: str | None = None
    cached: bool = False

class IntelligenceReport(BaseModel):
    model_config = ConfigDict(extra='allow')
    schema_version: str = '1.0'
    indicator: str
    request_id: str
    generated_at: str
    status: str
    indicator_type: str | None = None
    normalized_representations: dict[str, str] = Field(default_factory=dict)
    assessment: str | None = None
    assessment_reason: str | None = None
    evidence: list[dict] = Field(default_factory=list)
    provider_results: list[ProviderResult] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
