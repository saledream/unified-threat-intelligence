from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.audit import record_audit
from app.api.dependencies import require_analyst, require_authenticated
from app.api.schemas import (
    HashEnrichmentRequest,
    IndicatorValidationRequest,
    IpEnrichmentRequest,
    MitreSearchRequest,
    ThreatFoxRequest,
    UrlhausRequest,
)
from app.database import get_db
from app.services.registry import provider_status as get_provider_status
from app.models import User
from app.services.enrichment import (
    enrich_file_hash_malwarebazaar,
    enrich_indicator_threatfox,
    enrich_ip_abuseipdb,
    enrich_ip_all,
    enrich_ip_greynoise,
    enrich_ip_otx,
    enrich_url_urlhaus,
)
from app.services.indicators import validate_indicator
from app.services.mitre_attack import get_technique, search_techniques


router = APIRouter(prefix="/api", tags=["Threat Intelligence"])


@router.get("/health")
def health():
    return {"status": "ok", "service": "MMCY Threat Intelligence API"}


@router.get("/providers/status")
def provider_status(user: User = Depends(require_authenticated)):
    return get_provider_status()


@router.post("/indicators/validate")
def validate(
    data: IndicatorValidationRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    result = validate_indicator(data.indicator, data.indicator_type)
    outcome = result.get("status", "unknown")

    record_audit(
        db, user, "indicator.validate", outcome,
        data.indicator, data.indicator_type, request,
    )
    return result


async def run_enrichment(
    operation,
    action: str,
    indicator: str,
    indicator_type: str,
    request: Request,
    db: Session,
    user: User,
):
    try:
        result = await operation()
        outcome = result.get("status", "success") if isinstance(result, dict) else "success"
        record_audit(
            db, user, action, outcome,
            indicator, indicator_type, request,
        )
        return result
    except Exception:
        record_audit(
            db, user, action, "error",
            indicator, indicator_type, request,
        )
        raise HTTPException(
            status_code=502,
            detail="The intelligence provider request could not be completed.",
        )


@router.post("/enrichment/ip")
async def enrich_ip_combined(
    data: IpEnrichmentRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    return await run_enrichment(
        lambda: enrich_ip_all(data.ip),
        "enrichment.ip.all",
        data.ip,
        "ip",
        request,
        db,
        user,
    )


@router.post("/enrichment/ip/abuseipdb")
async def enrich_ip_abuse(
    data: IpEnrichmentRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    return await run_enrichment(
        lambda: enrich_ip_abuseipdb(data.ip, data.max_age_days),
        "enrichment.ip.abuseipdb",
        data.ip,
        "ip",
        request,
        db,
        user,
    )


@router.post("/enrichment/ip/greynoise")
async def enrich_ip_grey(
    data: IpEnrichmentRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    return await run_enrichment(
        lambda: enrich_ip_greynoise(data.ip),
        "enrichment.ip.greynoise",
        data.ip,
        "ip",
        request,
        db,
        user,
    )


@router.post("/enrichment/ip/otx")
async def enrich_ip_otx_route(
    data: IpEnrichmentRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    return await run_enrichment(
        lambda: enrich_ip_otx(data.ip),
        "enrichment.ip.otx",
        data.ip,
        "ip",
        request,
        db,
        user,
    )


@router.post("/enrichment/hash")
async def enrich_hash(
    data: HashEnrichmentRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    return await run_enrichment(
        lambda: enrich_file_hash_malwarebazaar(data.file_hash),
        "enrichment.hash.malwarebazaar",
        data.file_hash,
        "hash",
        request,
        db,
        user,
    )


@router.post("/enrichment/threatfox")
async def enrich_threatfox(
    data: ThreatFoxRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    return await run_enrichment(
        lambda: enrich_indicator_threatfox(
            data.indicator, data.indicator_type
        ),
        "enrichment.threatfox",
        data.indicator,
        data.indicator_type,
        request,
        db,
        user,
    )


@router.post("/enrichment/urlhaus")
async def enrich_urlhaus(
    data: UrlhausRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    return await run_enrichment(
        lambda: enrich_url_urlhaus(data.url),
        "enrichment.urlhaus",
        data.url,
        "url",
        request,
        db,
        user,
    )


@router.get("/mitre/search")
def mitre_search(
    query: str,
    platform: str | None = None,
    limit: int = 10,
    user: User = Depends(require_authenticated),
):
    try:
        data = MitreSearchRequest(
            query=query, platform=platform, limit=limit
        )
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="Local ATT&CK dataset is not installed.")
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Invalid MITRE search parameters.") from exc

    try:
        return search_techniques(data.query, data.platform, data.limit)
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="Local ATT&CK dataset is not installed.")


@router.get("/mitre/techniques/{technique_id}")
def mitre_technique(
    technique_id: str,
    user: User = Depends(require_authenticated),
):
    if len(technique_id) > 20:
        raise HTTPException(status_code=422, detail="Invalid technique ID.")

    try:
        return get_technique(technique_id)
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="Local ATT&CK dataset is not installed.")


# The unified endpoint shares the same orchestrator as the MCP tool.
from app.api.schemas import UnifiedEnrichmentRequest
from app.services.unified import enrich_indicator_all as unified_enrich

@router.post("/enrichment/unified")
async def enrich_unified(
    data: UnifiedEnrichmentRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_analyst),
):
    return await run_enrichment(
        lambda: unified_enrich(data.indicator),
        "enrichment.unified", data.indicator, "auto", request, db, user,
    )
