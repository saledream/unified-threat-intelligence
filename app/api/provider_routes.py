"""Admin provider controls contain no credential values."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.api.dependencies import require_admin
from app.api.audit import record_audit
from app.database import get_db
from app.models import ProviderSetting, User
from app.services.registry import CAPABILITIES, inventory
from app.services.provider_runtime import state

router = APIRouter(prefix='/api/providers', tags=['Provider administration'])

class ProviderUpdate(BaseModel):
    enabled: bool

@router.get('/registry')
async def provider_registry(admin: User = Depends(require_admin)):
    import asyncio
    providers = await asyncio.to_thread(inventory)
    health = state()['health']
    return {'providers': [{**p, 'health': health.get(p['name'])} for p in providers],
            'health_scope': 'This API worker only; configuration status is not a connectivity test'}

@router.patch('/{name}')
def update_provider(name: str, data: ProviderUpdate, request: Request,
                    db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    if name not in {c.name for c in CAPABILITIES}:
        raise HTTPException(404, 'Unknown provider')
    row = db.get(ProviderSetting, name)
    if row is None:
        row = ProviderSetting(name=name, enabled=data.enabled)
        db.add(row)
    else:
        row.enabled = data.enabled
    record_audit(db, admin, f'provider.{name}.enable' if data.enabled else f'provider.{name}.disable', request=request)
    return {'name': name, 'enabled': row.enabled}
