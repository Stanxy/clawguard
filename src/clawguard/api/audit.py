from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from clawguard.dependencies import ServiceContainer, get_container
from clawguard.models.audit import AuditEntry

router = APIRouter()


@router.get("/audit", response_model=list[AuditEntry])
async def query_audit(
    agent_id: str | None = Query(None),
    destination: str | None = Query(None),
    action: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    container: ServiceContainer = Depends(get_container),
) -> list[AuditEntry]:
    events = await container.audit_repo.query_events(
        agent_id=agent_id,
        destination=destination,
        action=action,
        limit=limit,
        offset=offset,
    )
    return [AuditEntry.model_validate(e) for e in events]
