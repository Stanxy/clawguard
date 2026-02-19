from __future__ import annotations

from fastapi import APIRouter, Depends

from clawguard import __version__
from clawguard.dependencies import ServiceContainer, get_container

router = APIRouter()


@router.get("/health")
async def health_check(
    container: ServiceContainer = Depends(get_container),
) -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "scanners": [st.value for st in container.registry.scanner_types],
        "policy_loaded": container.policy_engine.policy is not None,
        "default_action": container.policy_engine.policy.default_action.value,
    }
