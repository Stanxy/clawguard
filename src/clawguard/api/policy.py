from __future__ import annotations

from fastapi import APIRouter, Depends

from clawguard.dependencies import ServiceContainer, get_container
from clawguard.models.enums import ScannerType
from clawguard.models.policy import PolicyConfig
from clawguard.scanners.custom_scanner import CustomScanner

router = APIRouter()


@router.post("/policy/reload")
async def reload_policy(
    container: ServiceContainer = Depends(get_container),
) -> dict:
    container.policy_engine.reload(container.settings.policy_path)

    # Reload custom patterns
    custom_scanner = container.registry.get(ScannerType.CUSTOM)
    if isinstance(custom_scanner, CustomScanner):
        custom_scanner.load_patterns(container.policy_engine.policy.custom_patterns)

    # Update redactor config
    container.redactor._config = container.policy_engine.policy.redaction

    # Sync disabled patterns
    container._sync_disabled_patterns()

    return {
        "status": "reloaded",
        "default_action": container.policy_engine.policy.default_action.value,
        "custom_patterns_count": len(container.policy_engine.policy.custom_patterns),
    }


@router.put("/policy")
async def update_policy(
    policy: PolicyConfig,
    container: ServiceContainer = Depends(get_container),
) -> dict:
    # Save to file and update in-memory policy
    container.policy_engine.save_to_file(container.settings.policy_path, policy)

    # Reload custom patterns into CustomScanner
    custom_scanner = container.registry.get(ScannerType.CUSTOM)
    if isinstance(custom_scanner, CustomScanner):
        custom_scanner.load_patterns(policy.custom_patterns)

    # Update redactor config
    container.redactor._config = policy.redaction

    # Sync disabled patterns
    container._sync_disabled_patterns()

    return policy.model_dump(mode="json")
