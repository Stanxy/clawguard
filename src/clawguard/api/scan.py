from __future__ import annotations

import time

from fastapi import APIRouter, Depends

from clawguard.dependencies import ServiceContainer, get_container
from clawguard.models.enums import Action
from clawguard.models.scan import FindingResponse, ScanRequest, ScanResponse
from clawguard.utils.hashing import sha256_hash

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
async def scan_content(
    request: ScanRequest,
    container: ServiceContainer = Depends(get_container),
) -> ScanResponse:
    start = time.monotonic()

    # Determine which scanners to run based on destination
    scanner_types = container.policy_engine.get_scanners_for_destination(request.destination)

    # Run scanners
    findings = container.registry.scan_all(request.content, only=scanner_types)

    # Evaluate policy
    action = container.policy_engine.evaluate(
        findings,
        destination=request.destination,
        agent_id=request.agent_id,
    )

    # Apply action
    result = container.action_handler.handle(action, request.content, findings)

    duration_ms = (time.monotonic() - start) * 1000

    # Build finding responses (with redacted snippets, never raw secrets)
    finding_responses = []
    for f in findings:
        # Create a safe redacted snippet
        redacted = container.redactor._redact_value(f.matched_text)
        finding_responses.append(FindingResponse(
            scanner_type=f.scanner_type,
            finding_type=f.finding_type,
            severity=f.severity,
            start=f.start,
            end=f.end,
            redacted_snippet=redacted,
        ))

    # Audit log (async, never stores raw content)
    content_hash = sha256_hash(request.content)
    finding_records = [
        {
            "scanner_type": f.scanner_type.value,
            "finding_type": f.finding_type,
            "severity": f.severity.value,
            "start_offset": f.start,
            "end_offset": f.end,
            "redacted_snippet": container.redactor._redact_value(f.matched_text),
        }
        for f in findings
    ]

    scan_id = await container.audit_repo.log_scan({
        "agent_id": request.agent_id,
        "destination": request.destination,
        "content_hash": content_hash,
        "action": action.value,
        "findings_count": len(findings),
        "duration_ms": duration_ms,
        "findings": finding_records,
    })

    return ScanResponse(
        action=result.action,
        content=result.content,
        findings=finding_responses,
        findings_count=len(findings),
        scan_id=scan_id,
        duration_ms=round(duration_ms, 2),
    )
