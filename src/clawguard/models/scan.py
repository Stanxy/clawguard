from __future__ import annotations

from pydantic import BaseModel

from clawguard.models.enums import Action, ScannerType, Severity


class ScanRequest(BaseModel):
    content: str
    destination: str | None = None
    agent_id: str | None = None
    tool_name: str | None = None


class FindingResponse(BaseModel):
    scanner_type: ScannerType
    finding_type: str
    severity: Severity
    start: int
    end: int
    redacted_snippet: str | None = None


class ScanResponse(BaseModel):
    action: Action
    suggested_action: Action | None = None
    content: str | None = None
    findings: list[FindingResponse] = []
    findings_count: int = 0
    scan_id: int | None = None
    duration_ms: float = 0.0
