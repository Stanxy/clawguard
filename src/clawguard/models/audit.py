from __future__ import annotations

from pydantic import BaseModel


class AuditQuery(BaseModel):
    agent_id: str | None = None
    destination: str | None = None
    action: str | None = None
    limit: int = 50
    offset: int = 0


class AuditFinding(BaseModel):
    id: int
    scanner_type: str
    finding_type: str
    severity: str
    start_offset: int
    end_offset: int
    redacted_snippet: str | None = None


class AuditEntry(BaseModel):
    id: int
    timestamp: str | None = None
    agent_id: str | None = None
    destination: str | None = None
    content_hash: str
    action: str
    findings_count: int
    duration_ms: float
    findings: list[AuditFinding] = []
