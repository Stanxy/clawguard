"""Pydantic models for the dashboard API endpoints."""
from __future__ import annotations

from pydantic import BaseModel

from clawguard.models.audit import AuditEntry


class ActionCount(BaseModel):
    action: str
    count: int


class SeverityCount(BaseModel):
    severity: str
    count: int


class TopFindingType(BaseModel):
    finding_type: str
    count: int


class DashboardStats(BaseModel):
    total_scans: int = 0
    action_counts: list[ActionCount] = []
    severity_counts: list[SeverityCount] = []
    top_finding_types: list[TopFindingType] = []
    recent_scans: list[AuditEntry] = []


class PatternCatalogEntry(BaseModel):
    name: str
    severity: str
    default_severity: str = ""
    category: str
    description: str
    regex: str = ""


class PatternCatalog(BaseModel):
    secrets: list[PatternCatalogEntry] = []
    pii: list[PatternCatalogEntry] = []
    custom: list[PatternCatalogEntry] = []
