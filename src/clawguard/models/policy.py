from __future__ import annotations

from pydantic import BaseModel

from clawguard.models.enums import Action, RedactStrategy, Severity


class SeverityOverride(BaseModel):
    severity: Severity
    action: Action


class DestinationRule(BaseModel):
    pattern: str
    action: Action
    scanners: list[str] | None = None


class AgentRule(BaseModel):
    agent_id: str
    action: Action | None = None
    allowed_destinations: list[str] | None = None
    blocked_destinations: list[str] | None = None


class RedactionConfig(BaseModel):
    strategy: RedactStrategy = RedactStrategy.MASK
    mask_char: str = "*"
    mask_preserve_edges: int = 4


class PolicyConfig(BaseModel):
    default_action: Action = Action.BLOCK
    redaction: RedactionConfig = RedactionConfig()
    severity_overrides: list[SeverityOverride] = []
    destination_allowlist: list[str] = []
    destination_blocklist: list[str] = []
    destination_rules: list[DestinationRule] = []
    agent_rules: list[AgentRule] = []
    custom_patterns: list[dict[str, str]] = []
    disabled_patterns: list[str] = []
