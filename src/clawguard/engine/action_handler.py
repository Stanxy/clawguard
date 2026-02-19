from __future__ import annotations

from dataclasses import dataclass

from clawguard.models.enums import Action
from clawguard.engine.redactor import Redactor
from clawguard.scanners.base import Finding


@dataclass
class ActionResult:
    action: Action
    content: str | None
    findings_count: int


class ActionHandler:
    """Dispatches ALLOW/BLOCK/REDACT based on the policy decision."""

    def __init__(self, redactor: Redactor) -> None:
        self._redactor = redactor

    def handle(self, action: Action, content: str, findings: list[Finding]) -> ActionResult:
        if action == Action.ALLOW:
            return ActionResult(
                action=Action.ALLOW,
                content=content,
                findings_count=len(findings),
            )

        if action == Action.BLOCK:
            return ActionResult(
                action=Action.BLOCK,
                content=None,
                findings_count=len(findings),
            )

        # REDACT
        redacted = self._redactor.redact(content, findings)
        return ActionResult(
            action=Action.REDACT,
            content=redacted,
            findings_count=len(findings),
        )
