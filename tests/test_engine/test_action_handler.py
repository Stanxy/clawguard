from __future__ import annotations

import pytest

from clawguard.engine.action_handler import ActionHandler
from clawguard.engine.redactor import Redactor
from clawguard.models.enums import Action, ScannerType, Severity
from clawguard.models.policy import RedactionConfig
from clawguard.scanners.base import Finding


@pytest.fixture
def handler():
    return ActionHandler(Redactor())


def _make_finding(start: int = 0, end: int = 6) -> Finding:
    return Finding(
        scanner_type=ScannerType.SECRET,
        finding_type="test",
        severity=Severity.HIGH,
        matched_text="secret",
        start=start,
        end=end,
    )


class TestActionHandler:
    def test_allow_passes_content(self, handler):
        result = handler.handle(Action.ALLOW, "my secret text", [_make_finding()])
        assert result.action == Action.ALLOW
        assert result.content == "my secret text"
        assert result.findings_count == 1

    def test_block_returns_null_content(self, handler):
        result = handler.handle(Action.BLOCK, "my secret text", [_make_finding()])
        assert result.action == Action.BLOCK
        assert result.content is None
        assert result.findings_count == 1

    def test_redact_modifies_content(self, handler):
        content = "key = secret_value_here"
        finding = Finding(
            scanner_type=ScannerType.SECRET,
            finding_type="test",
            severity=Severity.HIGH,
            matched_text="secret_value_here",
            start=6,
            end=23,
        )
        result = handler.handle(Action.REDACT, content, [finding])
        assert result.action == Action.REDACT
        assert "secret_value_here" not in result.content
        assert result.findings_count == 1
