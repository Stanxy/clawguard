from __future__ import annotations

import pytest

from clawguard.engine.redactor import Redactor
from clawguard.models.enums import RedactStrategy, ScannerType, Severity
from clawguard.models.policy import RedactionConfig
from clawguard.scanners.base import Finding


def _make_finding(text: str, start: int, end: int) -> Finding:
    return Finding(
        scanner_type=ScannerType.SECRET,
        finding_type="test",
        severity=Severity.HIGH,
        matched_text=text,
        start=start,
        end=end,
    )


class TestMaskStrategy:
    def test_mask_default(self):
        redactor = Redactor(RedactionConfig(strategy=RedactStrategy.MASK, mask_preserve_edges=4))
        content = "key = AKIAIOSFODNN7EXAMPLE"
        finding = _make_finding("AKIAIOSFODNN7EXAMPLE", 6, 26)
        result = redactor.redact(content, [finding])
        assert result.startswith("key = AKIA")
        assert result.endswith("MPLE")
        assert "*" in result

    def test_mask_short_string(self):
        redactor = Redactor(RedactionConfig(strategy=RedactStrategy.MASK, mask_preserve_edges=4))
        content = "x = ab"
        finding = _make_finding("ab", 4, 6)
        result = redactor.redact(content, [finding])
        assert result == "x = **"


class TestHashStrategy:
    def test_hash_replacement(self):
        redactor = Redactor(RedactionConfig(strategy=RedactStrategy.HASH))
        content = "secret_here"
        finding = _make_finding("secret_here", 0, 11)
        result = redactor.redact(content, [finding])
        assert result.startswith("[REDACTED:sha256:")
        assert result.endswith("]")


class TestRemoveStrategy:
    def test_remove_replacement(self):
        redactor = Redactor(RedactionConfig(strategy=RedactStrategy.REMOVE))
        content = "key = mysecret rest"
        finding = _make_finding("mysecret", 6, 14)
        result = redactor.redact(content, [finding])
        assert result == "key = [REDACTED] rest"


class TestMultipleFindings:
    def test_multiple_redactions(self):
        redactor = Redactor(RedactionConfig(strategy=RedactStrategy.REMOVE))
        content = "aaa SECRET1 bbb SECRET2 ccc"
        findings = [
            _make_finding("SECRET1", 4, 11),
            _make_finding("SECRET2", 16, 23),
        ]
        result = redactor.redact(content, findings)
        assert "SECRET1" not in result
        assert "SECRET2" not in result
        assert "[REDACTED]" in result


class TestNoFindings:
    def test_no_changes(self):
        redactor = Redactor()
        assert redactor.redact("hello world", []) == "hello world"
