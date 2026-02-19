from __future__ import annotations

import pytest

from clawguard.models.enums import Severity
from clawguard.scanners.custom_scanner import CustomPattern, CustomScanner


@pytest.fixture
def scanner():
    return CustomScanner(patterns=[
        CustomPattern(name="project_code", regex=r"PROJ-[A-Z]{2}-\d{6}", severity=Severity.HIGH),
        CustomPattern(name="internal_id", regex=r"INT-\d{8}", severity=Severity.MEDIUM),
    ])


class TestCustomPatterns:
    def test_project_code_match(self, scanner):
        findings = scanner.scan("The code is PROJ-AB-123456 for this project")
        assert len(findings) == 1
        assert findings[0].finding_type == "project_code"
        assert findings[0].severity == Severity.HIGH

    def test_internal_id_match(self, scanner):
        findings = scanner.scan("Ref: INT-12345678")
        assert len(findings) == 1
        assert findings[0].finding_type == "internal_id"

    def test_no_match(self, scanner):
        findings = scanner.scan("Nothing special here")
        assert len(findings) == 0

    def test_multiple_matches(self, scanner):
        findings = scanner.scan("PROJ-AB-123456 and INT-12345678 found")
        assert len(findings) == 2


class TestLoadPatterns:
    def test_load_from_dict(self):
        scanner = CustomScanner()
        scanner.load_patterns([
            {"name": "test_pat", "regex": r"TEST-\d+", "severity": "HIGH"},
        ])
        findings = scanner.scan("issue TEST-42 reported")
        assert len(findings) == 1
        assert findings[0].finding_type == "test_pat"

    def test_load_default_severity(self):
        scanner = CustomScanner()
        scanner.load_patterns([
            {"name": "test_pat", "regex": r"TEST-\d+"},
        ])
        findings = scanner.scan("TEST-1")
        assert findings[0].severity == Severity.MEDIUM


class TestEmptyScanner:
    def test_no_patterns(self):
        scanner = CustomScanner()
        findings = scanner.scan("anything")
        assert len(findings) == 0
