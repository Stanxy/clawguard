from __future__ import annotations

import re
from dataclasses import dataclass

from clawguard.models.enums import ScannerType, Severity
from clawguard.scanners.base import BaseScanner, Finding


@dataclass
class CustomPattern:
    name: str
    regex: str
    severity: Severity
    compiled: re.Pattern[str] | None = None

    def __post_init__(self) -> None:
        self.compiled = re.compile(self.regex)


class CustomScanner(BaseScanner):
    scanner_type = ScannerType.CUSTOM

    def __init__(self, patterns: list[CustomPattern] | None = None) -> None:
        self._patterns: list[CustomPattern] = patterns or []

    def load_patterns(self, raw_patterns: list[dict[str, str]]) -> None:
        """Load patterns from YAML-derived dicts."""
        self._patterns = []
        for raw in raw_patterns:
            self._patterns.append(CustomPattern(
                name=raw["name"],
                regex=raw["regex"],
                severity=Severity(raw.get("severity", "MEDIUM").upper()),
            ))

    def scan(self, content: str) -> list[Finding]:
        findings: list[Finding] = []

        for cp in self._patterns:
            if cp.compiled is None:
                continue
            for match in cp.compiled.finditer(content):
                findings.append(Finding(
                    scanner_type=self.scanner_type,
                    finding_type=cp.name,
                    severity=cp.severity,
                    matched_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    context=_extract_context(content, match.start(), match.end()),
                ))

        return findings


def _extract_context(content: str, start: int, end: int, window: int = 30) -> str:
    ctx_start = max(0, start - window)
    ctx_end = min(len(content), end + window)
    return content[ctx_start:ctx_end]
