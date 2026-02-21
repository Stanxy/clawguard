from __future__ import annotations

from clawguard.models.enums import ScannerType, Severity
from clawguard.scanners.base import BaseScanner, Finding
from clawguard.scanners.patterns.pii import PII_PATTERNS


class PIIScanner(BaseScanner):
    scanner_type = ScannerType.PII

    def __init__(self) -> None:
        self.disabled_patterns: set[str] = set()
        self.severity_overrides: dict[str, Severity] = {}

    def scan(self, content: str) -> list[Finding]:
        findings: list[Finding] = []

        for pp in PII_PATTERNS:
            if pp.name in self.disabled_patterns:
                continue
            for match in pp.pattern.finditer(content):
                matched_text = match.group(0)

                # Run validator if defined (e.g. Luhn, SSN area-code check)
                if pp.validator is not None and not pp.validator(matched_text):
                    continue

                effective_severity = self.severity_overrides.get(pp.name, pp.severity)
                findings.append(Finding(
                    scanner_type=self.scanner_type,
                    finding_type=pp.name,
                    severity=effective_severity,
                    matched_text=matched_text,
                    start=match.start(),
                    end=match.end(),
                    context=_extract_context(content, match.start(), match.end()),
                ))

        return findings


def _extract_context(content: str, start: int, end: int, window: int = 30) -> str:
    ctx_start = max(0, start - window)
    ctx_end = min(len(content), end + window)
    return content[ctx_start:ctx_end]
