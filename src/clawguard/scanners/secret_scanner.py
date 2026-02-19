from __future__ import annotations

import re

from clawguard.models.enums import ScannerType, Severity
from clawguard.scanners.base import BaseScanner, Finding
from clawguard.scanners.patterns.secrets import SECRET_PATTERNS
from clawguard.utils.entropy import is_high_entropy


class SecretScanner(BaseScanner):
    scanner_type = ScannerType.SECRET

    def __init__(self, entropy_threshold: float = 4.5, entropy_min_length: int = 20) -> None:
        self._entropy_threshold = entropy_threshold
        self._entropy_min_length = entropy_min_length
        self.disabled_patterns: set[str] = set()

    def scan(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        seen_spans: set[tuple[int, int]] = set()

        # Pattern-based detection
        for sp in SECRET_PATTERNS:
            if sp.name in self.disabled_patterns:
                continue
            for match in sp.pattern.finditer(content):
                span = (match.start(), match.end())
                if span in seen_spans:
                    continue
                seen_spans.add(span)
                findings.append(Finding(
                    scanner_type=self.scanner_type,
                    finding_type=sp.name,
                    severity=sp.severity,
                    matched_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    context=_extract_context(content, match.start(), match.end()),
                    metadata={"category": sp.category},
                ))

        # Entropy-based detection for unmatched high-entropy tokens
        for match in re.finditer(r"[A-Za-z0-9+/=_\-]{20,}", content):
            span = (match.start(), match.end())
            # Skip if already caught by a pattern
            if any(s[0] <= span[0] and s[1] >= span[1] for s in seen_spans):
                continue
            token = match.group(0)
            if is_high_entropy(token, self._entropy_threshold, self._entropy_min_length):
                findings.append(Finding(
                    scanner_type=self.scanner_type,
                    finding_type="high_entropy_string",
                    severity=Severity.MEDIUM,
                    matched_text=token,
                    start=match.start(),
                    end=match.end(),
                    context=_extract_context(content, match.start(), match.end()),
                    metadata={"category": "entropy"},
                ))

        return findings


def _extract_context(content: str, start: int, end: int, window: int = 30) -> str:
    ctx_start = max(0, start - window)
    ctx_end = min(len(content), end + window)
    return content[ctx_start:ctx_end]
