from __future__ import annotations

from clawguard.models.enums import RedactStrategy
from clawguard.models.policy import RedactionConfig
from clawguard.scanners.base import Finding
from clawguard.utils.hashing import sha256_short


class Redactor:
    """Applies redaction strategies to content based on findings."""

    def __init__(self, config: RedactionConfig | None = None) -> None:
        self._config = config or RedactionConfig()

    @property
    def config(self) -> RedactionConfig:
        return self._config

    def redact(self, content: str, findings: list[Finding]) -> str:
        """Replace matched spans in content using the configured strategy.

        Processes findings from end to start to preserve offset accuracy.
        """
        if not findings:
            return content

        # Sort by start position descending so replacements don't shift offsets
        sorted_findings = sorted(findings, key=lambda f: f.start, reverse=True)

        result = content
        for finding in sorted_findings:
            replacement = self._redact_value(finding.matched_text)
            result = result[:finding.start] + replacement + result[finding.end:]

        return result

    def _redact_value(self, text: str) -> str:
        strategy = self._config.strategy

        if strategy == RedactStrategy.REMOVE:
            return "[REDACTED]"

        if strategy == RedactStrategy.HASH:
            return f"[REDACTED:sha256:{sha256_short(text)}]"

        # Default: mask
        return self._mask(text)

    def _mask(self, text: str) -> str:
        preserve = self._config.mask_preserve_edges
        char = self._config.mask_char

        if len(text) <= preserve * 2:
            return char * len(text)

        masked_len = len(text) - preserve * 2
        return text[:preserve] + (char * masked_len) + text[-preserve:]
