from __future__ import annotations

from clawguard.models.enums import ScannerType
from clawguard.scanners.base import BaseScanner, Finding
from clawguard.scanners.custom_scanner import CustomScanner
from clawguard.scanners.pii_scanner import PIIScanner
from clawguard.scanners.secret_scanner import SecretScanner


class ScannerRegistry:
    """Discovers, holds, and runs all registered scanners."""

    def __init__(self) -> None:
        self._scanners: dict[ScannerType, BaseScanner] = {}

    def register(self, scanner: BaseScanner) -> None:
        self._scanners[scanner.scanner_type] = scanner

    def get(self, scanner_type: ScannerType) -> BaseScanner | None:
        return self._scanners.get(scanner_type)

    @property
    def scanner_types(self) -> list[ScannerType]:
        return list(self._scanners.keys())

    def scan_all(self, content: str, only: list[ScannerType] | None = None) -> list[Finding]:
        """Run all (or selected) scanners and return aggregated findings."""
        findings: list[Finding] = []
        for stype, scanner in self._scanners.items():
            if only is not None and stype not in only:
                continue
            findings.extend(scanner.scan(content))
        return findings


def create_default_registry() -> ScannerRegistry:
    """Create a registry pre-loaded with all built-in scanners."""
    registry = ScannerRegistry()
    registry.register(SecretScanner())
    registry.register(PIIScanner())
    registry.register(CustomScanner())
    return registry
