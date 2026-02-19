from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from clawguard.models.enums import ScannerType, Severity


@dataclass
class Finding:
    scanner_type: ScannerType
    finding_type: str
    severity: Severity
    matched_text: str
    start: int
    end: int
    context: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


class BaseScanner(ABC):
    scanner_type: ScannerType

    @abstractmethod
    def scan(self, content: str) -> list[Finding]:
        """Scan content and return a list of findings."""
        ...
