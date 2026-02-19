from __future__ import annotations

from enum import Enum


class Action(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScannerType(str, Enum):
    SECRET = "SECRET"
    PII = "PII"
    CUSTOM = "CUSTOM"


class RedactStrategy(str, Enum):
    MASK = "mask"
    HASH = "hash"
    REMOVE = "remove"
