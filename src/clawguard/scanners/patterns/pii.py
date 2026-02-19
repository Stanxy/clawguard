"""PII patterns with validators (SSN, credit card, email, phone, IP)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from clawguard.models.enums import Severity


@dataclass(frozen=True)
class PIIPattern:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    validator: Callable[[str], bool] | None = None


# ── Validators ────────────────────────────────────────────────────────────────

def _validate_ssn(raw: str) -> bool:
    """Reject invalid SSN area codes: 000, 666, 900-999."""
    digits = raw.replace("-", "")
    if len(digits) != 9:
        return False
    area = int(digits[:3])
    group = int(digits[3:5])
    serial = int(digits[5:])
    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0 or serial == 0:
        return False
    return True


def _luhn_check(number: str) -> bool:
    """Luhn algorithm for credit card validation."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _validate_credit_card(raw: str) -> bool:
    """Strip separators and run Luhn check."""
    cleaned = re.sub(r"[\s\-]", "", raw)
    return _luhn_check(cleaned)


# ── Patterns ──────────────────────────────────────────────────────────────────

_SSN = PIIPattern(
    name="ssn",
    pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    severity=Severity.CRITICAL,
    validator=_validate_ssn,
)

_CREDIT_CARD_VISA = PIIPattern(
    name="credit_card_visa",
    pattern=re.compile(r"\b4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
    severity=Severity.CRITICAL,
    validator=_validate_credit_card,
)

_CREDIT_CARD_MASTERCARD = PIIPattern(
    name="credit_card_mastercard",
    pattern=re.compile(r"\b5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
    severity=Severity.CRITICAL,
    validator=_validate_credit_card,
)

_CREDIT_CARD_AMEX = PIIPattern(
    name="credit_card_amex",
    pattern=re.compile(r"\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b"),
    severity=Severity.CRITICAL,
    validator=_validate_credit_card,
)

_CREDIT_CARD_DISCOVER = PIIPattern(
    name="credit_card_discover",
    pattern=re.compile(r"\b6(?:011|5\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
    severity=Severity.CRITICAL,
    validator=_validate_credit_card,
)

_EMAIL = PIIPattern(
    name="email",
    pattern=re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    severity=Severity.MEDIUM,
)

_PHONE_US = PIIPattern(
    name="phone_us",
    pattern=re.compile(
        r"(?<!\d)"
        r"(?:\+?1[\s\-.]?)?"
        r"(?:\(?\d{3}\)?[\s\-.]?)"
        r"\d{3}[\s\-.]?\d{4}"
        r"(?!\d)"
    ),
    severity=Severity.MEDIUM,
)

_PHONE_E164 = PIIPattern(
    name="phone_e164",
    pattern=re.compile(r"\+[1-9]\d{6,14}\b"),
    severity=Severity.MEDIUM,
)

_IPV4 = PIIPattern(
    name="ipv4_address",
    pattern=re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    severity=Severity.LOW,
)

_IPV6 = PIIPattern(
    name="ipv6_address",
    pattern=re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        r"|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
        r"|"
        r"\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
    ),
    severity=Severity.LOW,
)


PII_PATTERNS: list[PIIPattern] = [
    _SSN,
    _CREDIT_CARD_VISA,
    _CREDIT_CARD_MASTERCARD,
    _CREDIT_CARD_AMEX,
    _CREDIT_CARD_DISCOVER,
    _EMAIL,
    _PHONE_US,
    _PHONE_E164,
    _IPV4,
    _IPV6,
]
