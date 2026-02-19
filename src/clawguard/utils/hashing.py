from __future__ import annotations

import hashlib


def sha256_hash(content: str) -> str:
    """Return hex SHA-256 digest of content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def sha256_short(content: str, length: int = 8) -> str:
    """Return truncated SHA-256 for display (e.g. redaction placeholders)."""
    return sha256_hash(content)[:length]
