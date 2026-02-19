from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.

    Returns bits of entropy per character. High-entropy strings (> 4.5)
    are likely random/secret material.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def is_high_entropy(data: str, threshold: float = 4.5, min_length: int = 20) -> bool:
    """Check if a string has suspiciously high entropy."""
    if len(data) < min_length:
        return False
    return shannon_entropy(data) > threshold
