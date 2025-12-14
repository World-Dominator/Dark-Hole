"""Secure randomness utilities."""

from __future__ import annotations

import os


def random_bytes(length: int) -> bytes:
    """Return ``length`` cryptographically secure random bytes."""

    if length < 0:
        raise ValueError("length must be non-negative")
    return os.urandom(length)
