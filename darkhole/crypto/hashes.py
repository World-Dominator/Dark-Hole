"""Digest primitives."""

from __future__ import annotations

import hashlib


def blake2b_digest(data: bytes, *, digest_size: int = 32, key: bytes | None = None) -> bytes:
    """Compute a BLAKE2b digest.

    Args:
        data: Data to hash.
        digest_size: Output size (1..64). For KDF-like usage, 32 bytes is typical.
        key: Optional key for keyed BLAKE2b (MAC-like usage).

    Returns:
        Digest bytes.
    """

    if not (1 <= digest_size <= 64):
        raise ValueError("digest_size must be in range 1..64")

    h = hashlib.blake2b(data, digest_size=digest_size, key=key or b"")
    return h.digest()
