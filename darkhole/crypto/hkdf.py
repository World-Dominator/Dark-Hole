"""HKDF wrappers.

The project uses HKDF with BLAKE2b for key derivation.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf_blake2b(
    ikm: bytes,
    *,
    salt: bytes | None = None,
    info: bytes = b"",
    length: int = 32,
    digest_size: int = 64,
) -> bytes:
    """Derive key material from ``ikm`` using HKDF(BLAKE2b).

    Args:
        ikm: Input keying material.
        salt: Optional salt; if omitted HKDF uses an all-zero salt.
        info: HKDF info/label.
        length: Output length.
        digest_size: BLAKE2b digest size. For security reasons, the default is
            the full 64 bytes.

    Returns:
        Derived bytes of size ``length``.
    """

    if length <= 0:
        raise ValueError("length must be positive")

    hkdf = HKDF(
        algorithm=hashes.BLAKE2b(digest_size=digest_size),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)
