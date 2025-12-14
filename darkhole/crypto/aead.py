"""ChaCha20-Poly1305 AEAD wrapper."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .errors import DecryptionError
from .random import random_bytes


@dataclass(frozen=True, slots=True)
class AeadCiphertext:
    """A serialized ChaCha20-Poly1305 ciphertext."""

    nonce: bytes
    data: bytes

    def to_bytes(self) -> bytes:
        """Serialize as ``nonce || data``."""

        return self.nonce + self.data

    @classmethod
    def from_bytes(cls, blob: bytes) -> "AeadCiphertext":
        """Parse a serialized ciphertext produced by :meth:`to_bytes`."""

        if len(blob) < 12:
            raise ValueError("ciphertext too short")
        return cls(nonce=blob[:12], data=blob[12:])


def aead_encrypt(key: bytes, plaintext: bytes, *, aad: bytes = b"", nonce: bytes | None = None) -> AeadCiphertext:
    """Encrypt using ChaCha20-Poly1305.

    Args:
        key: 32-byte key.
        plaintext: Plaintext.
        aad: Additional authenticated data.
        nonce: 12-byte nonce. If omitted, a random nonce is generated.

    Returns:
        :class:`AeadCiphertext`.
    """

    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")

    if nonce is None:
        nonce = random_bytes(12)
    if len(nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be 12 bytes")

    aead = ChaCha20Poly1305(key)
    ct = aead.encrypt(nonce, plaintext, aad)
    return AeadCiphertext(nonce=nonce, data=ct)


def aead_decrypt(key: bytes, ciphertext: AeadCiphertext, *, aad: bytes = b"") -> bytes:
    """Decrypt and authenticate using ChaCha20-Poly1305."""

    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 key must be 32 bytes")
    if len(ciphertext.nonce) != 12:
        raise ValueError("ChaCha20-Poly1305 nonce must be 12 bytes")

    aead = ChaCha20Poly1305(key)
    try:
        return aead.decrypt(ciphertext.nonce, ciphertext.data, aad)
    except Exception as e:
        raise DecryptionError("ciphertext authentication failed") from e
