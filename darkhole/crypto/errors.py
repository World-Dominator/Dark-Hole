"""Shared exceptions for :mod:`darkhole.crypto`.

The library generally raises a small set of domain-specific exceptions to avoid
leaking backend-specific implementation details.
"""

from __future__ import annotations


class CryptoError(Exception):
    """Base error for cryptographic operations."""


class InvalidKeyError(CryptoError):
    """Raised when key material is malformed or otherwise invalid."""


class DecryptionError(CryptoError):
    """Raised when ciphertext authentication fails or decryption is impossible."""


class RatchetError(CryptoError):
    """Raised for double ratchet protocol state errors."""
