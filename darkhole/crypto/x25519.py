"""X25519 key agreement utilities."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

from .errors import InvalidKeyError


@dataclass(frozen=True, slots=True)
class X25519KeyPair:
    """An X25519 key pair."""

    private: x25519.X25519PrivateKey
    public: x25519.X25519PublicKey

    def public_bytes(self) -> bytes:
        """Return the raw 32-byte public key."""

        return self.public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def private_bytes(self) -> bytes:
        """Return the raw 32-byte private key."""

        return self.private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def x25519_generate_keypair() -> X25519KeyPair:
    """Generate an X25519 key pair."""

    private = x25519.X25519PrivateKey.generate()
    return X25519KeyPair(private=private, public=private.public_key())


def x25519_public_from_bytes(data: bytes) -> x25519.X25519PublicKey:
    """Parse an X25519 public key from 32 raw bytes."""

    try:
        return x25519.X25519PublicKey.from_public_bytes(data)
    except Exception as e:  # pragma: no cover
        raise InvalidKeyError("invalid X25519 public key") from e


def x25519_private_from_bytes(data: bytes) -> x25519.X25519PrivateKey:
    """Parse an X25519 private key from 32 raw bytes."""

    try:
        return x25519.X25519PrivateKey.from_private_bytes(data)
    except Exception as e:  # pragma: no cover
        raise InvalidKeyError("invalid X25519 private key") from e


def x25519_shared_secret(
    private_key: x25519.X25519PrivateKey, public_key: x25519.X25519PublicKey
) -> bytes:
    """Compute the X25519 shared secret (32 bytes)."""

    return private_key.exchange(public_key)
