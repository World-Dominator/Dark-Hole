"""Core cryptographic primitives and protocols.

Modules in this package intentionally provide *thin* wrappers around vetted
implementations from :pypi:`cryptography`.

The most important exported API for higher layers is the double-ratchet
implementation (:class:`~darkhole.crypto.ratchet.DoubleRatchet`) which can be
used to derive per-message keys for secure messaging.
"""

from __future__ import annotations

from .aead import AeadCiphertext, aead_decrypt, aead_encrypt
from .errors import (
    CryptoError,
    DecryptionError,
    InvalidKeyError,
    RatchetError,
)
from .hashes import blake2b_digest
from .hkdf import hkdf_blake2b
from .opaque import (
    OpaqueClient,
    OpaqueClientRegistration,
    OpaqueServer,
    OpaqueServerRegistrationRecord,
)
from .random import random_bytes
from .ratchet import (
    DoubleRatchet,
    RatchetHeader,
    RatchetMessage,
    RatchetState,
    create_session_pair,
)
from .serialization import (
    deserialize_ratchet_state,
    serialize_ratchet_state,
)
from .x25519 import (
    X25519KeyPair,
    x25519_generate_keypair,
    x25519_public_from_bytes,
    x25519_shared_secret,
)

__all__ = [
    "AeadCiphertext",
    "CryptoError",
    "DecryptionError",
    "DoubleRatchet",
    "InvalidKeyError",
    "OpaqueClient",
    "OpaqueClientRegistration",
    "OpaqueServer",
    "OpaqueServerRegistrationRecord",
    "RatchetError",
    "RatchetHeader",
    "RatchetMessage",
    "RatchetState",
    "aead_decrypt",
    "aead_encrypt",
    "blake2b_digest",
    "create_session_pair",
    "deserialize_ratchet_state",
    "hkdf_blake2b",
    "random_bytes",
    "serialize_ratchet_state",
    "x25519_generate_keypair",
    "x25519_public_from_bytes",
    "x25519_shared_secret",
    "X25519KeyPair",
]
