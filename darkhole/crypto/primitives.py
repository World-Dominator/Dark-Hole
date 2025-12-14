from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def blake2b_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def node_id_from_public_key(public_key_bytes: bytes) -> bytes:
    return hashlib.blake2b(public_key_bytes, digest_size=16).digest()


def hkdf_sha256(ikm: bytes, *, salt: bytes | None = None, info: bytes = b"") -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(ikm)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes requires equal-length inputs")
    return bytes(x ^ y for x, y in zip(a, b, strict=True))


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, *, aad: bytes = b"") -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, *, aad: bytes = b"") -> bytes:
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


@dataclass(frozen=True)
class KeyPair:
    private_key: X25519PrivateKey

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(X25519PrivateKey.generate())

    @property
    def public_key(self) -> X25519PublicKey:
        return self.private_key.public_key()

    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes_raw()

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes_raw()

    def node_id(self) -> bytes:
        return node_id_from_public_key(self.public_bytes())

    def shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        return self.private_key.exchange(peer_pub)
