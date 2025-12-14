"""OPAQUE-inspired password-authenticated key establishment (PAKE).

OPAQUE (RFC 9380) is a strong PAKE that prevents servers from learning the
client's password and provides resistance against server-side compromise.

This codebase needs an initial PAKE-like flow to bootstrap a shared secret. A
full RFC 9380 implementation is out of scope for this foundation layer, but the
APIs are modeled after OPAQUE concepts:

- Registration produces an *envelope* stored by the server.
- Authentication decrypts the envelope using the password and performs an
  authenticated key exchange.

Security note:
    The implementation below is an *OPAQUE-inspired* construction, not a drop-in
    replacement for RFC 9380, and should not be used as-is in production.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hmac, hashes

from .aead import AeadCiphertext, aead_decrypt, aead_encrypt
from .errors import DecryptionError
from .hkdf import hkdf_blake2b
from .random import random_bytes
from .x25519 import (
    X25519KeyPair,
    x25519_generate_keypair,
    x25519_public_from_bytes,
    x25519_shared_secret,
)


@dataclass(frozen=True, slots=True)
class OpaqueClientRegistration:
    """Client-to-server registration payload."""

    client_public_key: bytes
    salt: bytes
    envelope: bytes


@dataclass(frozen=True, slots=True)
class OpaqueServerRegistrationRecord:
    """Server-side registration record stored for an account."""

    client_public_key: bytes
    salt: bytes
    envelope: bytes


@dataclass(frozen=True, slots=True)
class OpaqueServerLoginResponse:
    """Server response containing the AKE parameters."""

    server_ephemeral_public_key: bytes
    salt: bytes
    envelope: bytes
    client_public_key: bytes
    server_mac: bytes


def _password_key(password: str, *, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


class OpaqueClient:
    """Client-side OPAQUE-like operations."""

    def register(self, password: str) -> tuple[OpaqueClientRegistration, X25519KeyPair]:
        """Create a registration payload and the underlying static keypair."""

        salt = random_bytes(16)
        pw_key = _password_key(password, salt=salt)
        static = x25519_generate_keypair()
        envelope_ct = aead_encrypt(pw_key, static.private_bytes(), aad=b"opaque/envelope")
        payload = OpaqueClientRegistration(
            client_public_key=static.public_bytes(),
            salt=salt,
            envelope=envelope_ct.to_bytes(),
        )
        return payload, static

    def login_start(self) -> X25519KeyPair:
        """Generate an ephemeral keypair for the login AKE."""

        return x25519_generate_keypair()

    def login_finish(
        self,
        password: str,
        *,
        client_ephemeral: X25519KeyPair,
        response: OpaqueServerLoginResponse,
        transcript_hash: bytes,
    ) -> tuple[bytes, bytes]:
        """Finish the login and return ``(session_key, client_mac)``.

        The client verifies the server MAC to ensure the server had the correct
        record and derived the same shared secret.
        """

        pw_key = _password_key(password, salt=response.salt)

        # Decrypt and recover the static private key.
        envelope = AeadCiphertext.from_bytes(response.envelope)
        try:
            static_priv_bytes = aead_decrypt(pw_key, envelope, aad=b"opaque/envelope")
        except DecryptionError as e:
            raise DecryptionError("invalid password") from e

        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        static_private_key = x25519.X25519PrivateKey.from_private_bytes(static_priv_bytes)
        static_public_key = static_private_key.public_key()
        static_public_bytes = static_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        if static_public_bytes != response.client_public_key:
            raise DecryptionError("invalid password")

        # Compute AKE secret from ephemeral DH.
        server_eph_pub = x25519_public_from_bytes(response.server_ephemeral_public_key)
        eph_dh = x25519_shared_secret(client_ephemeral.private, server_eph_pub)

        secret = hkdf_blake2b(
            eph_dh + response.client_public_key,
            info=b"darkhole/opaque/secret",
            length=32,
        )

        # Verify server MAC over transcript.
        expected_server_mac = _hmac(secret, b"server" + transcript_hash)
        if not _constant_time_eq(expected_server_mac, response.server_mac):
            raise DecryptionError("server authentication failed")

        session_key = hkdf_blake2b(secret, info=b"darkhole/opaque/session", length=32)
        client_mac = _hmac(secret, b"client" + transcript_hash)
        return session_key, client_mac


class OpaqueServer:
    """Server-side OPAQUE-like operations."""

    def register_finish(self, payload: OpaqueClientRegistration) -> OpaqueServerRegistrationRecord:
        """Turn a client registration payload into a stored record."""

        return OpaqueServerRegistrationRecord(
            client_public_key=payload.client_public_key,
            salt=payload.salt,
            envelope=payload.envelope,
        )

    def login_start(
        self,
        record: OpaqueServerRegistrationRecord,
        *,
        client_ephemeral_public_key: bytes,
        transcript_hash: bytes,
    ) -> tuple[OpaqueServerLoginResponse, X25519KeyPair, bytes]:
        """Start login and return ``(response, server_ephemeral, secret)``."""

        client_eph_pub = x25519_public_from_bytes(client_ephemeral_public_key)
        server_ephemeral = x25519_generate_keypair()
        eph_dh = x25519_shared_secret(server_ephemeral.private, client_eph_pub)

        secret = hkdf_blake2b(
            eph_dh + record.client_public_key,
            info=b"darkhole/opaque/secret",
            length=32,
        )

        server_mac = _hmac(secret, b"server" + transcript_hash)
        response = OpaqueServerLoginResponse(
            server_ephemeral_public_key=server_ephemeral.public_bytes(),
            salt=record.salt,
            envelope=record.envelope,
            client_public_key=record.client_public_key,
            server_mac=server_mac,
        )
        return response, server_ephemeral, secret

    def login_finish(self, secret: bytes, *, client_mac: bytes, transcript_hash: bytes) -> bytes:
        """Verify client MAC and return the derived session key."""

        expected_client_mac = _hmac(secret, b"client" + transcript_hash)
        if not _constant_time_eq(expected_client_mac, client_mac):
            raise DecryptionError("client authentication failed")
        return hkdf_blake2b(secret, info=b"darkhole/opaque/session", length=32)


def _hmac(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.BLAKE2b(64))
    h.update(data)
    return h.finalize()


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    out = 0
    for x, y in zip(a, b, strict=True):
        out |= x ^ y
    return out == 0
