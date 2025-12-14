"""Asymmetric double ratchet.

This module implements a pragmatic variant of the Signal double ratchet.

The primary goal for the rest of the codebase is to expose an API that can:

- Evolve symmetric sending/receiving chains.
- Perform DH ratchet steps using X25519.
- Support out-of-order delivery by storing a bounded set of skipped message keys.
- Provide post-compromise security (self-healing) after a DH ratchet.

It is intentionally *not* wire-compatible with Signal; the focus is a clean,
well-typed internal primitive.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .aead import AeadCiphertext, aead_decrypt, aead_encrypt
from .errors import DecryptionError, RatchetError
from .hkdf import hkdf_blake2b
from .kdf_chain import KDFChain
from .random import random_bytes
from .x25519 import (
    X25519KeyPair,
    x25519_generate_keypair,
    x25519_public_from_bytes,
    x25519_shared_secret,
)


def _pub_bytes(pub: x25519.X25519PublicKey) -> bytes:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _kdf_rk(root_key: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """Derive ``(new_root_key, chain_key)`` from the current root key and DH output."""

    okm = hkdf_blake2b(
        dh_out,
        salt=root_key,
        info=b"darkhole/ratchet/kdf_rk",
        length=64,
    )
    return okm[:32], okm[32:]


def _mk_to_aead_key(message_key: bytes) -> bytes:
    return hkdf_blake2b(message_key, info=b"darkhole/ratchet/aead_key", length=32)


@dataclass(frozen=True, slots=True)
class RatchetHeader:
    """Unencrypted message header.

    Args:
        dh_public_key: Raw 32-byte X25519 public key identifying the sender's
            current DH ratchet key.
        pn: Number of messages in the previous sending chain.
        n: Message number in the current sending chain.
    """

    dh_public_key: bytes
    pn: int
    n: int

    def to_bytes(self) -> bytes:
        if len(self.dh_public_key) != 32:
            raise ValueError("dh_public_key must be 32 bytes")
        if self.pn < 0 or self.n < 0:
            raise ValueError("pn and n must be non-negative")
        return self.dh_public_key + self.pn.to_bytes(4, "big") + self.n.to_bytes(4, "big")


@dataclass(frozen=True, slots=True)
class RatchetMessage:
    """A double-ratchet encrypted message."""

    header: RatchetHeader
    ciphertext: bytes

    @property
    def ciphertext_obj(self) -> AeadCiphertext:
        return AeadCiphertext.from_bytes(self.ciphertext)


SkippedKeyId = tuple[bytes, int]


@dataclass(slots=True)
class RatchetState:
    """Mutable double-ratchet state.

    Notes:
        For persistence, use :func:`darkhole.crypto.serialization.serialize_ratchet_state`.
    """

    root_key: bytes
    dh_self: X25519KeyPair
    dh_remote_public: x25519.X25519PublicKey

    ck_s: bytes | None
    ck_r: bytes | None

    ns: int = 0
    nr: int = 0
    pn: int = 0

    mk_skipped: dict[SkippedKeyId, bytes] = field(default_factory=dict)
    max_skip: int = 1000

    def dh_remote_public_bytes(self) -> bytes:
        return _pub_bytes(self.dh_remote_public)


class DoubleRatchet:
    """High-level interface for encrypting and decrypting messages."""

    def __init__(self, state: RatchetState):
        self.state = state

    def encrypt(self, plaintext: bytes, *, aad: bytes = b"") -> RatchetMessage:
        """Encrypt a message.

        Args:
            plaintext: Bytes to encrypt.
            aad: Extra associated data.

        Returns:
            :class:`RatchetMessage`.
        """

        st = self.state

        if st.ck_s is None:
            self._dh_ratchet_send()

        assert st.ck_s is not None
        chain = KDFChain(st.ck_s)
        chain, mk = chain.next()
        st.ck_s = chain.chain_key

        header = RatchetHeader(
            dh_public_key=st.dh_self.public_bytes(),
            pn=st.pn,
            n=st.ns,
        )
        st.ns += 1

        aead_key = _mk_to_aead_key(mk)
        ct = aead_encrypt(aead_key, plaintext, aad=header.to_bytes() + aad)
        return RatchetMessage(header=header, ciphertext=ct.to_bytes())

    def decrypt(self, message: RatchetMessage, *, aad: bytes = b"") -> bytes:
        """Decrypt a received message."""

        st = self.state
        header = message.header

        skipped_id = (header.dh_public_key, header.n)
        if skipped_id in st.mk_skipped:
            mk = st.mk_skipped.pop(skipped_id)
            aead_key = _mk_to_aead_key(mk)
            return aead_decrypt(aead_key, message.ciphertext_obj, aad=header.to_bytes() + aad)

        sender_dh_pub = x25519_public_from_bytes(header.dh_public_key)

        if _pub_bytes(sender_dh_pub) != _pub_bytes(st.dh_remote_public):
            self._skip_message_keys(header.pn)
            self._dh_ratchet_receive(sender_dh_pub)

        if st.ck_r is None:
            raise RatchetError("missing receiving chain")

        if header.n < st.nr:
            raise DecryptionError("message key not available")

        self._skip_message_keys(header.n)

        chain = KDFChain(st.ck_r)
        chain, mk = chain.next()
        st.ck_r = chain.chain_key
        st.nr += 1

        aead_key = _mk_to_aead_key(mk)
        return aead_decrypt(aead_key, message.ciphertext_obj, aad=header.to_bytes() + aad)

    def _skip_message_keys(self, until: int) -> None:
        st = self.state
        if st.ck_r is None:
            return

        if until - st.nr > st.max_skip:
            raise RatchetError("too many skipped message keys")

        while st.nr < until:
            chain = KDFChain(st.ck_r)
            chain, mk = chain.next()
            st.ck_r = chain.chain_key

            key_id = (_pub_bytes(st.dh_remote_public), st.nr)
            st.mk_skipped[key_id] = mk
            st.nr += 1

    def _dh_ratchet_receive(self, new_remote: x25519.X25519PublicKey) -> None:
        st = self.state

        st.pn = st.ns
        st.ns = 0
        st.nr = 0

        st.dh_remote_public = new_remote

        dh_out = x25519_shared_secret(st.dh_self.private, st.dh_remote_public)
        st.root_key, st.ck_r = _kdf_rk(st.root_key, dh_out)

        st.dh_self = x25519_generate_keypair()
        dh_out = x25519_shared_secret(st.dh_self.private, st.dh_remote_public)
        st.root_key, st.ck_s = _kdf_rk(st.root_key, dh_out)

    def _dh_ratchet_send(self) -> None:
        st = self.state

        st.pn = st.ns
        st.ns = 0

        st.dh_self = x25519_generate_keypair()
        dh_out = x25519_shared_secret(st.dh_self.private, st.dh_remote_public)
        st.root_key, st.ck_s = _kdf_rk(st.root_key, dh_out)


def create_session_pair(
    *,
    shared_secret: bytes | None = None,
    max_skip: int = 1000,
) -> tuple[DoubleRatchet, DoubleRatchet]:
    """Create an initiator/responder session pair for tests and prototyping."""

    if shared_secret is None:
        shared_secret = random_bytes(32)

    # Initial DH keys.
    alice_dh = x25519_generate_keypair()
    bob_dh = x25519_generate_keypair()

    dh_out = x25519_shared_secret(alice_dh.private, bob_dh.public)
    initial_rk = hkdf_blake2b(shared_secret, info=b"darkhole/ratchet/initial_rk", length=32)
    root_key, chain_key = _kdf_rk(initial_rk, dh_out)

    alice_state = RatchetState(
        root_key=root_key,
        dh_self=alice_dh,
        dh_remote_public=bob_dh.public,
        ck_s=chain_key,
        ck_r=None,
        max_skip=max_skip,
    )
    bob_state = RatchetState(
        root_key=root_key,
        dh_self=bob_dh,
        dh_remote_public=alice_dh.public,
        ck_s=None,
        ck_r=chain_key,
        max_skip=max_skip,
    )

    return DoubleRatchet(alice_state), DoubleRatchet(bob_state)
