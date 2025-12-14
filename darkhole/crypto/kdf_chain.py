"""HKDF-based key derivation chains.

Double-ratchet style protocols evolve symmetric keys by repeatedly applying a
KDF to a chain key to derive message keys.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hkdf import hkdf_blake2b


@dataclass(frozen=True, slots=True)
class KDFChain:
    """A symmetric-key KDF chain."""

    chain_key: bytes

    def next(self) -> tuple["KDFChain", bytes]:
        """Advance the chain and return ``(next_chain, message_key)``."""

        next_ck = hkdf_blake2b(self.chain_key, info=b"darkhole/chain/ck", length=32)
        mk = hkdf_blake2b(self.chain_key, info=b"darkhole/chain/mk", length=32)
        return KDFChain(next_ck), mk
