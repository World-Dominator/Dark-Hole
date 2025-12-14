from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass
from hashlib import blake2b, sha256
from typing import Final, Optional, Union

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from darkhole.crypto.reputation import ReputationHooks


MAGIC: Final[bytes] = b"SPX1"
VERSION: Final[int] = 1

RELAY_ID_LEN: Final[int] = 32
CONTEXT_LEN: Final[int] = 16

ROUTING_PLAINTEXT_LEN: Final[int] = 64
ROUTING_ENTRY_LEN: Final[int] = ROUTING_PLAINTEXT_LEN + 16  # AEAD tag

FLAG_FINAL: Final[int] = 1


class SphinxPacketError(ValueError):
    pass


class SphinxTamperError(SphinxPacketError):
    pass


class SphinxPowError(SphinxPacketError):
    pass


@dataclass(frozen=True, slots=True)
class HopDescriptor:
    relay_id: bytes
    public_key: X25519PublicKey
    pow_difficulty: int = 8

    def __post_init__(self) -> None:
        if len(self.relay_id) != RELAY_ID_LEN:
            raise ValueError("relay_id must be 32 bytes")
        if not (0 <= self.pow_difficulty <= 255):
            raise ValueError("pow_difficulty must fit in a byte")


@dataclass(frozen=True, slots=True)
class SphinxPacket:
    """A layered packet for relay traversal.

    This is a pragmatic (test-focused) onion packet format.

    - Each hop has a sender-generated ephemeral X25519 public key.
    - Each hop has an encrypted routing entry (next hop + PoW params).
    - The payload is onion-encrypted (outermost hop first).

    Forwarding drops the first hop key + routing entry and replaces payload with
    its peeled inner ciphertext.
    """

    version: int
    context: bytes
    hop_pubkeys: tuple[bytes, ...]
    routing_entries: tuple[bytes, ...]
    payload: bytes

    def __post_init__(self) -> None:
        if self.version != VERSION:
            raise ValueError("unsupported packet version")
        if len(self.context) != CONTEXT_LEN:
            raise ValueError("context must be 16 bytes")
        if len(self.hop_pubkeys) != len(self.routing_entries):
            raise ValueError("hop_pubkeys and routing_entries length mismatch")
        for pk in self.hop_pubkeys:
            if len(pk) != 32:
                raise ValueError("hop public keys must be 32 bytes")
        for re_ in self.routing_entries:
            if len(re_) != ROUTING_ENTRY_LEN:
                raise ValueError("routing entries must be 80 bytes")

    @property
    def hop_count(self) -> int:
        return len(self.hop_pubkeys)

    def to_bytes(self) -> bytes:
        hop_count = self.hop_count
        header = (
            MAGIC
            + struct.pack("!BB", self.version, len(self.context))
            + self.context
            + struct.pack("!H", hop_count)
            + struct.pack("!I", len(self.payload))
        )
        return header + b"".join(self.hop_pubkeys) + b"".join(self.routing_entries) + self.payload

    @classmethod
    def from_bytes(cls, blob: bytes) -> "SphinxPacket":
        if len(blob) < 4 + 1 + 1 + CONTEXT_LEN + 2 + 4:
            raise SphinxPacketError("packet too short")
        if blob[:4] != MAGIC:
            raise SphinxPacketError("bad magic")
        version, ctx_len = struct.unpack("!BB", blob[4:6])
        if version != VERSION:
            raise SphinxPacketError("unsupported version")
        if ctx_len != CONTEXT_LEN:
            raise SphinxPacketError("unsupported context length")
        offset = 6
        context = blob[offset : offset + ctx_len]
        offset += ctx_len
        (hop_count,) = struct.unpack("!H", blob[offset : offset + 2])
        offset += 2
        (payload_len,) = struct.unpack("!I", blob[offset : offset + 4])
        offset += 4

        need = offset + hop_count * 32 + hop_count * ROUTING_ENTRY_LEN + payload_len
        if len(blob) < need:
            raise SphinxPacketError("packet truncated")

        hop_pubkeys = tuple(blob[offset + i * 32 : offset + (i + 1) * 32] for i in range(hop_count))
        offset += hop_count * 32
        routing_entries = tuple(
            blob[offset + i * ROUTING_ENTRY_LEN : offset + (i + 1) * ROUTING_ENTRY_LEN]
            for i in range(hop_count)
        )
        offset += hop_count * ROUTING_ENTRY_LEN
        payload = blob[offset : offset + payload_len]

        return cls(
            version=version,
            context=context,
            hop_pubkeys=hop_pubkeys,
            routing_entries=routing_entries,
            payload=payload,
        )


def relay_id_from_public_key(public_key: X25519PublicKey) -> bytes:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return blake2b(b"darkhole-relay-id" + raw, digest_size=RELAY_ID_LEN).digest()


def _hkdf_extract_expand(ikm: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 (extract+expand) with a tiny implementation.

    Avoids requiring additional cryptography primitives beyond X25519 + AEAD.
    """

    if length <= 0:
        return b""

    prk = _hmac_sha256(salt, ikm)
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = _hmac_sha256(prk, t + info + bytes([counter]))
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    block = 64
    if len(key) > block:
        key = sha256(key).digest()
    key = key.ljust(block, b"\x00")
    o_key_pad = bytes((b ^ 0x5C) for b in key)
    i_key_pad = bytes((b ^ 0x36) for b in key)
    return sha256(o_key_pad + sha256(i_key_pad + data).digest()).digest()


def _derive_hop_keys(shared_secret: bytes) -> tuple[bytes, bytes]:
    okm = _hkdf_extract_expand(
        shared_secret,
        salt=b"darkhole-sphinx-v1",
        info=b"hop-keys",
        length=64,
    )
    return okm[:32], okm[32:64]


def _routing_nonce(eph_pub: bytes) -> bytes:
    return blake2b(b"darkhole-sphinx-routing" + eph_pub, digest_size=12).digest()


def _payload_nonce(eph_pub: bytes) -> bytes:
    return blake2b(b"darkhole-sphinx-payload" + eph_pub, digest_size=12).digest()


def _leading_zero_bits(digest: bytes) -> int:
    zeros = 0
    for b in digest:
        if b == 0:
            zeros += 8
            continue
        zeros += (8 - b.bit_length())
        break
    return zeros


def _verify_pow(pow_data: bytes, *, difficulty_bits: int, nonce: bytes) -> bool:
    if difficulty_bits <= 0:
        return True
    digest = blake2b(pow_data + nonce, digest_size=32).digest()
    return _leading_zero_bits(digest) >= difficulty_bits


def _find_pow_nonce(pow_data: bytes, *, difficulty_bits: int, max_tries: int = 1_000_000) -> bytes:
    if difficulty_bits <= 0:
        return b"\x00" * 8
    for i in range(max_tries):
        nonce = struct.pack("!Q", i)
        if _verify_pow(pow_data, difficulty_bits=difficulty_bits, nonce=nonce):
            return nonce
    raise SphinxPowError("unable to satisfy PoW difficulty")


def _pack_routing_instruction(
    *,
    next_relay_id: bytes,
    flags: int,
    pow_difficulty: int,
    pow_nonce: bytes,
) -> bytes:
    if len(next_relay_id) != RELAY_ID_LEN:
        raise ValueError("next_relay_id must be 32 bytes")
    if len(pow_nonce) != 8:
        raise ValueError("pow_nonce must be 8 bytes")
    if not (0 <= flags <= 255):
        raise ValueError("flags must fit in a byte")
    if not (0 <= pow_difficulty <= 255):
        raise ValueError("pow_difficulty must fit in a byte")
    return struct.pack("!32sBB8s22s", next_relay_id, flags, pow_difficulty, pow_nonce, b"\x00" * 22)


def _unpack_routing_instruction(blob: bytes) -> tuple[bytes, int, int, bytes]:
    if len(blob) != ROUTING_PLAINTEXT_LEN:
        raise SphinxPacketError("routing instruction wrong size")
    next_relay_id, flags, pow_difficulty, pow_nonce, _ = struct.unpack("!32sBB8s22s", blob)
    return next_relay_id, flags, pow_difficulty, pow_nonce


def build_packet(
    path: list[HopDescriptor],
    payload: bytes,
    *,
    max_hops: Optional[int] = None,
    context: Optional[bytes] = None,
    sender_key: Optional[bytes] = None,
    treekem_context: Optional[bytes] = None,
) -> SphinxPacket:
    """Build an N-hop Sphinx-like onion packet.

    `context` is a public 16-byte value mixed into AEAD associated data for every
    hop. Callers can use it to bind packets to a group sender key / TreeKEM
    exporter output.
    """

    if not path:
        raise ValueError("path must be non-empty")

    if max_hops is None:
        max_hops = len(path)
    if max_hops < len(path):
        raise ValueError("max_hops must be >= len(path)")

    if context is None:
        ctx_material = (sender_key or b"") + (treekem_context or b"")
        context = blake2b(b"darkhole-sphinx-context" + ctx_material, digest_size=CONTEXT_LEN).digest()
    if len(context) != CONTEXT_LEN:
        raise ValueError("context must be 16 bytes")

    # Pre-generate sender ephemeral keys (one per hop) so relays can derive hop
    # keys without requiring group-wide blinding machinery.
    eph_privs: list[Optional[X25519PrivateKey]] = [None] * max_hops
    eph_pubs: list[bytes] = [b""] * max_hops
    for i in range(max_hops):
        if i < len(path):
            priv = X25519PrivateKey.generate()
            pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            eph_privs[i] = priv
            eph_pubs[i] = pub
        else:
            eph_pubs[i] = secrets.token_bytes(32)

    routing_entries: list[bytes] = [secrets.token_bytes(ROUTING_ENTRY_LEN) for _ in range(max_hops)]

    layered_payload = payload

    # Build from last real hop towards the first.
    for i in range(len(path) - 1, -1, -1):
        hop = path[i]
        eph_priv = eph_privs[i]
        if eph_priv is None:
            raise RuntimeError("missing ephemeral key")
        eph_pub = eph_pubs[i]

        shared = eph_priv.exchange(hop.public_key)
        routing_key, payload_key = _derive_hop_keys(shared)

        next_relay_id = path[i + 1].relay_id if i + 1 < len(path) else (b"\x00" * RELAY_ID_LEN)
        flags = FLAG_FINAL if i == len(path) - 1 else 0

        inner_hash = blake2b(layered_payload, digest_size=32).digest()
        pow_data = b"pow" + hop.relay_id + eph_pub + inner_hash
        pow_nonce = _find_pow_nonce(pow_data, difficulty_bits=hop.pow_difficulty)

        instruction = _pack_routing_instruction(
            next_relay_id=next_relay_id,
            flags=flags,
            pow_difficulty=hop.pow_difficulty,
            pow_nonce=pow_nonce,
        )

        aead_routing = ChaCha20Poly1305(routing_key)
        routing_entry = aead_routing.encrypt(
            _routing_nonce(eph_pub),
            instruction,
            b"darkhole-sphinx-routing" + bytes([VERSION]) + context + hop.relay_id,
        )
        if len(routing_entry) != ROUTING_ENTRY_LEN:
            raise RuntimeError("unexpected routing entry size")
        routing_entries[i] = routing_entry

        aead_payload = ChaCha20Poly1305(payload_key)
        layered_payload = aead_payload.encrypt(
            _payload_nonce(eph_pub),
            layered_payload,
            b"darkhole-sphinx-payload" + bytes([VERSION]) + context + routing_entry,
        )

    return SphinxPacket(
        version=VERSION,
        context=context,
        hop_pubkeys=tuple(eph_pubs),
        routing_entries=tuple(routing_entries),
        payload=layered_payload,
    )


@dataclass(frozen=True, slots=True)
class ForwardResult:
    next_relay_id: bytes
    packet: SphinxPacket


@dataclass(frozen=True, slots=True)
class DeliverResult:
    payload: bytes


ProcessResult = Union[ForwardResult, DeliverResult]


def process_packet(
    packet: SphinxPacket,
    *,
    relay_private_key: X25519PrivateKey,
    relay_id: bytes,
    reputation: Optional[ReputationHooks] = None,
) -> ProcessResult:
    """Peel a single layer of a Sphinx packet at a relay."""

    if len(relay_id) != RELAY_ID_LEN:
        raise ValueError("relay_id must be 32 bytes")
    if packet.hop_count == 0:
        raise SphinxPacketError("packet has no hops")

    eph_pub_bytes = packet.hop_pubkeys[0]
    routing_entry = packet.routing_entries[0]

    try:
        eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    except Exception as e:  # pragma: no cover
        raise SphinxPacketError("invalid hop public key") from e

    try:
        shared = relay_private_key.exchange(eph_pub)
        routing_key, payload_key = _derive_hop_keys(shared)

        aead_routing = ChaCha20Poly1305(routing_key)
        instruction = aead_routing.decrypt(
            _routing_nonce(eph_pub_bytes),
            routing_entry,
            b"darkhole-sphinx-routing" + bytes([packet.version]) + packet.context + relay_id,
        )

        next_relay_id, flags, pow_difficulty, pow_nonce = _unpack_routing_instruction(instruction)

        aead_payload = ChaCha20Poly1305(payload_key)
        inner_payload = aead_payload.decrypt(
            _payload_nonce(eph_pub_bytes),
            packet.payload,
            b"darkhole-sphinx-payload" + bytes([packet.version]) + packet.context + routing_entry,
        )

    except Exception as e:
        if reputation is not None:
            reputation.on_packet_tamper(relay_id)
        raise SphinxTamperError("packet failed integrity checks") from e

    pow_data = b"pow" + relay_id + eph_pub_bytes + blake2b(inner_payload, digest_size=32).digest()
    if not _verify_pow(pow_data, difficulty_bits=pow_difficulty, nonce=pow_nonce):
        if reputation is not None:
            reputation.on_pow_invalid(relay_id)
        raise SphinxPowError("invalid proof-of-work")
    if reputation is not None:
        reputation.on_pow_valid(relay_id)

    is_final = bool(flags & FLAG_FINAL)

    if is_final:
        if reputation is not None:
            reputation.on_packet_delivered(relay_id)
        return DeliverResult(payload=inner_payload)

    if reputation is not None:
        reputation.on_packet_forwarded(relay_id, next_relay_id)

    next_packet = SphinxPacket(
        version=packet.version,
        context=packet.context,
        hop_pubkeys=packet.hop_pubkeys[1:],
        routing_entries=packet.routing_entries[1:],
        payload=inner_payload,
    )
    return ForwardResult(next_relay_id=next_relay_id, packet=next_packet)
