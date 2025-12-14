from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass
from hashlib import blake2b
from typing import Final


FNT_MAGIC: Final[bytes] = b"FNT1"


class PacketLayerError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FountainParams:
    shard_size: int = 64
    parity_shards: int = 1


def _frame(message: bytes) -> bytes:
    return struct.pack("!I", len(message)) + message


def _unframe(framed: bytes) -> bytes:
    if len(framed) < 4:
        raise PacketLayerError("framed payload too short")
    (n,) = struct.unpack("!I", framed[:4])
    if n > len(framed) - 4:
        raise PacketLayerError("invalid frame length")
    return framed[4 : 4 + n]


def pad_to(data: bytes, size: int) -> bytes:
    if len(data) > size:
        raise PacketLayerError("data larger than target size")
    return data + secrets.token_bytes(size - len(data))


def build_padded_payload(message: bytes, *, payload_size: int) -> bytes:
    """Length-frame and pad a message to a fixed payload size."""

    return pad_to(_frame(message), payload_size)


def parse_padded_payload(payload: bytes) -> bytes:
    return _unframe(payload)


def build_fountain_payload(
    message: bytes,
    *,
    payload_size: int,
    params: FountainParams = FountainParams(),
) -> bytes:
    """Build a fixed-size payload containing a tiny (systematic) fountain wrapper.

    This is intentionally simple: the payload contains N data shards and a small
    number of parity shards (XOR across all data shards). This is enough for unit
    tests and provides a stable integration point for a richer FEC layer.
    """

    if params.shard_size <= 0:
        raise PacketLayerError("shard_size must be > 0")
    if params.parity_shards < 0:
        raise PacketLayerError("parity_shards must be >= 0")

    header_size = 4 + 2 + 2 + 2 + 4 + 16
    if payload_size <= header_size:
        raise PacketLayerError("payload_size too small")

    total_shards = (payload_size - header_size) // params.shard_size
    if total_shards <= 0:
        raise PacketLayerError("payload_size too small for shard_size")

    data_shards = total_shards - params.parity_shards
    if data_shards <= 0:
        raise PacketLayerError("not enough room for data shards")

    framed = _frame(message)
    data_capacity = data_shards * params.shard_size
    if len(framed) > data_capacity:
        raise PacketLayerError("message too large for payload/fountain params")

    data = pad_to(framed, data_capacity)
    shards = [data[i : i + params.shard_size] for i in range(0, len(data), params.shard_size)]

    parity = []
    if params.parity_shards:
        accum = bytearray(params.shard_size)
        for shard in shards:
            for i, b in enumerate(shard):
                accum[i] ^= b
        parity.append(bytes(accum))
        for _ in range(params.parity_shards - 1):
            parity.append(secrets.token_bytes(params.shard_size))

    digest = blake2b(data, digest_size=16).digest()

    header = (
        FNT_MAGIC
        + struct.pack("!HHHI", params.shard_size, data_shards, params.parity_shards, len(message))
        + digest
    )
    out = header + b"".join(shards) + b"".join(parity)
    return pad_to(out, payload_size)


def parse_fountain_payload(payload: bytes) -> bytes:
    header_size = 4 + 2 + 2 + 2 + 4 + 16
    if len(payload) < header_size:
        raise PacketLayerError("payload too short")

    magic = payload[:4]
    if magic != FNT_MAGIC:
        raise PacketLayerError("invalid fountain magic")

    shard_size, data_shards, parity_shards, msg_len = struct.unpack("!HHHI", payload[4:14])
    digest = payload[14:30]

    shards_blob = payload[header_size:]
    need = (data_shards + parity_shards) * shard_size
    if len(shards_blob) < need:
        raise PacketLayerError("payload too short for shards")

    data_blob = shards_blob[: data_shards * shard_size]
    if blake2b(data_blob, digest_size=16).digest() != digest:
        raise PacketLayerError("fountain digest mismatch")

    # Systematic: first data shards contain the framed+padding message.
    framed = data_blob
    msg = _unframe(framed)
    if len(msg) != msg_len:
        raise PacketLayerError("message length mismatch")
    return msg
