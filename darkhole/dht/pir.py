from __future__ import annotations

import math
from dataclasses import dataclass

from darkhole.crypto import xor_bytes


def _query_len(db_size: int) -> int:
    if db_size <= 0:
        raise ValueError("db_size must be positive")
    return math.ceil(db_size / 8)


def _one_hot(db_size: int, index: int) -> bytes:
    if not (0 <= index < db_size):
        raise IndexError("index out of range")

    out = bytearray(_query_len(db_size))
    byte_i, bit_i = divmod(index, 8)
    out[byte_i] ^= 1 << bit_i
    return bytes(out)


def _iter_selected_indices(query: bytes, db_size: int):
    for i in range(db_size):
        byte_i, bit_i = divmod(i, 8)
        if query[byte_i] & (1 << bit_i):
            yield i


class ByteRNG:
    def randbytes(self, n: int) -> bytes:  # pragma: no cover
        raise NotImplementedError


@dataclass(frozen=True)
class TwoServerXorPIR:
    """2-server XOR PIR.

    Each server receives a uniformly random selection vector, independent of the
    requested index. The client combines the responses via XOR.

    This assumes servers do not collude.
    """

    @staticmethod
    def build_queries(db_size: int, index: int, *, rng: ByteRNG) -> tuple[bytes, bytes]:
        qlen = _query_len(db_size)
        r = rng.randbytes(qlen)
        one_hot = _one_hot(db_size, index)
        return r, xor_bytes(r, one_hot)

    @staticmethod
    def build_queries_from_mask(db_size: int, index: int, *, mask: bytes) -> tuple[bytes, bytes]:
        if len(mask) != _query_len(db_size):
            raise ValueError("mask length mismatch")
        one_hot = _one_hot(db_size, index)
        return mask, xor_bytes(mask, one_hot)

    @staticmethod
    def respond(db: list[bytes], *, query: bytes) -> bytes:
        if not db:
            raise ValueError("empty database")
        record_len = len(db[0])
        if any(len(r) != record_len for r in db):
            raise ValueError("database records must be fixed length")

        db_size = len(db)
        if len(query) != _query_len(db_size):
            raise ValueError("query length mismatch")

        acc = bytearray(record_len)
        for i in _iter_selected_indices(query, db_size):
            rec = db[i]
            for j, b in enumerate(rec):
                acc[j] ^= b
        return bytes(acc)

    @staticmethod
    def reconstruct(resp_a: bytes, resp_b: bytes) -> bytes:
        return xor_bytes(resp_a, resp_b)
