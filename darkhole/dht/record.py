from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any


_RECORD_MAGIC = b"DHRC"
_HEADER_FMT = "!4sHIH"  # magic, key_len, value_len, metadata_len
_HEADER_LEN = struct.calcsize(_HEADER_FMT)


@dataclass(frozen=True)
class DHTRecord:
    key: bytes
    value: bytes
    metadata: dict[str, Any]


class RecordCodec:
    @staticmethod
    def encode(record: DHTRecord, *, record_size: int) -> bytes:
        metadata_bytes = json.dumps(record.metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(record.key) > 0xFFFF:
            raise ValueError("key too large")
        if len(metadata_bytes) > 0xFFFF:
            raise ValueError("metadata too large")
        if len(record.value) > 0xFFFFFFFF:
            raise ValueError("value too large")

        header = struct.pack(
            _HEADER_FMT,
            _RECORD_MAGIC,
            len(record.key),
            len(record.value),
            len(metadata_bytes),
        )
        body = record.key + record.value + metadata_bytes

        total_len = _HEADER_LEN + len(body)
        if total_len > record_size:
            raise ValueError("record exceeds record_size")
        return header + body + b"\x00" * (record_size - total_len)

    @staticmethod
    def decode(data: bytes) -> DHTRecord | None:
        if not data or set(data) == {0}:
            return None
        if len(data) < _HEADER_LEN:
            raise ValueError("record too short")

        magic, key_len, value_len, meta_len = struct.unpack(_HEADER_FMT, data[:_HEADER_LEN])
        if magic != _RECORD_MAGIC:
            raise ValueError("invalid record magic")

        start = _HEADER_LEN
        end_key = start + key_len
        end_val = end_key + value_len
        end_meta = end_val + meta_len
        if end_meta > len(data):
            raise ValueError("record length fields exceed buffer")

        key = data[start:end_key]
        value = data[end_key:end_val]
        metadata_bytes = data[end_val:end_meta]
        metadata = json.loads(metadata_bytes.decode("utf-8")) if metadata_bytes else {}
        return DHTRecord(key=key, value=value, metadata=metadata)
