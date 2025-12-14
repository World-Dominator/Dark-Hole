from __future__ import annotations

import struct


class MsgType:
    STORE = 1
    PIR_QUERY = 2
    PIR_RESPONSE = 3


_HEADER_FMT = "!B16sB"  # type, request_id, namespace_len
_HEADER_LEN = struct.calcsize(_HEADER_FMT)


def encode_message(*, msg_type: int, request_id: bytes, namespace: str, payload: bytes) -> bytes:
    if len(request_id) != 16:
        raise ValueError("request_id must be 16 bytes")
    ns_bytes = namespace.encode("utf-8")
    if len(ns_bytes) > 255:
        raise ValueError("namespace too long")
    return struct.pack(_HEADER_FMT, msg_type, request_id, len(ns_bytes)) + ns_bytes + payload


def decode_message(data: bytes) -> tuple[int, bytes, str, bytes]:
    if len(data) < _HEADER_LEN:
        raise ValueError("message too short")
    msg_type, request_id, ns_len = struct.unpack(_HEADER_FMT, data[:_HEADER_LEN])
    if len(data) < _HEADER_LEN + ns_len:
        raise ValueError("message namespace truncated")
    ns_bytes = data[_HEADER_LEN : _HEADER_LEN + ns_len]
    payload = data[_HEADER_LEN + ns_len :]
    return msg_type, request_id, ns_bytes.decode("utf-8"), payload


def encode_store_payload(*, slot: int, record: bytes) -> bytes:
    return struct.pack("!IH", slot, len(record)) + record


def decode_store_payload(payload: bytes) -> tuple[int, bytes]:
    if len(payload) < 6:
        raise ValueError("store payload too short")
    slot, rlen = struct.unpack("!IH", payload[:6])
    record = payload[6:]
    if len(record) != rlen:
        raise ValueError("store payload length mismatch")
    return slot, record


def encode_pir_query_payload(*, query: bytes) -> bytes:
    return struct.pack("!H", len(query)) + query


def decode_pir_query_payload(payload: bytes) -> bytes:
    if len(payload) < 2:
        raise ValueError("pir query payload too short")
    (qlen,) = struct.unpack("!H", payload[:2])
    query = payload[2:]
    if len(query) != qlen:
        raise ValueError("pir query payload length mismatch")
    return query


def encode_pir_response_payload(*, response: bytes) -> bytes:
    return struct.pack("!H", len(response)) + response


def decode_pir_response_payload(payload: bytes) -> bytes:
    if len(payload) < 2:
        raise ValueError("pir response payload too short")
    (rlen,) = struct.unpack("!H", payload[:2])
    response = payload[2:]
    if len(response) != rlen:
        raise ValueError("pir response payload length mismatch")
    return response
