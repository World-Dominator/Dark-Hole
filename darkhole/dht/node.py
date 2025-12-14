from __future__ import annotations

from dataclasses import dataclass, field

from darkhole.crypto import KeyPair
from darkhole.dht.messages import (
    MsgType,
    decode_message,
    decode_pir_query_payload,
    decode_store_payload,
    encode_message,
    encode_pir_response_payload,
)
from darkhole.dht.pir import TwoServerXorPIR


@dataclass
class DHTNode:
    keypair: KeyPair
    tier: str
    table_size: int
    record_size: int

    table: list[bytes] = field(init=False)
    observed_pir_queries: list[bytes] = field(default_factory=list)
    observed_app_messages: list[bytes] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.table = [b"\x00" * self.record_size for _ in range(self.table_size)]

    @property
    def node_id(self) -> bytes:
        return self.keypair.node_id()

    @property
    def public_key_bytes(self) -> bytes:
        return self.keypair.public_bytes()

    def handle_application_message(self, data: bytes) -> bytes | None:
        msg_type, request_id, namespace, payload = decode_message(data)
        self.observed_app_messages.append(data)

        if msg_type == MsgType.STORE:
            slot, record = decode_store_payload(payload)
            if slot >= self.table_size:
                raise ValueError("slot out of range")
            if len(record) != self.record_size:
                raise ValueError("record size mismatch")
            self.table[slot] = record
            return None

        if msg_type == MsgType.PIR_QUERY:
            query = decode_pir_query_payload(payload)
            self.observed_pir_queries.append(query)
            response = TwoServerXorPIR.respond(self.table, query=query)
            resp_payload = encode_pir_response_payload(response=response)
            return encode_message(
                msg_type=MsgType.PIR_RESPONSE,
                request_id=request_id,
                namespace=namespace,
                payload=resp_payload,
            )

        raise ValueError(f"unknown msg_type: {msg_type}")
