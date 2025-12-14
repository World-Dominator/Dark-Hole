from __future__ import annotations

import asyncio
import random
import secrets
from dataclasses import dataclass, field
from typing import Any

from darkhole.crypto import blake2b_256
from darkhole.dht.messages import (
    MsgType,
    decode_message,
    decode_pir_response_payload,
    encode_message,
    encode_pir_query_payload,
    encode_store_payload,
)
from darkhole.dht.overlay import MockOverlayNetwork
from darkhole.dht.pir import ByteRNG, TwoServerXorPIR
from darkhole.dht.record import DHTRecord, RecordCodec
from darkhole.dht.reputation import NullReputationHook, ReputationHook
from darkhole.dht.traffic import TierTrafficShaper
from darkhole.sphinx import SphinxPacket


def _key_to_slot(key: bytes, *, table_size: int) -> int:
    return int.from_bytes(blake2b_256(key)[:4], "big") % table_size


class _SecretsRNG(ByteRNG):
    def randbytes(self, n: int) -> bytes:
        return secrets.token_bytes(n)


@dataclass(frozen=True)
class DHTClientConfig:
    namespace: str = "default"
    table_size: int = 64
    record_size: int = 512
    replicas: int = 2
    route_hops: int = 3


@dataclass
class DHTClient:
    overlay: MockOverlayNetwork
    config: DHTClientConfig = field(default_factory=DHTClientConfig)
    traffic_shaper: TierTrafficShaper | None = None
    reputation_hook: ReputationHook = field(default_factory=NullReputationHook)
    rng: ByteRNG = field(default_factory=_SecretsRNG)
    route_rng: random.Random = field(default_factory=random.Random)

    def store_sync(self, *, key: bytes, value: bytes, metadata: dict[str, Any] | None = None) -> None:
        metadata = metadata or {}
        slot = _key_to_slot(key, table_size=self.config.table_size)
        record = RecordCodec.encode(
            DHTRecord(key=key, value=value, metadata=metadata),
            record_size=self.config.record_size,
        )

        payload = encode_store_payload(slot=slot, record=record)
        request_id = secrets.token_bytes(16)
        msg = encode_message(
            msg_type=MsgType.STORE,
            request_id=request_id,
            namespace=self.config.namespace,
            payload=payload,
        )

        replicas = self.overlay.get_replica_nodes(key, replicas=self.config.replicas)
        for node in replicas:
            route = self.overlay.plan_route(destination_id=node.node_id, hops=self.config.route_hops, rng=self.route_rng)
            packet = SphinxPacket.build(
                [n.public_key_bytes for n in route],
                [n.node_id for n in route],
                msg,
            )
            entry = route[0].node_id
            self.overlay.request(
                entry_node_id=entry,
                packet_bytes=packet,
                traffic_shaper=self.traffic_shaper,
                reputation_hook=self.reputation_hook,
            )

    def retrieve_sync(self, *, key: bytes) -> DHTRecord | None:
        slot = _key_to_slot(key, table_size=self.config.table_size)
        replicas = self.overlay.get_replica_nodes(key, replicas=self.config.replicas)
        if len(replicas) < 2:
            raise ValueError("PIR retrieval requires at least two replicas")

        q_a, q_b = TwoServerXorPIR.build_queries(self.config.table_size, slot, rng=self.rng)
        resp_a = self._pir_query_sync(node=replicas[0], query=q_a)
        resp_b = self._pir_query_sync(node=replicas[1], query=q_b)

        record_bytes = TwoServerXorPIR.reconstruct(resp_a, resp_b)
        rec = RecordCodec.decode(record_bytes)
        if rec is None:
            return None
        if rec.key != key:
            return None
        return rec

    def _pir_query_sync(self, *, node, query: bytes) -> bytes:
        request_id = secrets.token_bytes(16)
        payload = encode_pir_query_payload(query=query)
        msg = encode_message(
            msg_type=MsgType.PIR_QUERY,
            request_id=request_id,
            namespace=self.config.namespace,
            payload=payload,
        )

        route = self.overlay.plan_route(destination_id=node.node_id, hops=self.config.route_hops, rng=self.route_rng)
        packet = SphinxPacket.build(
            [n.public_key_bytes for n in route],
            [n.node_id for n in route],
            msg,
        )
        entry = route[0].node_id
        resp_msg = self.overlay.request(
            entry_node_id=entry,
            packet_bytes=packet,
            traffic_shaper=self.traffic_shaper,
            reputation_hook=self.reputation_hook,
        )
        if resp_msg is None:
            raise RuntimeError("missing PIR response")

        msg_type, _, _, resp_payload = decode_message(resp_msg)
        if msg_type != MsgType.PIR_RESPONSE:
            raise ValueError("unexpected response type")
        return decode_pir_response_payload(resp_payload)

    async def store(self, *, key: bytes, value: bytes, metadata: dict[str, Any] | None = None) -> None:
        metadata = metadata or {}
        slot = _key_to_slot(key, table_size=self.config.table_size)
        record = RecordCodec.encode(
            DHTRecord(key=key, value=value, metadata=metadata),
            record_size=self.config.record_size,
        )

        payload = encode_store_payload(slot=slot, record=record)
        request_id = secrets.token_bytes(16)
        msg = encode_message(
            msg_type=MsgType.STORE,
            request_id=request_id,
            namespace=self.config.namespace,
            payload=payload,
        )

        replicas = self.overlay.get_replica_nodes(key, replicas=self.config.replicas)
        for node in replicas:
            route = self.overlay.plan_route(destination_id=node.node_id, hops=self.config.route_hops, rng=self.route_rng)
            packet = SphinxPacket.build(
                [n.public_key_bytes for n in route],
                [n.node_id for n in route],
                msg,
            )
            entry = route[0].node_id
            await asyncio.to_thread(
                self.overlay.request,
                entry_node_id=entry,
                packet_bytes=packet,
                traffic_shaper=self.traffic_shaper,
                reputation_hook=self.reputation_hook,
            )

    async def retrieve(self, *, key: bytes) -> DHTRecord | None:
        slot = _key_to_slot(key, table_size=self.config.table_size)
        replicas = self.overlay.get_replica_nodes(key, replicas=self.config.replicas)
        if len(replicas) < 2:
            raise ValueError("PIR retrieval requires at least two replicas")

        q_a, q_b = TwoServerXorPIR.build_queries(self.config.table_size, slot, rng=self.rng)

        resp_a = await self._pir_query(node=replicas[0], query=q_a)
        resp_b = await self._pir_query(node=replicas[1], query=q_b)

        record_bytes = TwoServerXorPIR.reconstruct(resp_a, resp_b)
        rec = RecordCodec.decode(record_bytes)
        if rec is None:
            return None
        if rec.key != key:
            return None
        return rec

    async def _pir_query(self, *, node, query: bytes) -> bytes:
        request_id = secrets.token_bytes(16)
        payload = encode_pir_query_payload(query=query)
        msg = encode_message(
            msg_type=MsgType.PIR_QUERY,
            request_id=request_id,
            namespace=self.config.namespace,
            payload=payload,
        )

        route = self.overlay.plan_route(destination_id=node.node_id, hops=self.config.route_hops, rng=self.route_rng)
        packet = SphinxPacket.build(
            [n.public_key_bytes for n in route],
            [n.node_id for n in route],
            msg,
        )
        entry = route[0].node_id
        resp_msg = await asyncio.to_thread(
            self.overlay.request,
            entry_node_id=entry,
            packet_bytes=packet,
            traffic_shaper=self.traffic_shaper,
            reputation_hook=self.reputation_hook,
        )
        if resp_msg is None:
            raise RuntimeError("missing PIR response")

        msg_type, _, _, resp_payload = decode_message(resp_msg)
        if msg_type != MsgType.PIR_RESPONSE:
            raise ValueError("unexpected response type")
        return decode_pir_response_payload(resp_payload)
