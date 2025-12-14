from __future__ import annotations

import random
from dataclasses import dataclass, field

from darkhole.crypto import blake2b_256
from darkhole.dht.node import DHTNode
from darkhole.dht.reputation import NullReputationHook, ReputationHook
from darkhole.dht.traffic import TierTrafficShaper
from darkhole.sphinx import SphinxPacket


@dataclass
class MockOverlayNetwork:
    nodes: dict[bytes, DHTNode] = field(default_factory=dict)

    def add_node(self, node: DHTNode) -> None:
        self.nodes[node.node_id] = node

    def get_node(self, node_id: bytes) -> DHTNode:
        return self.nodes[node_id]

    def all_nodes(self) -> list[DHTNode]:
        return list(self.nodes.values())

    def get_replica_nodes(self, key: bytes, *, replicas: int = 2) -> list[DHTNode]:
        if replicas <= 0:
            raise ValueError("replicas must be positive")
        if replicas > len(self.nodes):
            raise ValueError("not enough nodes for replicas")

        ranked = sorted(
            self.nodes.values(),
            key=lambda n: (
                int.from_bytes(blake2b_256(key + n.node_id)[:8], "big"),
                n.node_id,
            ),
        )
        return ranked[:replicas]

    def plan_route(self, *, destination_id: bytes, hops: int = 3, rng: random.Random) -> list[DHTNode]:
        if destination_id not in self.nodes:
            raise KeyError("unknown destination")
        if hops < 1:
            raise ValueError("hops must be >= 1")

        dest = self.nodes[destination_id]
        if hops == 1:
            return [dest]

        candidates = [n for n in self.nodes.values() if n.node_id != destination_id]
        if not candidates:
            return [dest]

        route: list[DHTNode] = []
        while len(route) < hops - 1 and candidates:
            pick = rng.choice(candidates)
            route.append(pick)
            candidates = [n for n in candidates if n.node_id != pick.node_id]

        route.append(dest)
        return route

    def request(
        self,
        *,
        entry_node_id: bytes,
        packet_bytes: bytes,
        traffic_shaper: TierTrafficShaper | None = None,
        reputation_hook: ReputationHook | None = None,
    ) -> bytes | None:
        if reputation_hook is None:
            reputation_hook = NullReputationHook()

        current_id = entry_node_id
        current_packet = packet_bytes

        while True:
            node = self.get_node(current_id)
            if traffic_shaper is not None:
                traffic_shaper.consume(node.tier, len(current_packet))

            try:
                next_id, next_packet_or_payload = SphinxPacket.peel(current_packet, node.keypair)
            except Exception as e:  # noqa: BLE001
                reputation_hook.on_relay_failure(node.node_id, reason=str(e))
                raise

            reputation_hook.on_relay_success(node.node_id)

            if next_id is None:
                return node.handle_application_message(next_packet_or_payload)

            current_id = next_id
            current_packet = next_packet_or_payload
