from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field

import pytest

from darkhole.crypto import KeyPair, blake2b_256
from darkhole.dht import (
    DHTClient,
    DHTClientConfig,
    DHTNode,
    MockOverlayNetwork,
    NullReputationHook,
    TierTrafficShaper,
    TwoServerXorPIR,
)


class DeterministicRNG:
    def __init__(self, seed: int) -> None:
        self._rng = random.Random(seed)

    def randbytes(self, n: int) -> bytes:
        return self._rng.randbytes(n)


@dataclass
class CountingReputationHook(NullReputationHook):
    successes: list[bytes] = field(default_factory=list)
    failures: list[tuple[bytes, str]] = field(default_factory=list)

    def on_relay_success(self, node_id: bytes) -> None:
        self.successes.append(node_id)

    def on_relay_failure(self, node_id: bytes, *, reason: str) -> None:
        self.failures.append((node_id, reason))


def _key_to_slot(key: bytes, *, table_size: int) -> int:
    return int.from_bytes(blake2b_256(key)[:4], "big") % table_size


def _generate_unique_slot_keys(*, n: int, table_size: int) -> list[bytes]:
    keys: list[bytes] = []
    used_slots: set[int] = set()
    i = 0
    while len(keys) < n:
        key = f"k:{i}".encode("utf-8")
        slot = _key_to_slot(key, table_size=table_size)
        if slot not in used_slots:
            used_slots.add(slot)
            keys.append(key)
        i += 1
    return keys


@pytest.mark.asyncio
async def test_store_and_pir_retrieve_concurrent_clients() -> None:
    table_size = 128
    record_size = 256

    overlay = MockOverlayNetwork()
    for tier in ["gold", "gold", "silver", "silver", "bronze", "bronze"]:
        overlay.add_node(DHTNode(keypair=KeyPair.generate(), tier=tier, table_size=table_size, record_size=record_size))

    shaper = TierTrafficShaper(budgets={"gold": 5_000_000, "silver": 5_000_000, "bronze": 5_000_000})
    rep_hook = CountingReputationHook()

    cfg = DHTClientConfig(namespace="test", table_size=table_size, record_size=record_size, replicas=2, route_hops=3)

    clients = [
        DHTClient(
            overlay,
            config=cfg,
            traffic_shaper=shaper,
            reputation_hook=rep_hook,
            rng=DeterministicRNG(1000 + i),
            route_rng=random.Random(2000 + i),
        )
        for i in range(10)
    ]

    keys = _generate_unique_slot_keys(n=20, table_size=table_size)
    kvs = {k: (b"value:" + k, {"owner": "unit-test"}) for k in keys}

    await asyncio.gather(
        *(
            clients[i % len(clients)].store(key=k, value=v, metadata=meta)
            for i, (k, (v, meta)) in enumerate(kvs.items())
        )
    )

    results = await asyncio.gather(*[clients[i % len(clients)].retrieve(key=k) for i, k in enumerate(keys)])
    for k, rec in zip(keys, results, strict=True):
        assert rec is not None
        assert rec.key == k
        assert rec.value == kvs[k][0]
        assert rec.metadata["owner"] == "unit-test"

    # Tier accounting should have been exercised.
    assert shaper.used["gold"] > 0
    assert shaper.used["silver"] > 0
    assert shaper.used["bronze"] > 0

    # Relay reputation hooks should have been called.
    assert rep_hook.successes
    assert not rep_hook.failures

    # PIR privacy sanity check: server-observed query vectors are not one-hot selectors.
    # (the one-hot pattern would leak the requested index immediately)
    for node in overlay.all_nodes():
        for q in node.observed_pir_queries:
            ones = sum(bin(b).count("1") for b in q)
            assert ones not in {0, 1, table_size - 1, table_size}


def test_pir_query_distribution_independent_of_index() -> None:
    # Exhaustive check for db_size=8: for any fixed index i, qB = r XOR e_i
    # is uniformly distributed when r ranges over all 8-bit masks.
    db_size = 8
    all_masks = [bytes([m]) for m in range(256)]

    for index in range(db_size):
        observed = set()
        for mask in all_masks:
            _, q_b = TwoServerXorPIR.build_queries_from_mask(db_size, index, mask=mask)
            observed.add(q_b)
        assert len(observed) == 256


@pytest.mark.asyncio
async def test_sphinx_onion_delivers_only_at_destination() -> None:
    table_size = 16
    record_size = 128

    overlay = MockOverlayNetwork()
    nodes = [
        DHTNode(keypair=KeyPair.generate(), tier="bronze", table_size=table_size, record_size=record_size)
        for _ in range(4)
    ]
    for n in nodes:
        overlay.add_node(n)

    client = DHTClient(
        overlay,
        config=DHTClientConfig(namespace="sphinx", table_size=table_size, record_size=record_size, replicas=2, route_hops=3),
        rng=DeterministicRNG(123),
        route_rng=random.Random(456),
    )

    key = _generate_unique_slot_keys(n=1, table_size=table_size)[0]
    await client.store(key=key, value=b"payload", metadata={"t": 1})

    # Only destination nodes should have application-layer messages.
    app_msg_nodes = [n for n in overlay.all_nodes() if n.observed_app_messages]
    assert app_msg_nodes
    assert len(app_msg_nodes) <= 2  # replication factor

    rec = await client.retrieve(key=key)
    assert rec is not None
    assert rec.value == b"payload"
