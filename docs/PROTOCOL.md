# Darkhole Protocol (prototype)

This repository currently contains a **mockable DHT client subsystem** with **two-server PIR retrieval** and **Sphinx-style onion packets** for request transport.

> Note: this is a research-oriented prototype intended for unit/integration tests. It does **not** claim production-grade cryptographic security.

## Components

- `darkhole.sphinx.SphinxPacket`
  - A minimal Sphinx-like onion packet.
  - The client builds a multi-hop route and wraps a DHT request into nested AEAD layers.
  - Each relay peels exactly one layer, learns only the *next hop node id*, and forwards the remaining ciphertext.

- `darkhole.dht.MockOverlayNetwork`
  - In-memory overlay used by tests.
  - Simulates relay forwarding, tier-aware traffic accounting, and reputation hook callbacks.

- `darkhole.dht.TwoServerXorPIR`
  - 2-server XOR PIR scheme.
  - For a database of `N` fixed-size records and an index `i`, the client generates:
    - `qA = r`
    - `qB = r XOR e_i`
    where `r` is a uniform random bit-vector and `e_i` is the one-hot vector for index `i`.
  - Each server responds with the XOR of all records selected by its query vector.
  - The client XORs the two responses to recover record `i`.
  - Any *single* query (`qA` or `qB`) is uniformly random and does not reveal `i` (assuming the two servers do not collude).

## DHT workflow

### Storage

1. The client maps an application key to a fixed slot:

   `slot = blake2b_256(key) mod table_size`

2. The client encodes a fixed-size record containing `{key, value, metadata}`.

3. The record is stored on `replicas` relay nodes (default: 2). Storage is not PIR-protected in this prototype.

### Retrieval (PIR)

1. The client computes the same `slot`.
2. It selects two replica nodes.
3. It sends `qA` and `qB` as PIR query vectors to the two replicas using Sphinx packets (multi-hop).
4. The client reconstructs the record via XOR and verifies that the embedded `key` matches.

### Tier-aware traffic shaping

The mock overlay supports deterministic accounting via `TierTrafficShaper`. Each forwarded packet consumes budget for the tier of the hop it traverses.

### Reputation hooks

The overlay calls `ReputationHook.on_relay_success/on_relay_failure` for each hop peel.

## Example usage

```python
import asyncio

from darkhole.crypto import KeyPair
from darkhole.dht import DHTClient, DHTClientConfig, DHTNode, MockOverlayNetwork, TierTrafficShaper


async def main() -> None:
    overlay = MockOverlayNetwork()
    for tier in ["gold", "silver", "bronze", "bronze"]:
        overlay.add_node(DHTNode(keypair=KeyPair.generate(), tier=tier, table_size=64, record_size=512))

    shaper = TierTrafficShaper(budgets={"gold": 10_000_000, "silver": 10_000_000, "bronze": 10_000_000})

    client = DHTClient(
        overlay,
        config=DHTClientConfig(namespace="chat", table_size=64, record_size=512),
        traffic_shaper=shaper,
    )

    key = b"message:123"
    await client.store(key=key, value=b"hello", metadata={"ttl": 60})

    rec = await client.retrieve(key=key)
    assert rec is not None
    assert rec.value == b"hello"


asyncio.run(main())
```
# Protocol (cryptographic choices)

This document captures the cryptographic building blocks used by the `darkhole` protocol.
It is a stub intended to guide later integration work.

## Primitives

- **Key agreement (DH):** X25519
- **AEAD:** ChaCha20-Poly1305
- **Hash/Digest:** BLAKE2b
- **KDF:** HKDF with BLAKE2b (full 64-byte digest)

## Initial key establishment

For initial client/server establishment the project exposes an **OPAQUE-inspired**
password-authenticated key establishment API under `darkhole.crypto.opaque`.

Note: this is not an RFC 9380 implementation; it exists to provide a typed API surface
and a development stub. A future iteration can swap in a complete OPAQUE implementation
without changing higher-level callers.

## Messaging

The messaging layer uses an **asymmetric double ratchet** (`darkhole.crypto.ratchet`)
featuring:

- X25519 DH ratchet steps.
- HKDF(BLAKE2b) root-key and chain-key derivation.
- Per-message ChaCha20-Poly1305 keys.
- A bounded skipped-message-key cache for out-of-order delivery.
- Post-compromise security via DH ratcheting.
