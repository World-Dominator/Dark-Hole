# Sphinx routing (onion packet format)

This document describes the *current* Sphinx-inspired routing layer implemented in `darkhole/crypto/sphinx/`.

The goal is to provide deterministic N-hop relay traversal with:

- per-hop ephemeral key agreement (X25519)
- blinded routing information (each hop only learns its next hop)
- onion-encrypted payloads (each hop peels one layer)
- proof-of-work (PoW) tags to rate-limit spam/DoS
- explicit hooks for relay reputation / staking-slashing integration
- public `context` binding for group messaging (sender keys / TreeKEM exporters)

## Path descriptors

A sender constructs a packet using a list of hop descriptors:

- `relay_id` (32 bytes): a stable identifier for the relay
- `public_key` (X25519): used to derive per-hop symmetric keys
- `pow_difficulty` (bits): leading-zero-bits target for the PoW digest

Relays are addressed by their `relay_id` inside encrypted routing entries.

## Packet layout (conceptual)

A `SphinxPacket` contains:

- `version`: protocol version (currently `1`)
- `context`: 16 bytes of public context mixed into AEAD associated data
- `hop_pubkeys[i]`: sender-generated ephemeral X25519 pubkey for hop `i`
- `routing_entries[i]`: AEAD-encrypted routing instruction for hop `i`
- `payload`: onion-encrypted application payload

Routing instructions are fixed-size (64 bytes plaintext) and include:

- `next_relay_id` (32 bytes)
- `flags` (1 byte) — `FINAL` indicates last hop
- `pow_difficulty` (1 byte)
- `pow_nonce` (8 bytes)

## Key derivation

For hop `i`, the sender generates an ephemeral keypair `(eph_priv_i, eph_pub_i)` and computes:

- `shared_i = X25519(eph_priv_i, relay_pub_i)`
- `routing_key_i, payload_key_i = HKDF-SHA256(shared_i, salt="darkhole-sphinx-v1", info="hop-keys")`

These keys are used with ChaCha20-Poly1305.

## Onion construction

The sender builds the payload from the last hop back to the first hop:

1. Compute PoW for hop `i` over the *inner payload hash* (see below).
2. Encrypt routing instruction `i` using `routing_key_i`.
3. Encrypt the current payload blob using `payload_key_i`.

Each relay:

1. Uses the first `hop_pubkey` to derive hop keys.
2. Decrypts its first `routing_entry` to learn `next_relay_id` and PoW parameters.
3. Decrypts one payload layer to obtain the peeled inner payload.
4. Verifies PoW.
5. Forwards a new packet with the first hop key / routing entry removed.

## Proof-of-work (PoW)

The PoW is a per-hop, relay-specific digest check:

- The sender finds an 8-byte nonce such that:

  `blake2b(pow_data || nonce)` has at least `pow_difficulty` leading zero bits.

- `pow_data` is:

  `b"pow" || relay_id || hop_ephemeral_pubkey || blake2b(inner_payload)`

Relays validate PoW after peeling the payload layer.

## Defensive measures / fingerprinting avoidance

The current implementation is designed for correctness and deterministic relay peeling. Production hardening typically adds:

- **Fixed-size packets**: true Sphinx keeps packet sizes constant as layers peel. When packet size shrinks (e.g., by dropping hop keys) or ciphertext length grows with each layer, an observer can estimate path length.
- **Header padding / constant hop budget**: always transmit a fixed hop budget (e.g. 5–8 hops) with dummy entries, and avoid shrinking headers on forward.
- **Replay protection**: store/reject recently seen packet identifiers or per-hop tags.
- **Routing info blinding**: real Sphinx uses blinding of the ephemeral key and a shift-register header so that intermediaries cannot correlate layers.
- **Uniform processing time**: verify tags and perform decryption in constant-time / uniform work envelopes.

The `context` field exists to bind packets to group contexts (e.g., sender keys or TreeKEM exporter outputs) without changing the routing format.

## Reputation / staking-slashing integration

Relays call `ReputationHooks` (see `darkhole/crypto/reputation.py`) on:

- PoW valid/invalid
- packet tamper / integrity failure
- packet forwarded
- packet delivered

This is a stub for future integration with staking, slashing, and reputation systems.
