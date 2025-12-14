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
