from __future__ import annotations

import struct
from dataclasses import dataclass

from darkhole.crypto import KeyPair, aead_decrypt, aead_encrypt, hkdf_sha256

NODE_ID_LEN = 16
EPHEMERAL_PUB_LEN = 32


def _derive_hop_key_nonce(shared_secret: bytes) -> tuple[bytes, bytes]:
    material = hkdf_sha256(shared_secret, info=b"darkhole/sphinx/v1")
    key = material
    nonce = hkdf_sha256(shared_secret, info=b"darkhole/sphinx/v1/nonce")[:12]
    return key, nonce


@dataclass(frozen=True)
class SphinxPacket:
    ephemeral_public_key: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        return self.ephemeral_public_key + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "SphinxPacket":
        if len(data) < EPHEMERAL_PUB_LEN:
            raise ValueError("packet too short")
        return cls(data[:EPHEMERAL_PUB_LEN], data[EPHEMERAL_PUB_LEN:])

    @classmethod
    def build(cls, route_public_keys: list[bytes], route_node_ids: list[bytes], payload: bytes) -> bytes:
        if len(route_public_keys) != len(route_node_ids):
            raise ValueError("route_public_keys and route_node_ids length mismatch")
        if any(len(nid) != NODE_ID_LEN for nid in route_node_ids):
            raise ValueError("invalid node id length")

        eph = KeyPair.generate()
        eph_pub = eph.public_bytes()

        inner: bytes = payload
        for idx in range(len(route_public_keys) - 1, -1, -1):
            hop_pub = route_public_keys[idx]
            next_id = route_node_ids[idx + 1] if idx + 1 < len(route_node_ids) else b"\x00" * NODE_ID_LEN

            shared = eph.shared_secret(hop_pub)
            key, nonce = _derive_hop_key_nonce(shared)

            body = next_id + struct.pack("!I", len(inner)) + inner
            inner = aead_encrypt(key, nonce, body, aad=eph_pub)

        return eph_pub + inner

    @classmethod
    def peel(cls, packet_bytes: bytes, hop_keypair: KeyPair) -> tuple[bytes | None, bytes]:
        pkt = cls.from_bytes(packet_bytes)
        shared = hop_keypair.shared_secret(pkt.ephemeral_public_key)
        key, nonce = _derive_hop_key_nonce(shared)

        body = aead_decrypt(key, nonce, pkt.ciphertext, aad=pkt.ephemeral_public_key)
        if len(body) < NODE_ID_LEN + 4:
            raise ValueError("invalid sphinx layer")

        next_id = body[:NODE_ID_LEN]
        (inner_len,) = struct.unpack("!I", body[NODE_ID_LEN : NODE_ID_LEN + 4])
        inner = body[NODE_ID_LEN + 4 :]
        if len(inner) != inner_len:
            raise ValueError("invalid inner length")

        if next_id == b"\x00" * NODE_ID_LEN:
            return None, inner
        return next_id, pkt.ephemeral_public_key + inner
