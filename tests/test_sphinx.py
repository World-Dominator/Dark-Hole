from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from darkhole.crypto import packet_layer
from darkhole.crypto.sphinx import (
    DeliverResult,
    ForwardResult,
    HopDescriptor,
    SphinxPacket,
    SphinxTamperError,
    build_packet,
    process_packet,
    relay_id_from_public_key,
)


class TestSphinxRouting(unittest.TestCase):
    def _make_hop(self, pow_difficulty: int = 8):
        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        relay_id = relay_id_from_public_key(pub)
        return priv, HopDescriptor(relay_id=relay_id, public_key=pub, pow_difficulty=pow_difficulty)

    def test_packet_build_and_multihop_peel_delivers_payload(self):
        r1_priv, r1 = self._make_hop(pow_difficulty=8)
        r2_priv, r2 = self._make_hop(pow_difficulty=8)
        r3_priv, r3 = self._make_hop(pow_difficulty=8)

        message = b"hello sphinx"
        payload = packet_layer.build_padded_payload(message, payload_size=256)

        packet = build_packet([r1, r2, r3], payload)

        res1 = process_packet(packet, relay_private_key=r1_priv, relay_id=r1.relay_id)
        self.assertIsInstance(res1, ForwardResult)
        self.assertEqual(res1.next_relay_id, r2.relay_id)

        res2 = process_packet(res1.packet, relay_private_key=r2_priv, relay_id=r2.relay_id)
        self.assertIsInstance(res2, ForwardResult)
        self.assertEqual(res2.next_relay_id, r3.relay_id)

        res3 = process_packet(res2.packet, relay_private_key=r3_priv, relay_id=r3.relay_id)
        self.assertIsInstance(res3, DeliverResult)
        self.assertEqual(packet_layer.parse_padded_payload(res3.payload), message)

    def test_packet_roundtrip_serialization(self):
        r1_priv, r1 = self._make_hop(pow_difficulty=6)
        r2_priv, r2 = self._make_hop(pow_difficulty=6)

        payload = packet_layer.build_padded_payload(b"abc", payload_size=128)
        packet = build_packet([r1, r2], payload)

        blob = packet.to_bytes()
        packet2 = SphinxPacket.from_bytes(blob)
        self.assertEqual(packet, packet2)

        res = process_packet(packet2, relay_private_key=r1_priv, relay_id=r1.relay_id)
        self.assertIsInstance(res, ForwardResult)
        _ = process_packet(res.packet, relay_private_key=r2_priv, relay_id=r2.relay_id)

    def test_tamper_detection_in_routing_entry(self):
        r1_priv, r1 = self._make_hop(pow_difficulty=6)
        r2_priv, r2 = self._make_hop(pow_difficulty=6)

        payload = packet_layer.build_padded_payload(b"tamper", payload_size=128)
        packet = build_packet([r1, r2], payload)

        bad_entry = bytearray(packet.routing_entries[0])
        bad_entry[0] ^= 0x01

        tampered = SphinxPacket(
            version=packet.version,
            context=packet.context,
            hop_pubkeys=packet.hop_pubkeys,
            routing_entries=(bytes(bad_entry),) + packet.routing_entries[1:],
            payload=packet.payload,
        )

        with self.assertRaises(SphinxTamperError):
            process_packet(tampered, relay_private_key=r1_priv, relay_id=r1.relay_id)

    def test_tamper_detection_in_payload(self):
        r1_priv, r1 = self._make_hop(pow_difficulty=6)
        r2_priv, r2 = self._make_hop(pow_difficulty=6)

        payload = packet_layer.build_padded_payload(b"tamper", payload_size=128)
        packet = build_packet([r1, r2], payload)

        bad_payload = bytearray(packet.payload)
        bad_payload[len(bad_payload) // 2] ^= 0xFF

        tampered = SphinxPacket(
            version=packet.version,
            context=packet.context,
            hop_pubkeys=packet.hop_pubkeys,
            routing_entries=packet.routing_entries,
            payload=bytes(bad_payload),
        )

        with self.assertRaises(SphinxTamperError):
            process_packet(tampered, relay_private_key=r1_priv, relay_id=r1.relay_id)

    def test_interop_with_fountain_padding_layer(self):
        r1_priv, r1 = self._make_hop(pow_difficulty=6)
        r2_priv, r2 = self._make_hop(pow_difficulty=6)
        r3_priv, r3 = self._make_hop(pow_difficulty=6)

        message = b"group message payload"
        payload = packet_layer.build_fountain_payload(
            message,
            payload_size=512,
            params=packet_layer.FountainParams(shard_size=64, parity_shards=1),
        )

        packet = build_packet([r1, r2, r3], payload, sender_key=b"sender-key-v1")

        res: object = process_packet(packet, relay_private_key=r1_priv, relay_id=r1.relay_id)
        self.assertIsInstance(res, ForwardResult)
        res = process_packet(res.packet, relay_private_key=r2_priv, relay_id=r2.relay_id)
        self.assertIsInstance(res, ForwardResult)
        res = process_packet(res.packet, relay_private_key=r3_priv, relay_id=r3.relay_id)
        self.assertIsInstance(res, DeliverResult)

        decoded = packet_layer.parse_fountain_payload(res.payload)
        self.assertEqual(decoded, message)


if __name__ == "__main__":
    unittest.main()
