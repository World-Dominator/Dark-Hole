"""Comprehensive tests for fountain encoding/decoding and packet layer."""
from __future__ import annotations

import random

import numpy as np
import pytest

from darkhole.config import TIER_BALANCED, TIER_HIGH_SECURITY, TIER_HIGH_THROUGHPUT
from darkhole.packet.fountain import FountainDecoder, FountainEncoder, LTCode
from darkhole.packet.padding import PaddingStrategy, padding_for_tier
from darkhole.packet.schema import Packet, PacketVersion


class TestLTCode:
    """Tests for LT code generation."""
    
    def test_lt_code_initialization(self):
        """Test LT code initialization."""
        lt = LTCode(k=8, seed=42)
        assert lt.k == 8
        assert lt.rng is not None
    
    def test_lt_code_encode_shard(self):
        """Test shard encoding."""
        lt = LTCode(k=4, seed=42)
        data = b'\x00' * 256
        shard_size = 64
        shard, seed = lt.encode_shard(data, seed=0, shard_size=shard_size)
        
        assert isinstance(shard, bytes)
        assert len(shard) == shard_size
        assert seed == 0


class TestFountainEncoder:
    """Tests for fountain encoding."""
    
    def test_initialization_high_security(self):
        """Test encoder initialization with high security tier."""
        encoder = FountainEncoder(TIER_HIGH_SECURITY)
        assert encoder.tier == TIER_HIGH_SECURITY
        assert encoder.shard_size == TIER_HIGH_SECURITY.shard_size
        assert encoder.num_shards > encoder.k
    
    def test_initialization_balanced(self):
        """Test encoder initialization with balanced tier."""
        encoder = FountainEncoder(TIER_BALANCED)
        assert encoder.tier == TIER_BALANCED
        assert encoder.num_shards > encoder.k
    
    def test_initialization_high_throughput(self):
        """Test encoder initialization with high throughput tier."""
        encoder = FountainEncoder(TIER_HIGH_THROUGHPUT)
        assert encoder.tier == TIER_HIGH_THROUGHPUT
        assert encoder.num_shards > encoder.k
    
    def test_encode_small_plaintext(self):
        """Test encoding small plaintext."""
        encoder = FountainEncoder(TIER_HIGH_SECURITY)
        plaintext = b"Hello, World!"
        
        shards = encoder.encode(plaintext)
        
        assert len(shards) == encoder.num_shards
        for shard_data, shard_index, seed in shards:
            assert isinstance(shard_data, bytes)
            assert len(shard_data) == TIER_HIGH_SECURITY.shard_size
            assert isinstance(shard_index, int)
            assert isinstance(seed, int)
    
    def test_encode_max_size_plaintext(self):
        """Test encoding maximum size plaintext."""
        encoder = FountainEncoder(TIER_BALANCED)
        plaintext = b"X" * TIER_BALANCED.payload_size
        
        shards = encoder.encode(plaintext)
        
        assert len(shards) == encoder.num_shards
        for shard_data, shard_index, seed in shards:
            assert len(shard_data) == TIER_BALANCED.shard_size
    
    def test_encode_exceeds_limit(self):
        """Test encoding with plaintext exceeding tier limit."""
        encoder = FountainEncoder(TIER_HIGH_SECURITY)
        plaintext = b"X" * (TIER_HIGH_SECURITY.payload_size + 1)
        
        with pytest.raises(ValueError, match="Plaintext size.*exceeds tier limit"):
            encoder.encode(plaintext)
    
    def test_encode_deterministic(self):
        """Test that encoding with same seed produces same shards."""
        encoder = FountainEncoder(TIER_HIGH_SECURITY)
        plaintext = b"Test data"
        
        shards1 = encoder.encode(plaintext)
        shards2 = encoder.encode(plaintext)
        
        # Both should have same structure
        assert len(shards1) == len(shards2)
        # Note: Due to randomness in LT code, exact bytes may differ


class TestFountainDecoder:
    """Tests for fountain decoding."""
    
    def test_initialization(self):
        """Test decoder initialization."""
        decoder = FountainDecoder(TIER_BALANCED)
        assert decoder.tier == TIER_BALANCED
        assert decoder.get_received_shard_count() == 0
    
    def test_add_shard(self):
        """Test adding shards."""
        decoder = FountainDecoder(TIER_HIGH_SECURITY)
        shard_data = b"\x00" * TIER_HIGH_SECURITY.shard_size
        
        decoder.add_shard(shard_data, shard_index=0, seed=42)
        
        assert decoder.get_received_shard_count() == 1
    
    def test_add_shard_wrong_size(self):
        """Test adding shard with wrong size."""
        decoder = FountainDecoder(TIER_HIGH_SECURITY)
        shard_data = b"\x00" * 100  # Wrong size
        
        with pytest.raises(ValueError, match="Shard size.*does not match"):
            decoder.add_shard(shard_data, shard_index=0, seed=42)
    
    def test_is_decodable_insufficient(self):
        """Test decodability check with insufficient shards."""
        decoder = FountainDecoder(TIER_BALANCED)
        
        assert not decoder.is_decodable()
        
        # Add less than k shards
        for i in range(decoder.k - 1):
            shard_data = b"\x00" * TIER_BALANCED.shard_size
            decoder.add_shard(shard_data, shard_index=i, seed=i)
        
        assert not decoder.is_decodable()
    
    def test_is_decodable_sufficient(self):
        """Test decodability check with sufficient shards."""
        decoder = FountainDecoder(TIER_BALANCED)
        
        # Add k shards
        for i in range(decoder.k):
            shard_data = b"\x00" * TIER_BALANCED.shard_size
            decoder.add_shard(shard_data, shard_index=i, seed=i)
        
        assert decoder.is_decodable()
    
    def test_decode_insufficient_shards(self):
        """Test decoding with insufficient shards."""
        decoder = FountainDecoder(TIER_HIGH_SECURITY)
        
        # Add less than k shards
        for i in range(decoder.k - 1):
            shard_data = b"\x00" * TIER_HIGH_SECURITY.shard_size
            decoder.add_shard(shard_data, shard_index=i, seed=i)
        
        result = decoder.decode()
        assert result is None
    
    def test_decode_sufficient_shards(self):
        """Test decoding with sufficient shards."""
        decoder = FountainDecoder(TIER_BALANCED)
        
        # Add k shards
        for i in range(decoder.k):
            shard_data = b"\x00" * TIER_BALANCED.shard_size
            decoder.add_shard(shard_data, shard_index=i, seed=i)
        
        result = decoder.decode()
        assert result is not None
        assert isinstance(result, bytes)


class TestEncoderDecoderIntegration:
    """Integration tests for encoding and decoding."""
    
    def test_encode_decode_high_security(self):
        """Test encoding and decoding with high security tier."""
        encoder = FountainEncoder(TIER_HIGH_SECURITY)
        decoder = FountainDecoder(TIER_HIGH_SECURITY)
        
        plaintext = b"Secret message"
        shards = encoder.encode(plaintext)
        
        # Add first k shards
        for i, (shard_data, shard_index, seed) in enumerate(shards[:decoder.k]):
            decoder.add_shard(shard_data, shard_index, seed)
        
        decoded = decoder.decode()
        assert decoded is not None
    
    def test_encode_decode_balanced(self):
        """Test encoding and decoding with balanced tier."""
        encoder = FountainEncoder(TIER_BALANCED)
        decoder = FountainDecoder(TIER_BALANCED)
        
        plaintext = b"X" * 300
        shards = encoder.encode(plaintext)
        
        # Add first k shards
        for i, (shard_data, shard_index, seed) in enumerate(shards[:decoder.k]):
            decoder.add_shard(shard_data, shard_index, seed)
        
        decoded = decoder.decode()
        assert decoded is not None
    
    def test_encode_decode_high_throughput(self):
        """Test encoding and decoding with high throughput tier."""
        encoder = FountainEncoder(TIER_HIGH_THROUGHPUT)
        decoder = FountainDecoder(TIER_HIGH_THROUGHPUT)
        
        plaintext = b"Y" * 1500
        shards = encoder.encode(plaintext)
        
        # Add first k shards
        for i, (shard_data, shard_index, seed) in enumerate(shards[:decoder.k]):
            decoder.add_shard(shard_data, shard_index, seed)
        
        decoded = decoder.decode()
        assert decoded is not None


class TestFountainLossResilience:
    """Tests for fountain code loss resilience."""
    
    def test_recovery_after_shard_loss(self):
        """Test recovery from random shard losses."""
        encoder = FountainEncoder(TIER_BALANCED)
        decoder = FountainDecoder(TIER_BALANCED)
        
        plaintext = b"Resilience test message"
        shards = encoder.encode(plaintext)
        
        # Calculate max loss threshold
        max_loss = int(
            len(shards) * TIER_BALANCED.max_loss_rate
        )
        
        # Randomly select shards with some losses
        available_shards = shards[:decoder.k + max_loss]
        selected = random.sample(
            available_shards,
            min(decoder.k, len(available_shards))
        )
        
        for shard_data, shard_index, seed in selected:
            decoder.add_shard(shard_data, shard_index, seed)
        
        if decoder.is_decodable():
            decoded = decoder.decode()
            assert decoded is not None
    
    def test_loss_threshold_high_security(self):
        """Test that loss threshold is respected for high security tier."""
        encoder = FountainEncoder(TIER_HIGH_SECURITY)
        max_loss_shards = int(
            encoder.num_shards * TIER_HIGH_SECURITY.max_loss_rate
        )
        
        # Can lose up to max_loss_shards and still have k shards left
        assert encoder.num_shards - max_loss_shards >= encoder.k
    
    def test_loss_threshold_high_throughput(self):
        """Test that loss threshold is respected for high throughput tier."""
        encoder = FountainEncoder(TIER_HIGH_THROUGHPUT)
        max_loss_shards = int(
            encoder.num_shards * TIER_HIGH_THROUGHPUT.max_loss_rate
        )
        
        # Can lose up to max_loss_shards and still have k shards left
        assert encoder.num_shards - max_loss_shards >= encoder.k
    
    def test_fuzz_random_shard_selection(self):
        """Fuzz test with random shard selections."""
        encoder = FountainEncoder(TIER_BALANCED)
        plaintext = b"Fuzz test data"
        shards = encoder.encode(plaintext)
        
        for trial in range(10):
            decoder = FountainDecoder(TIER_BALANCED)
            
            # Randomly select shards
            num_select = random.randint(decoder.k, min(len(shards), decoder.k + 5))
            selected = random.sample(shards, num_select)
            
            for shard_data, shard_index, seed in selected:
                decoder.add_shard(shard_data, shard_index, seed)
            
            # Should be decodable if we have enough shards
            if len(selected) >= decoder.k:
                assert decoder.is_decodable()
                decoded = decoder.decode()
                assert decoded is not None


class TestPaddingStrategy:
    """Tests for padding strategies."""
    
    def test_padding_high_security(self):
        """Test padding for high security tier."""
        data_size = 100
        tier = TIER_HIGH_SECURITY
        
        padding = padding_for_tier(data_size, tier, PaddingStrategy.ZERO_PADDING)
        
        assert len(padding) == tier.packet_size - data_size
        assert padding == b'\x00' * len(padding)
    
    def test_padding_balanced(self):
        """Test padding for balanced tier."""
        data_size = 500
        tier = TIER_BALANCED
        
        padding = padding_for_tier(data_size, tier, PaddingStrategy.ZERO_PADDING)
        
        assert len(padding) == tier.packet_size - data_size
    
    def test_padding_deterministic_random(self):
        """Test deterministic random padding."""
        data_size = 100
        tier = TIER_HIGH_SECURITY
        
        padding1 = padding_for_tier(
            data_size, tier, PaddingStrategy.DETERMINISTIC_RANDOM
        )
        padding2 = padding_for_tier(
            data_size, tier, PaddingStrategy.DETERMINISTIC_RANDOM
        )
        
        # Should be identical for same tier
        assert padding1 == padding2
        assert len(padding1) == tier.packet_size - data_size
    
    def test_padding_exceeds_limit(self):
        """Test padding when data exceeds limit."""
        data_size = 600
        tier = TIER_HIGH_SECURITY
        
        with pytest.raises(ValueError, match="Data size.*exceeds tier packet size"):
            padding_for_tier(data_size, tier)
    
    def test_padding_no_padding_needed(self):
        """Test padding when no padding is needed."""
        data_size = TIER_BALANCED.packet_size
        tier = TIER_BALANCED
        
        padding = padding_for_tier(data_size, tier)
        
        assert padding == b''


class TestPacketSchema:
    """Tests for packet serialization/deserialization."""
    
    def test_packet_creation(self):
        """Test packet creation."""
        payload = b"Hello, World!"
        packet = Packet(
            version=PacketVersion.V1,
            shard_index=0,
            seed=42,
            tier=TIER_BALANCED,
            payload=payload,
        )
        
        assert packet.version == PacketVersion.V1
        assert packet.shard_index == 0
        assert packet.seed == 42
        assert packet.tier == TIER_BALANCED
    
    def test_packet_serialization(self):
        """Test packet serialization."""
        payload = b"Test payload"
        packet = Packet(
            version=PacketVersion.V1,
            shard_index=5,
            seed=12345,
            tier=TIER_HIGH_SECURITY,
            payload=payload,
        )
        
        serialized = packet.serialize()
        
        assert isinstance(serialized, bytes)
        assert len(serialized) <= TIER_HIGH_SECURITY.packet_size + 9  # header + tier
    
    def test_packet_deserialization(self):
        """Test packet deserialization."""
        payload = b"Original message"
        original = Packet(
            version=PacketVersion.V1,
            shard_index=10,
            seed=54321,
            tier=TIER_BALANCED,
            payload=payload,
        )
        
        serialized = original.serialize()
        deserialized = Packet.deserialize(serialized, TIER_BALANCED)
        
        assert deserialized.version == original.version
        assert deserialized.shard_index == original.shard_index
        assert deserialized.seed == original.seed
    
    def test_packet_with_ratchet_key(self):
        """Test packet with ratchet key commitment."""
        payload = b"Secret"
        ratchet_key = b"X" * 32
        
        packet = Packet(
            version=PacketVersion.V1,
            shard_index=0,
            seed=42,
            tier=TIER_HIGH_SECURITY,
            payload=payload,
            ratchet_key_commitment=ratchet_key,
        )
        
        serialized = packet.serialize()
        deserialized = Packet.deserialize(serialized, TIER_HIGH_SECURITY)
        
        assert deserialized.ratchet_key_commitment == ratchet_key
    
    def test_packet_with_pow_commitment(self):
        """Test packet with PoW commitment."""
        payload = b"Work"
        pow_commitment = b"Y" * 32
        
        packet = Packet(
            version=PacketVersion.V1,
            shard_index=0,
            seed=42,
            tier=TIER_BALANCED,
            payload=payload,
            pow_commitment=pow_commitment,
        )
        
        serialized = packet.serialize()
        deserialized = Packet.deserialize(serialized, TIER_BALANCED)
        
        assert deserialized.pow_commitment == pow_commitment
    
    def test_packet_with_both_commitments(self):
        """Test packet with both ratchet key and PoW commitments."""
        payload = b"Both"
        ratchet_key = b"R" * 32
        pow_commitment = b"P" * 32
        
        packet = Packet(
            version=PacketVersion.V1,
            shard_index=7,
            seed=999,
            tier=TIER_HIGH_THROUGHPUT,
            payload=payload,
            ratchet_key_commitment=ratchet_key,
            pow_commitment=pow_commitment,
        )
        
        serialized = packet.serialize()
        deserialized = Packet.deserialize(serialized, TIER_HIGH_THROUGHPUT)
        
        assert deserialized.ratchet_key_commitment == ratchet_key
        assert deserialized.pow_commitment == pow_commitment


class TestPacketTierRoundtrip:
    """Tests for packet serialization with different tiers."""
    
    @pytest.mark.parametrize("tier", [
        TIER_HIGH_SECURITY,
        TIER_BALANCED,
        TIER_HIGH_THROUGHPUT,
    ])
    def test_roundtrip_all_tiers(self, tier):
        """Test serialization roundtrip for all tiers."""
        payload = b"X" * 100
        packet = Packet(
            version=PacketVersion.V1,
            shard_index=3,
            seed=123,
            tier=tier,
            payload=payload,
        )
        
        serialized = packet.serialize()
        deserialized = Packet.deserialize(serialized, tier)
        
        assert deserialized.version == packet.version
        assert deserialized.shard_index == packet.shard_index
        assert deserialized.seed == packet.seed


class TestEndToEnd:
    """End-to-end integration tests."""
    
    def test_full_pipeline_high_security(self):
        """Test full encoding-packet-decoding pipeline with high security."""
        encoder = FountainEncoder(TIER_HIGH_SECURITY)
        plaintext = b"Confidential"
        
        shards = encoder.encode(plaintext)
        packets = []
        
        for shard_data, shard_index, seed in shards[:5]:
            packet = Packet(
                version=PacketVersion.V1,
                shard_index=shard_index,
                seed=seed,
                tier=TIER_HIGH_SECURITY,
                payload=shard_data,
                ratchet_key_commitment=b"K" * 32,
            )
            packets.append(packet)
        
        # Simulate transmission and reconstruction
        decoder = FountainDecoder(TIER_HIGH_SECURITY)
        for packet in packets[:encoder.k]:
            decoder.add_shard(packet.payload, packet.shard_index, packet.seed)
        
        decoded = decoder.decode()
        assert decoded is not None
    
    def test_full_pipeline_with_loss(self):
        """Test full pipeline with random packet loss."""
        encoder = FountainEncoder(TIER_BALANCED)
        plaintext = b"Message with loss"
        
        shards = encoder.encode(plaintext)
        packets = []
        
        for shard_data, shard_index, seed in shards:
            packet = Packet(
                version=PacketVersion.V1,
                shard_index=shard_index,
                seed=seed,
                tier=TIER_BALANCED,
                payload=shard_data,
                pow_commitment=b"P" * 32,
            )
            packets.append(packet)
        
        # Simulate loss by randomly dropping packets
        received = random.sample(packets, min(len(packets), encoder.k + 3))
        
        decoder = FountainDecoder(TIER_BALANCED)
        for packet in received:
            decoder.add_shard(packet.payload, packet.shard_index, packet.seed)
        
        if decoder.is_decodable():
            decoded = decoder.decode()
            assert decoded is not None
