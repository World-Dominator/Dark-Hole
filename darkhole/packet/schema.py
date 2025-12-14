"""Versioned packet schema with serialization/deserialization helpers."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from darkhole.config import TrafficTier


class PacketVersion(Enum):
    """Packet format version."""
    
    V1 = 1
    """Version 1: Basic packet with fountain coding."""


@dataclass
class Packet:
    """Packet structure with metadata and payload.
    
    Format (binary):
    - version (1 byte)
    - flags (1 byte)
    - shard_index (2 bytes)
    - seed (4 bytes)
    - tier_id (1 byte)
    - ratchet_key_commitment (32 bytes, optional)
    - pow_commitment (32 bytes, optional)
    - payload (variable, padded to packet_size)
    """
    
    version: PacketVersion
    shard_index: int
    seed: int
    tier: TrafficTier
    payload: bytes
    ratchet_key_commitment: Optional[bytes] = None
    pow_commitment: Optional[bytes] = None
    
    # Flags
    HAS_RATCHET_KEY = 0x01
    HAS_POW = 0x02
    
    HEADER_SIZE = 8  # version(1) + flags(1) + shard_index(2) + seed(4)
    OPTIONAL_FIELDS_SIZE = 64  # ratchet(32) + pow(32)
    
    def serialize(self) -> bytes:
        """Serialize packet to bytes.
        
        Returns:
            Serialized packet bytes.
        """
        flags = 0
        if self.ratchet_key_commitment:
            flags |= self.HAS_RATCHET_KEY
        if self.pow_commitment:
            flags |= self.HAS_POW
        
        # Build header
        header = struct.pack(
            '!BBHI',
            self.version.value,
            flags,
            self.shard_index,
            self.seed,
        )
        
        # Add tier ID
        tier_id = self._tier_to_id(self.tier)
        header += struct.pack('!B', tier_id)
        
        # Add optional fields if present
        optional_data = b''
        if self.ratchet_key_commitment:
            optional_data += self.ratchet_key_commitment
        if self.pow_commitment:
            optional_data += self.pow_commitment
        
        # Ensure payload is correct size
        payload = self.payload
        if len(payload) < self.tier.packet_size - len(header) - len(optional_data):
            payload += b'\x00' * (
                self.tier.packet_size
                - len(header)
                - len(optional_data)
                - len(payload)
            )
        
        return header + optional_data + payload
    
    @staticmethod
    def deserialize(data: bytes, tier: TrafficTier) -> Packet:
        """Deserialize packet from bytes.
        
        Args:
            data: Serialized packet bytes.
            tier: Traffic tier configuration.
            
        Returns:
            Deserialized Packet.
            
        Raises:
            ValueError: If packet is malformed.
        """
        if len(data) < Packet.HEADER_SIZE + 1:
            raise ValueError(f"Packet too short: {len(data)} bytes")
        
        # Parse header
        version_val, flags, shard_index, seed = struct.unpack(
            '!BBHI', data[:Packet.HEADER_SIZE]
        )
        
        version = PacketVersion(version_val)
        
        # Parse tier
        tier_id = data[Packet.HEADER_SIZE]
        parsed_tier = Packet._id_to_tier(tier_id)
        
        offset = Packet.HEADER_SIZE + 1
        
        # Parse optional fields
        ratchet_key_commitment = None
        pow_commitment = None
        
        if flags & Packet.HAS_RATCHET_KEY:
            ratchet_key_commitment = data[offset:offset + 32]
            offset += 32
        
        if flags & Packet.HAS_POW:
            pow_commitment = data[offset:offset + 32]
            offset += 32
        
        # Rest is payload
        payload = data[offset:offset + tier.packet_size]
        
        return Packet(
            version=version,
            shard_index=shard_index,
            seed=seed,
            tier=parsed_tier,
            payload=payload,
            ratchet_key_commitment=ratchet_key_commitment,
            pow_commitment=pow_commitment,
        )
    
    @staticmethod
    def _tier_to_id(tier: TrafficTier) -> int:
        """Convert tier to ID.
        
        Args:
            tier: Traffic tier.
            
        Returns:
            Numeric tier ID.
        """
        tier_map = {
            "high_security": 0,
            "balanced": 1,
            "high_throughput": 2,
        }
        return tier_map.get(tier.name, 1)
    
    @staticmethod
    def _id_to_tier(tier_id: int) -> TrafficTier:
        """Convert tier ID to tier.
        
        Args:
            tier_id: Numeric tier ID.
            
        Returns:
            Traffic tier.
        """
        from darkhole.config import TIER_HIGH_SECURITY, TIER_BALANCED, TIER_HIGH_THROUGHPUT
        
        tier_map = {
            0: TIER_HIGH_SECURITY,
            1: TIER_BALANCED,
            2: TIER_HIGH_THROUGHPUT,
        }
        return tier_map.get(tier_id, TIER_BALANCED)
