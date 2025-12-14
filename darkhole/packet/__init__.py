"""Packet handling and serialization for Darkhole framework.

This module provides packet structures and serialization/deserialization
functionality for network communication.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from enum import Enum
import json
import time


class PacketType(Enum):
    """Types of packets in the Darkhole protocol."""
    HELLO = "hello"
    DATA = "data"
    RELAY = "relay"
    PING = "ping"
    PONG = "pong"
    ERROR = "error"


class PacketFlags:
    """Packet flag constants."""
    ENCRYPTED = 0x01
    COMPRESSED = 0x02
    RELIABLE = 0x04
    BROADCAST = 0x08


@dataclass
class Packet:
    """
    Base packet structure for Darkhole network communication.
    
    Represents a network packet with headers, payload, and metadata
    for routing and processing.
    """
    
    packet_type: PacketType
    source: str
    destination: Optional[str] = None
    payload: Optional[bytes] = None
    sequence_number: Optional[int] = None
    flags: int = 0
    timestamp: Optional[float] = None
    
    def __post_init__(self) -> None:
        """Initialize packet after creation."""
        if self.timestamp is None:
            self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to dictionary representation."""
        return {
            "type": self.packet_type.value,
            "source": self.source,
            "destination": self.destination,
            "payload": self.payload.hex() if self.payload else None,
            "sequence_number": self.sequence_number,
            "flags": self.flags,
            "timestamp": self.timestamp,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Packet:
        """Create packet from dictionary representation."""
        return cls(
            packet_type=PacketType(data["type"]),
            source=data["source"],
            destination=data.get("destination"),
            payload=bytes.fromhex(data["payload"]) if data.get("payload") else None,
            sequence_number=data.get("sequence_number"),
            flags=data.get("flags", 0),
            timestamp=data.get("timestamp"),
        )


@dataclass
class DataPacket(Packet):
    """Packet for transmitting application data."""
    
    content_type: str = "application/octet-stream"
    compression: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Initialize data packet after creation."""
        super().__post_init__()
        if self.packet_type != PacketType.DATA:
            raise ValueError("DataPacket must have DATA packet type")


@dataclass
class RelayPacket(Packet):
    """Packet for relay node operations."""
    
    next_hop: Optional[str] = None
    relay_path: list[str] = None
    
    def __post_init__(self) -> None:
        """Initialize relay packet after creation."""
        super().__post_init__()
        if self.packet_type != PacketType.RELAY:
            raise ValueError("RelayPacket must have RELAY packet type")
        if self.relay_path is None:
            self.relay_path = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert relay packet to dictionary representation."""
        data = super().to_dict()
        data["next_hop"] = self.next_hop
        data["relay_path"] = self.relay_path
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RelayPacket:
        """Create relay packet from dictionary representation."""
        return cls(
            packet_type=PacketType(data["type"]),
            source=data["source"],
            destination=data.get("destination"),
            payload=bytes.fromhex(data["payload"]) if data.get("payload") else None,
            sequence_number=data.get("sequence_number"),
            flags=data.get("flags", 0),
            timestamp=data.get("timestamp"),
            next_hop=data.get("next_hop"),
            relay_path=data.get("relay_path", []),
        )


class PacketError(Exception):
    """Base exception for packet operations."""
    pass


class PacketSerializer:
    """
    Serialization and deserialization for Darkhole packets.
    
    Handles conversion between packet objects and binary/string
    representations for network transmission.
    """
    
    @staticmethod
    def serialize_json(packet: Packet) -> bytes:
        """
        Serialize packet to JSON bytes.
        
        Args:
            packet: Packet to serialize.
            
        Returns:
            JSON-encoded bytes.
            
        Raises:
            PacketError: If serialization fails.
        """
        try:
            data = packet.to_dict()
            return json.dumps(data).encode('utf-8')
        except Exception as e:
            raise PacketError(f"Failed to serialize packet: {e}")
    
    @staticmethod
    def deserialize_json(data: bytes) -> Packet:
        """
        Deserialize packet from JSON bytes.
        
        Args:
            data: JSON-encoded packet data.
            
        Returns:
            Deserialized packet object.
            
        Raises:
            PacketError: If deserialization fails.
        """
        try:
            json_data = json.loads(data.decode('utf-8'))
            
            # Determine packet type and create appropriate packet
            packet_type = json_data["type"]
            
            if packet_type == PacketType.DATA.value:
                return DataPacket(
                    packet_type=PacketType.DATA,
                    source=json_data["source"],
                    destination=json_data.get("destination"),
                    payload=bytes.fromhex(json_data["payload"]) if json_data.get("payload") else None,
                    sequence_number=json_data.get("sequence_number"),
                    flags=json_data.get("flags", 0),
                    timestamp=json_data.get("timestamp"),
                    content_type=json_data.get("content_type", "application/octet-stream"),
                    compression=json_data.get("compression"),
                )
            elif packet_type == PacketType.RELAY.value:
                return RelayPacket.from_dict(json_data)
            else:
                return Packet.from_dict(json_data)
                
        except Exception as e:
            raise PacketError(f"Failed to deserialize packet: {e}")
    
    @staticmethod
    def validate_packet(packet: Packet) -> bool:
        """
        Validate packet structure and content.
        
        Args:
            packet: Packet to validate.
            
        Returns:
            True if packet is valid.
            
        Raises:
            PacketError: If packet is invalid.
        """
        if not packet.source:
            raise PacketError("Packet source is required")
            
        if packet.packet_type is None:
            raise PacketError("Packet type is required")
            
        if packet.timestamp is None:
            raise PacketError("Packet timestamp is required")
            
        # Validate specific packet types
        if isinstance(packet, (DataPacket, RelayPacket)):
            if not packet.destination:
                raise PacketError(f"{type(packet).__name__} requires destination")
                
        return True