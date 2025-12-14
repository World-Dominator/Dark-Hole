"""Unit tests for darkhole.packet module."""

import pytest
import json

from darkhole.packet import (
    Packet, DataPacket, RelayPacket, PacketType, PacketFlags,
    PacketSerializer, PacketError
)


class TestPacketType:
    """Test PacketType enum."""
    
    def test_packet_types(self):
        """Test all packet types are defined."""
        assert PacketType.HELLO.value == "hello"
        assert PacketType.DATA.value == "data"
        assert PacketType.RELAY.value == "relay"
        assert PacketType.PING.value == "ping"
        assert PacketType.PONG.value == "pong"
        assert PacketType.ERROR.value == "error"


class TestPacketFlags:
    """Test PacketFlags constants."""
    
    def test_flags_defined(self):
        """Test all packet flags are defined."""
        assert PacketFlags.ENCRYPTED == 0x01
        assert PacketFlags.COMPRESSED == 0x02
        assert PacketFlags.RELIABLE == 0x04
        assert PacketFlags.BROADCAST == 0x08


class TestPacket:
    """Test base Packet class."""
    
    def test_packet_creation(self):
        """Test creating a basic packet."""
        packet = Packet(
            packet_type=PacketType.DATA,
            source="source_node",
            destination="dest_node",
            payload=b"test_payload"
        )
        
        assert packet.packet_type == PacketType.DATA
        assert packet.source == "source_node"
        assert packet.destination == "dest_node"
        assert packet.payload == b"test_payload"
        assert packet.sequence_number is None
        assert packet.flags == 0
        assert packet.timestamp is not None
    
    def test_packet_creation_minimal(self):
        """Test creating a minimal packet."""
        packet = Packet(
            packet_type=PacketType.PING,
            source="source_node"
        )
        
        assert packet.packet_type == PacketType.PING
        assert packet.source == "source_node"
        assert packet.destination is None
        assert packet.payload is None
        assert packet.timestamp is not None
    
    def test_packet_to_dict(self):
        """Test converting packet to dictionary."""
        packet = Packet(
            packet_type=PacketType.DATA,
            source="source_node",
            destination="dest_node",
            payload=b"test_payload",
            sequence_number=42,
            flags=PacketFlags.ENCRYPTED
        )
        
        packet_dict = packet.to_dict()
        
        assert packet_dict["type"] == "data"
        assert packet_dict["source"] == "source_node"
        assert packet_dict["destination"] == "dest_node"
        assert packet_dict["payload"] == "746573745f7061796c6f6164"  # hex of b"test_payload"
        assert packet_dict["sequence_number"] == 42
        assert packet_dict["flags"] == 1
        assert "timestamp" in packet_dict
    
    def test_packet_from_dict(self):
        """Test creating packet from dictionary."""
        data = {
            "type": "data",
            "source": "source_node",
            "destination": "dest_node",
            "payload": "746573745f7061796c6f6164",
            "sequence_number": 42,
            "flags": 1,
            "timestamp": 1234567890.0
        }
        
        packet = Packet.from_dict(data)
        
        assert packet.packet_type == PacketType.DATA
        assert packet.source == "source_node"
        assert packet.destination == "dest_node"
        assert packet.payload == b"test_payload"
        assert packet.sequence_number == 42
        assert packet.flags == 1
        assert packet.timestamp == 1234567890.0
    
    def test_packet_to_dict_and_back(self):
        """Test round-trip conversion to dict and back."""
        original = Packet(
            packet_type=PacketType.RELAY,
            source="source",
            destination="dest",
            payload=b"relay_data",
            sequence_number=100,
            flags=PacketFlags.RELIABLE | PacketFlags.ENCRYPTED
        )
        
        # Convert to dict and back
        packet_dict = original.to_dict()
        restored = Packet.from_dict(packet_dict)
        
        assert restored.packet_type == original.packet_type
        assert restored.source == original.source
        assert restored.destination == original.destination
        assert restored.payload == original.payload
        assert restored.sequence_number == original.sequence_number
        assert restored.flags == original.flags
        assert restored.timestamp == original.timestamp


class TestDataPacket:
    """Test DataPacket class."""
    
    def test_datapacket_creation(self):
        """Test creating a data packet."""
        packet = DataPacket(
            source="source_node",
            destination="dest_node",
            payload=b"application_data"
        )
        
        assert packet.packet_type == PacketType.DATA
        assert packet.source == "source_node"
        assert packet.destination == "dest_node"
        assert packet.payload == b"application_data"
        assert packet.content_type == "application/octet-stream"
        assert packet.compression is None
    
    def test_datapacket_with_compression(self):
        """Test creating data packet with compression."""
        packet = DataPacket(
            source="source_node",
            destination="dest_node",
            payload=b"compressed_data",
            compression="gzip"
        )
        
        assert packet.compression == "gzip"
    
    def test_datapacket_to_dict(self):
        """Test converting data packet to dictionary."""
        packet = DataPacket(
            source="source_node",
            destination="dest_node",
            payload=b"data",
            content_type="application/json",
            compression="gzip"
        )
        
        packet_dict = packet.to_dict()
        
        assert packet_dict["type"] == "data"
        assert packet_dict["content_type"] == "application/json"
        assert packet_dict["compression"] == "gzip"
    
    def test_datapacket_from_dict(self):
        """Test creating data packet from dictionary."""
        data = {
            "type": "data",
            "source": "source_node",
            "destination": "dest_node",
            "payload": "64617461",
            "content_type": "application/json",
            "compression": "gzip"
        }
        
        packet = DataPacket.from_dict(data)
        
        assert packet.payload == b"data"
        assert packet.content_type == "application/json"
        assert packet.compression == "gzip"


class TestRelayPacket:
    """Test RelayPacket class."""
    
    def test_relaypacket_creation(self):
        """Test creating a relay packet."""
        packet = RelayPacket(
            source="source_node",
            destination="dest_node",
            payload=b"relay_data"
        )
        
        assert packet.packet_type == PacketType.RELAY
        assert packet.source == "source_node"
        assert packet.destination == "dest_node"
        assert packet.payload == b"relay_data"
        assert packet.next_hop is None
        assert packet.relay_path == []
    
    def test_relaypacket_with_hop(self):
        """Test creating relay packet with next hop."""
        packet = RelayPacket(
            source="source_node",
            destination="dest_node",
            data=b"relay_data",
            next_hop="relay_node_1"
        )
        
        assert packet.next_hop == "relay_node_1"
    
    def test_relaypacket_with_path(self):
        """Test creating relay packet with relay path."""
        packet = RelayPacket(
            source="source_node",
            destination="dest_node",
            payload=b"relay_data",
            relay_path=["relay1", "relay2"]
        )
        
        assert packet.relay_path == ["relay1", "relay2"]


class TestPacketError:
    """Test PacketError exception."""
    
    def test_packet_error_inheritance(self):
        """Test that PacketError inherits from Exception."""
        error = PacketError("Test error")
        assert isinstance(error, Exception)
    
    def test_packet_error_message(self):
        """Test PacketError message."""
        error_message = "Packet operation failed"
        error = PacketError(error_message)
        assert str(error) == error_message


class TestPacketSerializer:
    """Test PacketSerializer class."""
    
    def test_serialize_json_basic_packet(self):
        """Test serializing basic packet to JSON."""
        packet = Packet(
            packet_type=PacketType.PING,
            source="node1",
            payload=b"ping_data"
        )
        
        serialized = PacketSerializer.serialize_json(packet)
        
        assert isinstance(serialized, bytes)
        # Should be valid JSON
        data = json.loads(serialized.decode('utf-8'))
        assert data["type"] == "ping"
        assert data["source"] == "node1"
    
    def test_deserialize_json_basic_packet(self):
        """Test deserializing basic packet from JSON."""
        json_data = {
            "type": "pong",
            "source": "node2",
            "payload": "706f6e67",  # hex of b"pong"
            "timestamp": 1234567890.0
        }
        
        serialized = json.dumps(json_data).encode('utf-8')
        packet = PacketSerializer.deserialize_json(serialized)
        
        assert packet.packet_type == PacketType.PONG
        assert packet.source == "node2"
        assert packet.payload == b"pong"
        assert packet.timestamp == 1234567890.0
    
    def test_serialize_and_deserialize_roundtrip(self):
        """Test round-trip serialization and deserialization."""
        original = Packet(
            packet_type=PacketType.DATA,
            source="source",
            destination="dest",
            payload=b"test_data",
            sequence_number=42
        )
        
        serialized = PacketSerializer.serialize_json(original)
        restored = PacketSerializer.deserialize_json(serialized)
        
        assert restored.packet_type == original.packet_type
        assert restored.source == original.source
        assert restored.destination == original.destination
        assert restored.payload == original.payload
        assert restored.sequence_number == original.sequence_number
    
    def test_validate_valid_packet(self):
        """Test validating a valid packet."""
        packet = Packet(
            packet_type=PacketType.HELLO,
            source="valid_source"
        )
        
        result = PacketSerializer.validate_packet(packet)
        assert result is True
    
    def test_validate_packet_missing_source(self):
        """Test validating packet with missing source."""
        packet = Packet(
            packet_type=PacketType.DATA,
            source=""  # Empty source
        )
        
        with pytest.raises(PacketError, match="Packet source is required"):
            PacketSerializer.validate_packet(packet)
    
    def test_validate_packet_missing_type(self):
        """Test validating packet with missing type."""
        packet = Packet(
            packet_type=PacketType.DATA,
            source="source"
        )
        packet.packet_type = None  # Remove type
        
        with pytest.raises(PacketError, match="Packet type is required"):
            PacketSerializer.validate_packet(packet)
    
    def test_validate_datapacket_missing_destination(self):
        """Test validating data packet without destination."""
        packet = DataPacket(
            source="source",
            destination="",  # Empty destination
            data=b"data"
        )
        
        with pytest.raises(PacketError, match="DataPacket requires destination"):
            PacketSerializer.validate_packet(packet)
    
    def test_deserialize_invalid_json(self):
        """Test deserializing invalid JSON."""
        invalid_data = b"{ invalid json "
        
        with pytest.raises(PacketError, match="Failed to deserialize packet"):
            PacketSerializer.deserialize_json(invalid_data)