"""Unit tests for darkhole.dht module."""

import pytest
import time

from darkhole.dht import (
    DHT, NodeInfo, DHTBucket, StoredValue, DHTBucketState,
    DHTTask, DHTError
)


class TestNodeInfo:
    """Test NodeInfo dataclass."""
    
    def test_nodeinfo_creation(self):
        """Test creating a node info object."""
        node = NodeInfo(
            node_id="test_node_123",
            address="192.168.1.1",
            port=8080
        )
        
        assert node.node_id == "test_node_123"
        assert node.address == "192.168.1.1"
        assert node.port == 8080
        assert node.last_seen > 0
        assert node.is_bootstrap is False
        assert node.reputation == 1.0
    
    def test_nodeinfo_creation_with_bootstrap(self):
        """Test creating a bootstrap node."""
        node = NodeInfo(
            node_id="bootstrap_1",
            address="10.0.0.1",
            port=9000,
            is_bootstrap=True,
            reputation=0.9
        )
        
        assert node.is_bootstrap is True
        assert node.reputation == 0.9
    
    def test_nodeinfo_validation_invalid_id(self):
        """Test node info validation with empty node ID."""
        with pytest.raises(ValueError, match="Node ID is required"):
            NodeInfo(
                node_id="",  # Empty ID
                address="192.168.1.1",
                port=8080
            )
    
    def test_nodeinfo_validation_invalid_address(self):
        """Test node info validation with empty address."""
        with pytest.raises(ValueError, match="Node address is required"):
            NodeInfo(
                node_id="test_node",
                address="",  # Empty address
                port=8080
            )
    
    def test_nodeinfo_validation_invalid_port(self):
        """Test node info validation with invalid port."""
        with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
            NodeInfo(
                node_id="test_node",
                address="192.168.1.1",
                port=0  # Invalid port
            )
        
        with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
            NodeInfo(
                node_id="test_node",
                address="192.168.1.1",
                port=70000  # Invalid port
            )
    
    def test_is_active_property(self):
        """Test is_active property."""
        # Fresh node should be active
        node = NodeInfo(
            node_id="test_node",
            address="192.168.1.1",
            port=8080
        )
        assert node.is_active is True
        
        # Old node should not be active
        old_node = NodeInfo(
            node_id="old_node",
            address="192.168.1.1",
            port=8080
        )
        old_node.last_seen = time.time() - 7200  # 2 hours ago
        assert old_node.is_active is False
    
    def test_distance_to(self):
        """Test distance calculation to another node."""
        node1 = NodeInfo(
            node_id="node1",
            address="192.168.1.1",
            port=8080
        )
        
        node2 = NodeInfo(
            node_id="node2",
            address="192.168.1.2",
            port=8080
        )
        
        distance = node1.distance_to(node2.node_id)
        assert isinstance(distance, int)
        assert distance >= 0


class TestDHTBucket:
    """Test DHTBucket dataclass."""
    
    def test_bucket_creation(self):
        """Test creating a DHT bucket."""
        bucket = DHTBucket(start=0, end=100)
        
        assert bucket.start == 0
        assert bucket.end == 100
        assert bucket.nodes == []
        assert bucket.state == DHTBucketState.ACTIVE
        assert bucket.nodes == []
    
    def test_bucket_validation_invalid_range(self):
        """Test bucket validation with invalid range."""
        with pytest.raises(ValueError, match="Bucket start must be less than end"):
            DHTBucket(start=100, end=0)  # Start >= end
    
    def test_add_node(self):
        """Test adding node to bucket."""
        bucket = DHTBucket(start=0, end=100)
        node = NodeInfo(
            node_id="test_node",
            address="192.168.1.1",
            port=8080
        )
        
        result = bucket.add_node(node)
        assert result is True
        assert len(bucket.nodes) == 1
        assert bucket.nodes[0] == node
    
    def test_add_node_duplicate(self):
        """Test adding duplicate node to bucket."""
        bucket = DHTBucket(start=0, end=100)
        node = NodeInfo(
            node_id="test_node",
            address="192.168.1.1",
            port=8080
        )
        
        # Add twice
        bucket.add_node(node)
        bucket.add_node(node)
        
        # Should still only have one node
        assert len(bucket.nodes) == 1
        # But last_seen should be updated
        assert bucket.nodes[0].last_seen > 0
    
    def test_add_node_bucket_full(self):
        """Test adding node when bucket is full."""
        bucket = DHTBucket(start=0, end=100)
        
        # Add 20 nodes to fill the bucket
        for i in range(20):
            node = NodeInfo(
                node_id=f"node_{i}",
                address=f"192.168.1.{i}",
                port=8080
            )
            bucket.add_node(node)
        
        # Try to add one more
        extra_node = NodeInfo(
            node_id="extra_node",
            address="192.168.1.100",
            port=8080
        )
        
        result = bucket.add_node(extra_node)
        assert result is False
        assert len(bucket.nodes) == 20
    
    def test_remove_node(self):
        """Test removing node from bucket."""
        bucket = DHTBucket(start=0, end=100)
        node = NodeInfo(
            node_id="test_node",
            address="192.168.1.1",
            port=8080
        )
        
        bucket.add_node(node)
        assert len(bucket.nodes) == 1
        
        result = bucket.remove_node("test_node")
        assert result is True
        assert len(bucket.nodes) == 0
    
    def test_remove_node_not_found(self):
        """Test removing node that doesn't exist."""
        bucket = DHTBucket(start=0, end=100)
        
        result = bucket.remove_node("nonexistent_node")
        assert result is False
    
    def test_get_active_nodes(self):
        """Test getting active nodes from bucket."""
        bucket = DHTBucket(start=0, end=100)
        
        # Add active node
        active_node = NodeInfo(
            node_id="active_node",
            address="192.168.1.1",
            port=8080
        )
        bucket.add_node(active_node)
        
        # Add inactive node
        inactive_node = NodeInfo(
            node_id="inactive_node",
            address="192.168.1.2",
            port=8080
        )
        inactive_node.last_seen = time.time() - 7200  # 2 hours ago
        bucket.add_node(inactive_node)
        
        active_nodes = bucket.get_active_nodes()
        assert len(active_nodes) == 1
        assert active_nodes[0].node_id == "active_node"
    
    def test_needs_refresh(self):
        """Test bucket refresh requirement."""
        bucket = DHTBucket(start=0, end=100)
        
        # Fresh bucket should not need refresh
        assert bucket.needs_refresh() is False
        
        # Old bucket should need refresh
        bucket.last_refreshed = time.time() - 7200  # 2 hours ago
        assert bucket.needs_refresh() is True


class TestStoredValue:
    """Test StoredValue dataclass."""
    
    def test_stored_value_creation(self):
        """Test creating a stored value."""
        value = StoredValue(
            key="test_key",
            value=b"test_value"
        )
        
        assert value.key == "test_key"
        assert value.value == b"test_value"
        assert value.timestamp > 0
        assert value.ttl == 3600.0  # Default 1 hour
        assert value.owner_id is None
    
    def test_stored_value_creation_with_ttl(self):
        """Test creating stored value with custom TTL."""
        value = StoredValue(
            key="test_key",
            value=b"test_value",
            ttl=1800.0,  # 30 minutes
            owner_id="owner_node"
        )
        
        assert value.ttl == 1800.0
        assert value.owner_id == "owner_node"
    
    def test_is_expired(self):
        """Test expiration checking."""
        # Fresh value should not be expired
        value = StoredValue(
            key="test_key",
            value=b"test_value",
            ttl=3600.0
        )
        assert value.is_expired is False
        
        # Old value should be expired
        old_value = StoredValue(
            key="test_key",
            value=b"test_value",
            ttl=3600.0
        )
        old_value.timestamp = time.time() - 7200  # 2 hours ago
        assert old_value.is_expired is True


class TestDHT:
    """Test DHT class."""
    
    @pytest.fixture
    def dht(self):
        """Create a DHT instance for testing."""
        return DHT(node_id="test_dht_node")
    
    def test_dht_creation(self):
        """Test creating a DHT instance."""
        dht = DHT()
        
        assert dht.node_id is not None
        assert len(dht.buckets) == 256
        assert dht.storage == {}
        assert len(dht.bootstrap_nodes) == 0
    
    def test_dht_creation_with_custom_id(self):
        """Test creating DHT with custom node ID."""
        dht = DHT(node_id="custom_node_123")
        assert dht.node_id == "custom_node_123"
    
    def test_add_bootstrap_node(self):
        """Test adding bootstrap node."""
        dht = DHT()
        
        dht.add_bootstrap_node("10.0.0.1", 8080, "bootstrap_1")
        
        assert len(dht.bootstrap_nodes) == 1
        bootstrap_node = list(dht.bootstrap_nodes)[0]
        assert bootstrap_node.address == "10.0.0.1"
        assert bootstrap_node.port == 8080
        assert bootstrap_node.node_id == "bootstrap_1"
        assert bootstrap_node.is_bootstrap is True
    
    def test_add_bootstrap_node_auto_id(self):
        """Test adding bootstrap node with auto-generated ID."""
        dht = DHT()
        
        dht.add_bootstrap_node("10.0.0.1", 8080)
        
        assert len(dht.bootstrap_nodes) == 1
        bootstrap_node = list(dht.bootstrap_nodes)[0]
        assert bootstrap_node.node_id == "10.0.0.1:8080"
    
    def test_find_node(self):
        """Test finding nodes."""
        dht = DHT(node_id="test_node")
        
        # Add some nodes to buckets
        for i in range(5):
            node = NodeInfo(
                node_id=f"node_{i}",
                address=f"192.168.1.{i}",
                port=8080
            )
            # Manually add to a bucket for testing
            if dht.buckets:
                dht.buckets[0].add_node(node)
        
        nodes = dht.find_node("target_node")
        
        # Should return nodes (implementation returns all active nodes currently)
        assert isinstance(nodes, list)
    
    def test_store_value(self):
        """Test storing a value."""
        dht = DHT()
        
        result = dht.store_value("test_key", b"test_value")
        assert result is True
        assert "test_key" in dht.storage
        
        stored_value = dht.storage["test_key"]
        assert stored_value.key == "test_key"
        assert stored_value.value == b"test_value"
        assert stored_value.owner_id == dht.node_id
    
    def test_store_value_with_ttl(self):
        """Test storing value with custom TTL."""
        dht = DHT()
        
        dht.store_value("test_key", b"test_value", ttl=1800.0)
        
        stored_value = dht.storage["test_key"]
        assert stored_value.ttl == 1800.0
    
    def test_find_value_existing(self):
        """Test finding an existing value."""
        dht = DHT()
        
        # Store a value
        dht.store_value("test_key", b"test_value")
        
        # Find it
        result = dht.find_value("test_key")
        assert result == b"test_value"
    
    def test_find_value_not_found(self):
        """Test finding a non-existent value."""
        dht = DHT()
        
        result = dht.find_value("nonexistent_key")
        assert result is None
    
    def test_find_value_expired(self):
        """Test finding an expired value."""
        dht = DHT()
        
        # Store a value
        dht.store_value("test_key", b"test_value")
        
        # Make it expired
        stored_value = dht.storage["test_key"]
        stored_value.timestamp = time.time() - 7200  # 2 hours ago
        
        # Should not find it
        result = dht.find_value("test_key")
        assert result is None
    
    def test_remove_expired_values(self):
        """Test removing expired values."""
        dht = DHT()
        
        # Store some values
        dht.store_value("valid_key", b"valid_value")
        
        # Store expired value
        dht.store_value("expired_key", b"expired_value")
        expired_value = dht.storage["expired_key"]
        expired_value.timestamp = time.time() - 7200  # 2 hours ago
        
        # Remove expired values
        removed_count = dht.remove_expired_values()
        
        assert removed_count == 1
        assert "valid_key" in dht.storage
        assert "expired_key" not in dht.storage
    
    def test_ping_node_existing(self):
        """Test pinging an existing node."""
        dht = DHT()
        
        # Add a node to routing table
        node = NodeInfo(
            node_id="test_node",
            address="192.168.1.1",
            port=8080
        )
        if dht.buckets:
            dht.buckets[0].add_node(node)
        
        result = dht.ping_node("test_node")
        assert result is True
    
    def test_ping_node_not_found(self):
        """Test pinging a non-existent node."""
        dht = DHT()
        
        result = dht.ping_node("nonexistent_node")
        assert result is False
    
    def test_get_routing_table_stats(self):
        """Test getting routing table statistics."""
        dht = DHT()
        
        # Add some nodes
        for i in range(3):
            node = NodeInfo(
                node_id=f"node_{i}",
                address=f"192.168.1.{i}",
                port=8080
            )
            if dht.buckets:
                dht.buckets[0].add_node(node)
        
        # Store some values
        dht.store_value("key1", b"value1")
        dht.store_value("key2", b"value2")
        
        stats = dht.get_routing_table_stats()
        
        assert "total_nodes" in stats
        assert "active_nodes" in stats
        assert "total_buckets" in stats
        assert "stored_values" in stats
        assert stats["total_buckets"] == 256
        assert stats["stored_values"] == 2
    
    def test_refresh_bucket(self):
        """Test refreshing a bucket."""
        dht = DHT()
        
        # Refresh bucket 0
        dht.refresh_bucket(0)
        
        # Check that refresh time was updated
        bucket = dht.buckets[0]
        assert bucket.last_refreshed > time.time() - 10  # Should be recent
    
    def test_refresh_bucket_invalid_index(self):
        """Test refreshing bucket with invalid index."""
        dht = DHT()
        
        # Should not raise an error, just do nothing
        dht.refresh_bucket(999)
        dht.refresh_bucket(-1)