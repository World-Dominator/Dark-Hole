"""Distributed Hash Table (DHT) implementation for Darkhole.

This module provides a Kademlia-like DHT for peer discovery and
content routing in the Darkhole network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Callable, Any
from enum import Enum
import time
import hashlib


class DHTBucketState(Enum):
    """States for DHT buckets."""
    ACTIVE = "active"
    STALE = "stale"
    REPLACING = "replacing"


@dataclass
class NodeInfo:
    """Information about a DHT node."""
    node_id: str
    address: str
    port: int
    last_seen: float = field(default_factory=time.time)
    is_bootstrap: bool = False
    reputation: float = 1.0
    
    def __post_init__(self) -> None:
        """Validate node info after creation."""
        if not self.node_id:
            raise ValueError("Node ID is required")
        if not self.address:
            raise ValueError("Node address is required")
        if self.port <= 0 or self.port > 65535:
            raise ValueError("Port must be between 1 and 65535")
    
    @property
    def is_active(self) -> bool:
        """Check if node is considered active."""
        return time.time() - self.last_seen < 3600.0  # 1 hour
    
    def distance_to(self, other_id: str) -> int:
        """Calculate XOR distance to another node ID."""
        return int(hashlib.sha256(self.node_id.encode()).hexdigest(), 16) ^ \
               int(hashlib.sha256(other_id.encode()).hexdigest(), 16)


@dataclass
class DHTBucket:
    """Bucket in the DHT routing table."""
    start: int
    end: int
    nodes: List[NodeInfo] = field(default_factory=list)
    state: DHTBucketState = DHTBucketState.ACTIVE
    last_refreshed: float = field(default_factory=time.time)
    
    def __post_init__(self) -> None:
        """Validate bucket after creation."""
        if self.start >= self.end:
            raise ValueError("Bucket start must be less than end")
    
    def add_node(self, node: NodeInfo) -> bool:
        """
        Add a node to this bucket.
        
        Args:
            node: Node to add.
            
        Returns:
            True if node was added, False if bucket is full.
        """
        # Check if node already exists
        for existing in self.nodes:
            if existing.node_id == node.node_id:
                existing.last_seen = node.last_seen
                return True
        
        # Add node if bucket has space
        if len(self.nodes) < 20:  # Bucket size
            self.nodes.append(node)
            return True
        
        # TODO: Implement replacement cache logic
        return False
    
    def remove_node(self, node_id: str) -> bool:
        """Remove a node from this bucket."""
        for i, node in enumerate(self.nodes):
            if node.node_id == node_id:
                del self.nodes[i]
                return True
        return False
    
    def get_active_nodes(self) -> List[NodeInfo]:
        """Get active nodes in this bucket."""
        return [node for node in self.nodes if node.is_active]
    
    def needs_refresh(self) -> bool:
        """Check if bucket needs to be refreshed."""
        return time.time() - self.last_refreshed > 3600.0  # 1 hour


@dataclass
class StoredValue:
    """A value stored in the DHT."""
    key: str
    value: bytes
    timestamp: float = field(default_factory=time.time)
    ttl: float = 3600.0  # 1 hour default TTL
    owner_id: Optional[str] = None
    
    @property
    def is_expired(self) -> bool:
        """Check if this stored value has expired."""
        return time.time() - self.timestamp > self.ttl


class DHTTask(Enum):
    """Tasks that can be performed by the DHT."""
    FIND_NODE = "find_node"
    FIND_VALUE = "find_value"
    STORE_VALUE = "store_value"
    PING = "ping"


class DHTError(Exception):
    """Base exception for DHT operations."""
    pass


class DHT:
    """
    Distributed Hash Table implementation for Darkhole.
    
    Provides peer discovery, content storage, and routing services
    using a Kademlia-like protocol.
    """
    
    def __init__(self, node_id: Optional[str] = None) -> None:
        """
        Initialize DHT.
        
        Args:
            node_id: Unique identifier for this node. If None,
                    a random ID will be generated.
        """
        self.node_id = node_id or self._generate_node_id()
        self.buckets: List[DHTBucket] = self._initialize_buckets()
        self.storage: Dict[str, StoredValue] = {}
        self.bootstrap_nodes: List[NodeInfo] = []
        
    def _generate_node_id(self) -> str:
        """Generate a random node ID."""
        import secrets
        return secrets.token_hex(32)
    
    def _initialize_buckets(self) -> List[DHTBucket]:
        """Initialize the routing table buckets."""
        buckets = []
        # Create 256 buckets covering the full ID space
        for i in range(256):
            buckets.append(DHTBucket(
                start=i * (2**256 // 256),
                end=(i + 1) * (2**256 // 256)
            ))
        return buckets
    
    def add_bootstrap_node(self, address: str, port: int, node_id: Optional[str] = None) -> None:
        """
        Add a bootstrap node for network discovery.
        
        Args:
            address: Bootstrap node address.
            port: Bootstrap node port.
            node_id: Bootstrap node ID if known.
        """
        bootstrap_id = node_id or f"{address}:{port}"
        bootstrap_node = NodeInfo(
            node_id=bootstrap_id,
            address=address,
            port=port,
            is_bootstrap=True
        )
        self.bootstrap_nodes.append(bootstrap_node)
    
    def find_node(self, target_id: str, count: int = 20) -> List[NodeInfo]:
        """
        Find nodes closest to target ID.
        
        Args:
            target_id: Target node ID.
            count: Maximum number of nodes to return.
            
        Returns:
            List of closest nodes.
        """
        # TODO: Implement proper Kademlia find_node
        # For now, return all active nodes from all buckets
        all_nodes: List[NodeInfo] = []
        for bucket in self.buckets:
            all_nodes.extend(bucket.get_active_nodes())
        
        # Sort by distance to target
        all_nodes.sort(key=lambda n: n.distance_to(target_id))
        
        return all_nodes[:count]
    
    def store_value(self, key: str, value: bytes, ttl: float = 3600.0) -> bool:
        """
        Store a value in the DHT.
        
        Args:
            key: Key to store under.
            value: Value to store.
            ttl: Time to live for the value.
            
        Returns:
            True if storage was successful.
        """
        stored_value = StoredValue(
            key=key,
            value=value,
            ttl=ttl,
            owner_id=self.node_id
        )
        self.storage[key] = stored_value
        return True
    
    def find_value(self, key: str) -> Optional[bytes]:
        """
        Find a value in the DHT.
        
        Args:
            key: Key to look up.
            
        Returns:
            Value bytes if found, None otherwise.
        """
        if key in self.storage:
            stored_value = self.storage[key]
            if not stored_value.is_expired:
                return stored_value.value
        
        # Value not found or expired
        return None
    
    def remove_expired_values(self) -> int:
        """
        Remove expired values from storage.
        
        Returns:
            Number of values removed.
        """
        expired_keys = [
            key for key, value in self.storage.items()
            if value.is_expired
        ]
        
        for key in expired_keys:
            del self.storage[key]
        
        return len(expired_keys)
    
    def ping_node(self, node_id: str) -> bool:
        """
        Ping a node to check if it's alive.
        
        Args:
            node_id: ID of node to ping.
            
        Returns:
            True if node responds, False otherwise.
        """
        # TODO: Implement actual ping mechanism
        # For now, check if node exists in routing table
        for bucket in self.buckets:
            for node in bucket.nodes:
                if node.node_id == node_id and node.is_active:
                    return True
        return False
    
    def get_routing_table_stats(self) -> Dict[str, Any]:
        """Get statistics about the routing table."""
        total_nodes = sum(len(bucket.nodes) for bucket in self.buckets)
        active_nodes = sum(len(bucket.get_active_nodes()) for bucket in self.buckets)
        stale_buckets = sum(1 for bucket in self.buckets if bucket.needs_refresh())
        
        return {
            "total_nodes": total_nodes,
            "active_nodes": active_nodes,
            "total_buckets": len(self.buckets),
            "stale_buckets": stale_buckets,
            "stored_values": len(self.storage),
        }
    
    def refresh_bucket(self, bucket_index: int) -> None:
        """
        Refresh a specific bucket.
        
        Args:
            bucket_index: Index of bucket to refresh.
        """
        if 0 <= bucket_index < len(self.buckets):
            self.buckets[bucket_index].last_refreshed = time.time()
            # TODO: Implement actual bucket refresh by finding nodes