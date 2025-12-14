"""Relay node functionality for Darkhole network.

This module provides relay services for forwarding packets
through the Darkhole network when direct connections aren't possible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum
import time
import uuid


class RelayState(Enum):
    """States for relay operations."""
    IDLE = "idle"
    CONNECTING = "connecting"
    ACTIVE = "active"
    FAILED = "failed"
    EXPIRED = "expired"


class RelayStrategy(Enum):
    """Strategies for relay path selection."""
    SHORTEST = "shortest"
    FASTEST = "fastest"
    LOAD_BALANCED = "load_balanced"
    RANDOM = "random"


@dataclass
class RelayPath:
    """A relay path through the network."""
    path_id: str
    source: str
    destination: str
    hops: List[str] = field(default_factory=list)
    state: RelayState = RelayState.IDLE
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    latency: float = 0.0
    reliability: float = 1.0
    bandwidth_limit: Optional[int] = None
    
    @property
    def path_length(self) -> int:
        """Get the number of hops in this path."""
        return len(self.hops)
    
    @property
    def is_active(self) -> bool:
        """Check if this path is currently active."""
        return self.state == RelayState.ACTIVE
    
    def add_hop(self, hop: str) -> None:
        """Add a hop to the path."""
        self.hops.append(hop)
        self.last_used = time.time()
    
    def update_metrics(self, latency: float, success: bool) -> None:
        """Update path performance metrics."""
        # Exponential moving average for latency
        if self.latency == 0:
            self.latency = latency
        else:
            self.latency = 0.7 * self.latency + 0.3 * latency
        
        # Update reliability
        if success:
            self.reliability = min(1.0, self.reliability * 1.01)
        else:
            self.reliability = max(0.0, self.reliability * 0.99)
        
        self.last_used = time.time()


@dataclass
class RelayNode:
    """Information about a relay node."""
    node_id: str
    address: str
    port: int
    load: float = 0.0
    capacity: int = 100
    is_active: bool = True
    last_seen: float = field(default_factory=time.time)
    latency: float = 0.0
    
    @property
    def available_capacity(self) -> int:
        """Get available relay capacity."""
        return max(0, self.capacity - int(self.load))
    
    def update_load(self, load: float) -> None:
        """Update the node's load."""
        self.load = max(0.0, min(1.0, load))
        self.last_seen = time.time()


@dataclass
class RelayRequest:
    """A relay request to be processed."""
    request_id: str
    source: str
    destination: str
    data: bytes
    priority: int = 0
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 60.0)
    
    @property
    def is_expired(self) -> bool:
        """Check if this request has expired."""
        return time.time() > self.expires_at


class RelayError(Exception):
    """Base exception for relay operations."""
    pass


class RelayManager:
    """
    Relay service manager for Darkhole network.
    
    Provides packet relay services for connections that cannot
    establish direct communication.
    """
    
    def __init__(self, node_id: Optional[str] = None) -> None:
        """
        Initialize relay manager.
        
        Args:
            node_id: Unique identifier for this relay node.
        """
        self.node_id = node_id or str(uuid.uuid4())
        self.relay_paths: Dict[str, RelayPath] = {}
        self.relay_nodes: Dict[str, RelayNode] = {}
        self.pending_requests: Dict[str, RelayRequest] = {}
        self.active_relays: int = 0
        self.total_relays: int = 0
        
    def register_relay_node(self, node_id: str, address: str, port: int, 
                          capacity: int = 100) -> None:
        """
        Register a relay node in the network.
        
        Args:
            node_id: Unique identifier for the relay node.
            address: Node's network address.
            port: Node's network port.
            capacity: Maximum number of simultaneous relays.
        """
        relay_node = RelayNode(
            node_id=node_id,
            address=address,
            port=port,
            capacity=capacity
        )
        self.relay_nodes[node_id] = relay_node
    
    def create_relay_path(self, source: str, destination: str,
                         strategy: RelayStrategy = RelayStrategy.SHORTEST,
                         max_hops: int = 5) -> Optional[RelayPath]:
        """
        Create a relay path from source to destination.
        
        Args:
            source: Source node identifier.
            destination: Destination node identifier.
            strategy: Strategy for path selection.
            max_hops: Maximum number of relay hops.
            
        Returns:
            RelayPath if successful, None otherwise.
        """
        path_id = str(uuid.uuid4())
        relay_path = RelayPath(
            path_id=path_id,
            source=source,
            destination=destination
        )
        
        # Select relay nodes based on strategy
        selected_hops = self._select_relay_hops(
            destination, strategy, max_hops - 1
        )
        
        if not selected_hops:
            return None
        
        # Add hops to path
        for hop in selected_hops:
            relay_path.add_hop(hop)
        
        # Set initial state
        relay_path.state = RelayState.CONNECTING
        
        # Store the path
        self.relay_paths[path_id] = relay_path
        self.total_relays += 1
        
        # TODO: Establish actual connections to relay nodes
        
        return relay_path
    
    def _select_relay_hops(self, destination: str, strategy: RelayStrategy,
                          max_hops: int) -> List[str]:
        """
        Select relay nodes for a path based on strategy.
        
        Args:
            destination: Destination node.
            strategy: Selection strategy.
            max_hops: Maximum number of hops to select.
            
        Returns:
            List of selected relay node IDs.
        """
        available_nodes = [
            node for node in self.relay_nodes.values()
            if node.is_active and node.available_capacity > 0
        ]
        
        if not available_nodes:
            return []
        
        selected_hops = []
        
        for _ in range(min(max_hops, len(available_nodes))):
            if not available_nodes:
                break
            
            # Select node based on strategy
            if strategy == RelayStrategy.SHORTEST:
                # Select node with lowest load
                selected = min(available_nodes, key=lambda n: n.load)
            elif strategy == RelayStrategy.FASTEST:
                # Select node with lowest latency
                selected = min(available_nodes, key=lambda n: n.latency)
            elif strategy == RelayStrategy.LOAD_BALANCED:
                # Select node with best capacity/load ratio
                selected = max(available_nodes, key=lambda n: n.available_capacity)
            else:  # RANDOM
                import random
                selected = random.choice(available_nodes)
            
            selected_hops.append(selected.node_id)
            available_nodes.remove(selected)
        
        return selected_hops
    
    def relay_packet(self, path_id: str, data: bytes) -> bool:
        """
        Relay a packet through a specified path.
        
        Args:
            path_id: ID of the relay path to use.
            data: Packet data to relay.
            
        Returns:
            True if relay was successful.
            
        Raises:
            RelayError: If relay fails.
        """
        if path_id not in self.relay_paths:
            raise RelayError(f"Relay path {path_id} not found")
        
        path = self.relay_paths[path_id]
        
        if not path.is_active:
            raise RelayError(f"Relay path {path_id} is not active")
        
        # TODO: Implement actual packet forwarding
        # For now, simulate success
        path.last_used = time.time()
        self.active_relays += 1
        
        # Update path metrics (simulated)
        path.update_metrics(50.0, True)  # 50ms latency, success
        
        return True
    
    def expire_old_requests(self) -> int:
        """
        Remove expired relay requests.
        
        Returns:
            Number of requests that expired.
        """
        current_time = time.time()
        expired_count = 0
        
        expired_keys = [
            key for key, request in self.pending_requests.items()
            if current_time > request.expires_at
        ]
        
        for key in expired_keys:
            del self.pending_requests[key]
            expired_count += 1
        
        return expired_count
    
    def get_path_stats(self, path_id: str) -> Optional[Dict[str, Any]]:
        """
        Get statistics for a relay path.
        
        Args:
            path_id: ID of the relay path.
            
        Returns:
            Dictionary with path statistics or None if not found.
        """
        if path_id not in self.relay_paths:
            return None
        
        path = self.relay_paths[path_id]
        
        return {
            "path_id": path.path_id,
            "source": path.source,
            "destination": path.destination,
            "hops": len(path.hops),
            "state": path.state.value,
            "latency": path.latency,
            "reliability": path.reliability,
            "created_at": path.created_at,
            "last_used": path.last_used,
        }
    
    def get_network_stats(self) -> Dict[str, Any]:
        """
        Get overall relay network statistics.
        
        Returns:
            Dictionary with network statistics.
        """
        total_paths = len(self.relay_paths)
        active_paths = sum(1 for path in self.relay_paths.values() if path.is_active)
        
        total_nodes = len(self.relay_nodes)
        active_nodes = sum(1 for node in self.relay_nodes.values() if node.is_active)
        
        avg_latency = 0.0
        if self.relay_paths:
            total_latency = sum(path.latency for path in self.relay_paths.values())
            avg_latency = total_latency / len(self.relay_paths)
        
        return {
            "total_paths": total_paths,
            "active_paths": active_paths,
            "total_nodes": total_nodes,
            "active_nodes": active_nodes,
            "avg_latency": avg_latency,
            "total_relays": self.total_relays,
            "pending_requests": len(self.pending_requests),
        }