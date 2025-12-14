"""Configuration for darkhole packet layer and traffic modes."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class TrafficTier:
    """Tiered traffic configuration."""
    
    name: str
    payload_size: int
    """Maximum plaintext payload size in bytes."""
    
    packet_size: int
    """Constant packet size in bytes after padding."""
    
    shard_size: int
    """Size of each shard from fountain encoding in bytes."""
    
    redundancy_factor: float
    """Redundancy factor for fountain encoding (e.g., 1.5 means 50% overhead)."""
    
    max_loss_rate: float
    """Maximum acceptable packet loss rate (0.0-1.0)."""


# Standard traffic tiers
TIER_HIGH_SECURITY: Final[TrafficTier] = TrafficTier(
    name="high_security",
    payload_size=256,
    packet_size=512,
    shard_size=64,
    redundancy_factor=1.5,
    max_loss_rate=0.3,
)

TIER_BALANCED: Final[TrafficTier] = TrafficTier(
    name="balanced",
    payload_size=512,
    packet_size=1024,
    shard_size=128,
    redundancy_factor=1.3,
    max_loss_rate=0.2,
)

TIER_HIGH_THROUGHPUT: Final[TrafficTier] = TrafficTier(
    name="high_throughput",
    payload_size=2048,
    packet_size=4096,
    shard_size=512,
    redundancy_factor=1.2,
    max_loss_rate=0.1,
)

TRAFFIC_TIERS = {
    "high_security": TIER_HIGH_SECURITY,
    "balanced": TIER_BALANCED,
    "high_throughput": TIER_HIGH_THROUGHPUT,
}
