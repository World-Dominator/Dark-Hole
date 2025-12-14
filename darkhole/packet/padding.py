"""Padding strategies for constant-length frames and timing obfuscation."""
from __future__ import annotations

from enum import Enum

from darkhole.config import TrafficTier


class PaddingStrategy(Enum):
    """Padding strategy for alignment."""
    
    ZERO_PADDING = "zero"
    """Pad with zero bytes."""
    
    RANDOM_PADDING = "random"
    """Pad with random bytes."""
    
    DETERMINISTIC_RANDOM = "deterministic_random"
    """Pad with deterministically random bytes based on tier."""


def padding_for_tier(
    data_size: int,
    tier: TrafficTier,
    strategy: PaddingStrategy = PaddingStrategy.DETERMINISTIC_RANDOM,
) -> bytes:
    """Generate padding to reach tier packet size.
    
    Args:
        data_size: Current data size.
        tier: Traffic tier configuration.
        strategy: Padding strategy to use.
        
    Returns:
        Padding bytes to append.
        
    Raises:
        ValueError: If data already exceeds tier packet size.
    """
    if data_size > tier.packet_size:
        raise ValueError(
            f"Data size {data_size} exceeds tier packet size {tier.packet_size}"
        )
    
    padding_size = tier.packet_size - data_size
    
    if padding_size == 0:
        return b''
    
    if strategy == PaddingStrategy.ZERO_PADDING:
        return b'\x00' * padding_size
    elif strategy == PaddingStrategy.RANDOM_PADDING:
        import os
        return os.urandom(padding_size)
    elif strategy == PaddingStrategy.DETERMINISTIC_RANDOM:
        # Generate deterministic padding based on tier name hash
        import hashlib
        seed = int(
            hashlib.sha256(tier.name.encode()).digest()[:8].hex(),
            16
        )
        rng_seed = seed & 0xffffffff
        
        import numpy as np
        rng = np.random.RandomState(rng_seed)
        return bytes(rng.randint(0, 256, size=padding_size, dtype=np.uint8))
    else:
        raise ValueError(f"Unknown padding strategy: {strategy}")


def compute_padding_metadata(
    plaintext_size: int,
    tier: TrafficTier,
) -> dict:
    """Compute padding metadata for a message.
    
    Args:
        plaintext_size: Size of the plaintext.
        tier: Traffic tier configuration.
        
    Returns:
        Dictionary with padding metadata.
    """
    # After fountain encoding, shards are tier.shard_size each
    # Total encoded size is (num_shards * shard_size)
    num_shards = tier.shard_size
    
    return {
        "plaintext_size": plaintext_size,
        "padding_size": tier.packet_size - plaintext_size,
        "total_packet_size": tier.packet_size,
    }
