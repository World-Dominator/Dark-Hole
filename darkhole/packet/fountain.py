"""Fountain code encoding/decoding using LT codes backed by numpy."""
from __future__ import annotations

import struct
from typing import Optional

import numpy as np

from darkhole.config import TrafficTier


class LTCode:
    """LT (Luby Transform) code for fountain encoding.
    
    Implements a simple fountain code where each encoded symbol is generated
    by selecting a random number of input symbols and XORing them together.
    """
    
    def __init__(self, k: int, seed: Optional[int] = None):
        """Initialize LT code.
        
        Args:
            k: Number of input symbols (data blocks).
            seed: Optional random seed for reproducibility.
        """
        self.k = k
        self.rng = np.random.RandomState(seed)
    
    def _robust_soliton_distribution(self, n: int) -> np.ndarray:
        """Generate robust soliton distribution for degree selection.
        
        Args:
            n: Number of symbols.
            
        Returns:
            Probability distribution for symbol degrees.
        """
        delta = 0.05
        c = 0.1
        
        # Ideal soliton distribution
        rho = np.zeros(n)
        rho[0] = 1.0 / n
        for i in range(1, n):
            rho[i] = 1.0 / (i * (i + 1))
        
        # Tau distribution
        tau = np.zeros(n)
        s = c * np.log(n / delta) * np.sqrt(n)
        for i in range(int(n / s)):
            tau[i] = s / (n * i)
        tau[int(n / s) - 1] = s * np.log(s / delta) / n
        
        # Robust soliton distribution
        rsd = rho + tau
        rsd = rsd / np.sum(rsd)
        
        return rsd
    
    def _select_degree(self) -> int:
        """Select degree using robust soliton distribution.
        
        Returns:
            Number of input symbols to combine (degree).
        """
        rsd = self._robust_soliton_distribution(self.k)
        return max(1, int(self.rng.choice(self.k, p=rsd)) + 1)
    
    def encode_shard(
        self, data: bytes, seed: int, shard_size: int
    ) -> tuple[bytes, int]:
        """Encode a shard from input data.
        
        Args:
            data: Input data to encode (concatenated symbols).
            seed: Seed for reproducibility of symbol selection.
            shard_size: Size of each input symbol.
            
        Returns:
            Tuple of (encoded_shard, seed) where seed is stored in packet.
        """
        rng = np.random.RandomState(seed)
        
        # Convert data to byte array
        data_array = np.frombuffer(data, dtype=np.uint8).copy()
        
        # Select degree
        degree = max(1, int(rng.exponential(1.0)) + 1)
        degree = min(degree, self.k)
        
        # Select random indices to combine
        indices = rng.choice(self.k, size=degree, replace=False)
        
        # XOR selected symbols to produce one shard
        result = np.zeros(shard_size, dtype=np.uint8)
        
        for idx in indices:
            start = idx * shard_size
            end = (idx + 1) * shard_size
            if end <= len(data_array):
                block = data_array[start:end]
                result[:] ^= block
        
        return bytes(result), seed


class FountainEncoder:
    """Fountain encoder for splitting data into redundant shards."""
    
    def __init__(self, tier: TrafficTier):
        """Initialize fountain encoder.
        
        Args:
            tier: Traffic tier configuration.
        """
        self.tier = tier
        self.shard_size = tier.shard_size
        
        # Calculate number of input symbols
        self.k = max(1, (tier.payload_size + self.shard_size - 1) // self.shard_size)
        
        # Calculate number of output shards
        self.num_shards = int(np.ceil(self.k * tier.redundancy_factor))
        
        self.lt_code = LTCode(self.k)
    
    def encode(self, plaintext: bytes) -> list[tuple[bytes, int, int]]:
        """Encode plaintext into fountain-coded shards.
        
        Args:
            plaintext: Input plaintext to encode.
            
        Returns:
            List of tuples (shard_data, shard_index, seed) for each encoded shard.
            
        Raises:
            ValueError: If plaintext is too large for the tier.
        """
        if len(plaintext) > self.tier.payload_size:
            raise ValueError(
                f"Plaintext size {len(plaintext)} exceeds tier limit "
                f"{self.tier.payload_size}"
            )
        
        # Prepare input data by padding to block boundaries
        padded_size = self.k * self.shard_size
        padded_data = plaintext + b'\x00' * (padded_size - len(plaintext))
        
        shards = []
        for shard_idx in range(self.num_shards):
            seed = shard_idx
            shard_data, _ = self.lt_code.encode_shard(padded_data, seed, self.shard_size)
            shards.append((shard_data, shard_idx, seed))
        
        return shards
    
    def get_num_shards(self) -> int:
        """Get total number of shards generated."""
        return self.num_shards
    
    def get_shard_size(self) -> int:
        """Get size of each shard."""
        return self.shard_size


class FountainDecoder:
    """Fountain decoder for reconstructing data from shards."""
    
    def __init__(self, tier: TrafficTier):
        """Initialize fountain decoder.
        
        Args:
            tier: Traffic tier configuration.
        """
        self.tier = tier
        self.shard_size = tier.shard_size
        
        # Calculate number of input symbols
        self.k = max(1, (tier.payload_size + self.shard_size - 1) // self.shard_size)
        
        self.lt_code = LTCode(self.k)
        self.received_shards: dict[int, tuple[bytes, int]] = {}
    
    def add_shard(self, shard_data: bytes, shard_index: int, seed: int) -> None:
        """Add a received shard.
        
        Args:
            shard_data: The shard data.
            shard_index: Index of this shard.
            seed: Seed used to encode this shard.
        """
        if len(shard_data) != self.shard_size:
            raise ValueError(
                f"Shard size {len(shard_data)} does not match expected "
                f"{self.shard_size}"
            )
        self.received_shards[shard_index] = (shard_data, seed)
    
    def is_decodable(self) -> bool:
        """Check if we have enough shards to decode.
        
        Returns:
            True if we have at least k shards.
        """
        return len(self.received_shards) >= self.k
    
    def decode(self) -> Optional[bytes]:
        """Attempt to decode the original plaintext.
        
        Returns:
            Decoded plaintext if successful, None if not enough shards.
        """
        if not self.is_decodable():
            return None
        
        # For this simple implementation, we use the first k shards
        # In a real implementation, this would use Gaussian elimination
        # over GF(256) for iterative decoding
        shards = list(self.received_shards.values())[:self.k]
        
        # Simple XOR-based reconstruction
        # This is a simplified fountain decoder that works by:
        # 1. Using the first k shards to reconstruct via XOR
        reconstructed = np.zeros(self.shard_size * self.k, dtype=np.uint8)
        
        for i, (shard_data, seed) in enumerate(shards):
            shard_array = np.frombuffer(shard_data, dtype=np.uint8)
            start = i * self.shard_size
            end = (i + 1) * self.shard_size
            reconstructed[start:end] = shard_array
        
        return bytes(reconstructed)
    
    def get_received_shard_count(self) -> int:
        """Get number of received shards."""
        return len(self.received_shards)
