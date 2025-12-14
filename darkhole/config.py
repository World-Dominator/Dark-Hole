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
"""Configuration management for Darkhole framework."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from enum import Enum
import os


class SecurityLevel(Enum):
    """Security levels for Darkhole operations."""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    MAXIMUM = "maximum"


class NetworkTier(Enum):
    """Network operation tiers."""
    BASIC = "basic"
    STANDARD = "standard"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"


@dataclass
class CryptoConfig:
    """Cryptographic configuration settings."""
    
    algorithm: str = "ChaCha20-Poly1305"
    key_derivation: str = "HKDF-SHA256"
    key_length: int = 32
    nonce_length: int = 12
    security_level: SecurityLevel = SecurityLevel.HIGH
    enable_forward_secrecy: bool = True


@dataclass
class NetworkConfig:
    """Network configuration settings."""
    
    max_connections: int = 100
    connection_timeout: float = 30.0
    retry_attempts: int = 3
    enable_upnp: bool = False
    enable_nat_traversal: bool = True
    port_range: tuple[int, int] = (8080, 8090)


@dataclass
class DHTConfig:
    """Distributed Hash Table configuration."""
    
    bootstrap_nodes: List[str] = field(default_factory=list)
    bucket_size: int = 20
    max_bucket_depth: int = 8
    refresh_interval: float = 3600.0
    timeout: float = 10.0


@dataclass
class RelayConfig:
    """Relay node configuration."""
    
    enable_relay: bool = True
    max_relay_hops: int = 3
    relay_timeout: float = 60.0
    enable_load_balancing: bool = True


@dataclass
class TierConfig:
    """Configuration for different network tiers."""
    
    name: NetworkTier
    crypto: CryptoConfig
    network: NetworkConfig
    dht: DHTConfig
    relay: RelayConfig
    
    # Tier-specific limits
    max_message_size: int = 1024 * 1024  # 1MB
    rate_limit_per_minute: int = 1000
    concurrent_connections: int = 50
    priority_level: int = 1
    
    @classmethod
    def basic(cls) -> TierConfig:
        """Create basic tier configuration."""
        return cls(
            name=NetworkTier.BASIC,
            crypto=CryptoConfig(security_level=SecurityLevel.MEDIUM),
            network=NetworkConfig(max_connections=10),
            dht=DHTConfig(timeout=5.0),
            relay=RelayConfig(max_relay_hops=1),
            max_message_size=64 * 1024,  # 64KB
            rate_limit_per_minute=100,
            concurrent_connections=5,
            priority_level=3,
        )
    
    @classmethod
    def standard(cls) -> TierConfig:
        """Create standard tier configuration."""
        return cls(
            name=NetworkTier.STANDARD,
            crypto=CryptoConfig(security_level=SecurityLevel.HIGH),
            network=NetworkConfig(max_connections=50),
            dht=DHTConfig(timeout=10.0),
            relay=RelayConfig(max_relay_hops=2),
            max_message_size=512 * 1024,  # 512KB
            rate_limit_per_minute=500,
            concurrent_connections=25,
            priority_level=2,
        )
    
    @classmethod
    def premium(cls) -> TierConfig:
        """Create premium tier configuration."""
        return cls(
            name=NetworkTier.PREMIUM,
            crypto=CryptoConfig(security_level=SecurityLevel.HIGH),
            network=NetworkConfig(max_connections=100),
            dht=DHTConfig(timeout=15.0),
            relay=RelayConfig(max_relay_hops=3),
            max_message_size=2 * 1024 * 1024,  # 2MB
            rate_limit_per_minute=2000,
            concurrent_connections=50,
            priority_level=1,
        )
    
    @classmethod
    def enterprise(cls) -> TierConfig:
        """Create enterprise tier configuration."""
        return cls(
            name=NetworkTier.ENTERPRISE,
            crypto=CryptoConfig(security_level=SecurityLevel.MAXIMUM),
            network=NetworkConfig(max_connections=500, enable_upnp=True),
            dht=DHTConfig(timeout=20.0),
            relay=RelayConfig(max_relay_hops=5),
            max_message_size=10 * 1024 * 1024,  # 10MB
            rate_limit_per_minute=10000,
            concurrent_connections=100,
            priority_level=0,
        )


class Config:
    """
    Main configuration manager for Darkhole framework.
    
    Provides centralized configuration management with support for
    different operational tiers and environment-specific overrides.
    """
    
    def __init__(self, tier: NetworkTier = NetworkTier.STANDARD) -> None:
        """
        Initialize configuration manager.
        
        Args:
            tier: Network tier to use for default configurations.
        """
        self.tier = tier
        self._tier_configs: Dict[NetworkTier, TierConfig] = {}
        self._custom_config: Dict[str, Any] = {}
        self._load_defaults()
        
    def _load_defaults(self) -> None:
        """Load default tier configurations."""
        self._tier_configs = {
            NetworkTier.BASIC: TierConfig.basic(),
            NetworkTier.STANDARD: TierConfig.standard(),
            NetworkTier.PREMIUM: TierConfig.premium(),
            NetworkTier.ENTERPRISE: TierConfig.enterprise(),
        }
        
    def get_tier_config(self, tier: Optional[NetworkTier] = None) -> TierConfig:
        """
        Get configuration for specified tier.
        
        Args:
            tier: Network tier. If None, uses current tier.
            
        Returns:
            Tier configuration object.
        """
        tier = tier or self.tier
        if tier not in self._tier_configs:
            # Fallback to standard if tier not found
            tier = NetworkTier.STANDARD
        return self._tier_configs[tier]
        
    def set_custom_config(self, key: str, value: Any) -> None:
        """
        Set custom configuration value.
        
        Args:
            key: Configuration key.
            value: Configuration value.
        """
        self._custom_config[key] = value
        
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value.
        
        Checks custom config first, then falls back to tier config.
        
        Args:
            key: Configuration key.
            default: Default value if key not found.
            
        Returns:
            Configuration value or default.
        """
        # Check custom config first
        if key in self._custom_config:
            return self._custom_config[key]
            
        # Check tier config attributes
        tier_config = self.get_tier_config()
        if hasattr(tier_config, key):
            return getattr(tier_config, key)
            
        return default
        
    def get_from_environment(self, key: str, env_var: str, default: Any = None) -> Any:
        """
        Get configuration value from environment variable or config.
        
        Args:
            key: Configuration key.
            env_var: Environment variable name.
            default: Default value.
            
        Returns:
            Configuration value from environment or config.
        """
        env_value = os.getenv(env_var)
        if env_value is not None:
            return env_value
        return self.get(key, default)
        
    def validate(self) -> List[str]:
        """
        Validate current configuration.
        
        Returns:
            List of validation errors. Empty if valid.
        """
        errors = []
        tier_config = self.get_tier_config()
        
        # Validate tier config
        if tier_config.max_message_size <= 0:
            errors.append("max_message_size must be positive")
            
        if tier_config.rate_limit_per_minute <= 0:
            errors.append("rate_limit_per_minute must be positive")
            
        if tier_config.concurrent_connections <= 0:
            errors.append("concurrent_connections must be positive")
            
        # Validate crypto config
        crypto = tier_config.crypto
        if crypto.key_length not in [16, 24, 32]:
            errors.append("key_length must be 16, 24, or 32 bytes")
            
        return errors
