"""Unit tests for darkhole.config module."""

import pytest
import os

from darkhole.config import (
    Config, TierConfig, CryptoConfig, NetworkConfig, DHTConfig, RelayConfig,
    SecurityLevel, NetworkTier
)


class TestSecurityLevel:
    """Test SecurityLevel enum."""
    
    def test_security_levels(self):
        """Test all security levels are defined."""
        assert SecurityLevel.LOW.value == "low"
        assert SecurityLevel.MEDIUM.value == "medium"
        assert SecurityLevel.HIGH.value == "high"
        assert SecurityLevel.MAXIMUM.value == "maximum"


class TestNetworkTier:
    """Test NetworkTier enum."""
    
    def test_network_tiers(self):
        """Test all network tiers are defined."""
        assert NetworkTier.BASIC.value == "basic"
        assert NetworkTier.STANDARD.value == "standard"
        assert NetworkTier.PREMIUM.value == "premium"
        assert NetworkTier.ENTERPRISE.value == "enterprise"


class TestCryptoConfig:
    """Test CryptoConfig dataclass."""
    
    def test_default_config(self):
        """Test default crypto configuration."""
        config = CryptoConfig()
        assert config.algorithm == "ChaCha20-Poly1305"
        assert config.key_derivation == "HKDF-SHA256"
        assert config.key_length == 32
        assert config.nonce_length == 12
        assert config.security_level == SecurityLevel.HIGH
        assert config.enable_forward_secrecy is True
    
    def test_custom_config(self):
        """Test custom crypto configuration."""
        config = CryptoConfig(
            algorithm="AES-256-GCM",
            key_length=64,
            security_level=SecurityLevel.MAXIMUM,
            enable_forward_secrecy=False
        )
        assert config.algorithm == "AES-256-GCM"
        assert config.key_length == 64
        assert config.security_level == SecurityLevel.MAXIMUM
        assert config.enable_forward_secrecy is False


class TestNetworkConfig:
    """Test NetworkConfig dataclass."""
    
    def test_default_config(self):
        """Test default network configuration."""
        config = NetworkConfig()
        assert config.max_connections == 100
        assert config.connection_timeout == 30.0
        assert config.retry_attempts == 3
        assert config.enable_upnp is False
        assert config.enable_nat_traversal is True
        assert config.port_range == (8080, 8090)
    
    def test_custom_config(self):
        """Test custom network configuration."""
        config = NetworkConfig(
            max_connections=500,
            connection_timeout=60.0,
            enable_upnp=True,
            port_range=(9000, 9100)
        )
        assert config.max_connections == 500
        assert config.connection_timeout == 60.0
        assert config.enable_upnp is True
        assert config.port_range == (9000, 9100)


class TestDHTConfig:
    """Test DHTConfig dataclass."""
    
    def test_default_config(self):
        """Test default DHT configuration."""
        config = DHTConfig()
        assert config.bootstrap_nodes == []
        assert config.bucket_size == 20
        assert config.max_bucket_depth == 8
        assert config.refresh_interval == 3600.0
        assert config.timeout == 10.0
    
    def test_custom_config(self):
        """Test custom DHT configuration."""
        config = DHTConfig(
            bootstrap_nodes=["node1", "node2"],
            bucket_size=50,
            timeout=15.0
        )
        assert config.bootstrap_nodes == ["node1", "node2"]
        assert config.bucket_size == 50
        assert config.timeout == 15.0


class TestRelayConfig:
    """Test RelayConfig dataclass."""
    
    def test_default_config(self):
        """Test default relay configuration."""
        config = RelayConfig()
        assert config.enable_relay is True
        assert config.max_relay_hops == 3
        assert config.relay_timeout == 60.0
        assert config.enable_load_balancing is True
    
    def test_custom_config(self):
        """Test custom relay configuration."""
        config = RelayConfig(
            max_relay_hops=5,
            relay_timeout=120.0,
            enable_load_balancing=False
        )
        assert config.max_relay_hops == 5
        assert config.relay_timeout == 120.0
        assert config.enable_load_balancing is False


class TestTierConfig:
    """Test TierConfig dataclass."""
    
    def test_tier_config_creation(self):
        """Test creating a tier configuration."""
        crypto = CryptoConfig()
        network = NetworkConfig()
        dht = DHTConfig()
        relay = RelayConfig()
        
        tier = TierConfig(
            name=NetworkTier.STANDARD,
            crypto=crypto,
            network=network,
            dht=dht,
            relay=relay
        )
        
        assert tier.name == NetworkTier.STANDARD
        assert tier.crypto == crypto
        assert tier.network == network
        assert tier.dht == dht
        assert tier.relay == relay
        assert tier.max_message_size == 1024 * 1024  # Default 1MB
    
    def test_basic_tier(self):
        """Test basic tier configuration."""
        tier = TierConfig.basic()
        
        assert tier.name == NetworkTier.BASIC
        assert tier.crypto.security_level == SecurityLevel.MEDIUM
        assert tier.network.max_connections == 10
        assert tier.max_message_size == 64 * 1024  # 64KB
        assert tier.rate_limit_per_minute == 100
    
    def test_standard_tier(self):
        """Test standard tier configuration."""
        tier = TierConfig.standard()
        
        assert tier.name == NetworkTier.STANDARD
        assert tier.crypto.security_level == SecurityLevel.HIGH
        assert tier.network.max_connections == 50
        assert tier.max_message_size == 512 * 1024  # 512KB
    
    def test_premium_tier(self):
        """Test premium tier configuration."""
        tier = TierConfig.premium()
        
        assert tier.name == NetworkTier.PREMIUM
        assert tier.crypto.security_level == SecurityLevel.HIGH
        assert tier.network.max_connections == 100
        assert tier.max_message_size == 2 * 1024 * 1024  # 2MB
        assert tier.priority_level == 1
    
    def test_enterprise_tier(self):
        """Test enterprise tier configuration."""
        tier = TierConfig.enterprise()
        
        assert tier.name == NetworkTier.ENTERPRISE
        assert tier.crypto.security_level == SecurityLevel.MAXIMUM
        assert tier.network.max_connections == 500
        assert tier.network.enable_upnp is True
        assert tier.max_message_size == 10 * 1024 * 1024  # 10MB
        assert tier.priority_level == 0


class TestConfig:
    """Test main Config class."""
    
    @pytest.fixture
    def config(self):
        """Create a config instance for testing."""
        return Config()
    
    def test_default_initialization(self):
        """Test default configuration initialization."""
        config = Config()
        assert config.tier == NetworkTier.STANDARD
    
    def test_custom_tier_initialization(self):
        """Test configuration with custom tier."""
        config = Config(tier=NetworkTier.BASIC)
        assert config.tier == NetworkTier.BASIC
    
    def test_get_tier_config_default(self, config):
        """Test getting tier configuration for default tier."""
        tier_config = config.get_tier_config()
        assert tier_config.name == NetworkTier.STANDARD
    
    def test_get_tier_config_specific(self, config):
        """Test getting tier configuration for specific tier."""
        tier_config = config.get_tier_config(NetworkTier.BASIC)
        assert tier_config.name == NetworkTier.BASIC
    
    def test_get_tier_config_nonexistent(self, config):
        """Test getting tier configuration for non-existent tier."""
        # Should fallback to standard
        tier_config = config.get_tier_config(None)
        assert tier_config.name == NetworkTier.STANDARD
    
    def test_set_custom_config(self, config):
        """Test setting custom configuration."""
        config.set_custom_config("test_key", "test_value")
        assert config.get("test_key") == "test_value"
    
    def test_get_custom_config(self, config):
        """Test getting custom configuration."""
        config._custom_config["existing_key"] = "existing_value"
        assert config.get("existing_key") == "existing_value"
    
    def test_get_with_default(self, config):
        """Test getting configuration with default value."""
        assert config.get("nonexistent_key", "default") == "default"
        assert config.get("nonexistent_key") is None
    
    def test_get_from_environment(self, config):
        """Test getting configuration from environment."""
        # Set environment variable
        os.environ["TEST_ENV_VAR"] = "env_value"
        
        result = config.get_from_environment("config_key", "TEST_ENV_VAR", "default")
        assert result == "env_value"
        
        # Test fallback to default when env var not set
        del os.environ["TEST_ENV_VAR"]
        result = config.get_from_environment("config_key", "MISSING_VAR", "default")
        assert result == "default"
        
        # Test fallback to config when env var not set
        config.set_custom_config("config_key", "config_value")
        result = config.get_from_environment("config_key", "MISSING_VAR", "default")
        assert result == "config_value"
    
    def test_validate_valid_config(self, config):
        """Test validating a valid configuration."""
        errors = config.validate()
        assert errors == []
    
    def test_validate_invalid_config(self, config):
        """Test validating an invalid configuration."""
        # Modify config to be invalid
        tier_config = config.get_tier_config()
        tier_config.max_message_size = -1
        tier_config.rate_limit_per_minute = 0
        tier_config.concurrent_connections = -5
        tier_config.crypto.key_length = 999
        
        errors = config.validate()
        assert len(errors) > 0
        assert "max_message_size must be positive" in errors
        assert "rate_limit_per_minute must be positive" in errors
        assert "concurrent_connections must be positive" in errors
        assert "key_length must be 16, 24, or 32 bytes" in errors