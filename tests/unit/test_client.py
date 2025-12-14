"""Unit tests for darkhole.client module."""

import pytest
from unittest.mock import Mock, patch

from darkhole.client import Client, ClientConfig


class TestClientConfig:
    """Test ClientConfig dataclass."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = ClientConfig()
        assert config.host == "localhost"
        assert config.port == 8080
        assert config.timeout == 30.0
        assert config.max_retries == 3
        assert config.enable_encryption is True
        assert config.debug is False
    
    def test_custom_config(self):
        """Test custom configuration values."""
        config = ClientConfig(
            host="192.168.1.1",
            port=9000,
            timeout=60.0,
            enable_encryption=False,
            debug=True
        )
        assert config.host == "192.168.1.1"
        assert config.port == 9000
        assert config.timeout == 60.0
        assert config.enable_encryption is False
        assert config.debug is True


class TestClient:
    """Test Client class."""
    
    @pytest.fixture
    def client(self):
        """Create a client instance for testing."""
        return Client()
    
    @pytest.fixture
    def custom_client(self):
        """Create a client with custom config."""
        config = ClientConfig(host="test.host", port=9999)
        return Client(config=config)
    
    def test_client_initialization(self, client):
        """Test client initialization."""
        assert client.config.host == "localhost"
        assert client.config.port == 8080
        assert client._connected is False
        assert client._peers == []
    
    def test_client_initialization_with_custom_config(self, custom_client):
        """Test client initialization with custom configuration."""
        assert custom_client.config.host == "test.host"
        assert custom_client.config.port == 9999
        assert custom_client._connected is False
    
    @pytest.mark.asyncio
    async def test_connect(self, client):
        """Test connecting to the network."""
        assert client._connected is False
        await client.connect()
        assert client._connected is True
    
    @pytest.mark.asyncio
    async def test_disconnect(self, client):
        """Test disconnecting from the network."""
        client._connected = True
        await client.disconnect()
        assert client._connected is False
    
    @pytest.mark.asyncio
    async def test_send_message_not_connected(self, client):
        """Test sending message when not connected raises error."""
        with pytest.raises(ConnectionError, match="Not connected"):
            await client.send_message("test message")
    
    @pytest.mark.asyncio
    async def test_send_message_connected(self, client):
        """Test sending message when connected."""
        await client.connect()
        result = await client.send_message("Hello, Darkhole!")
        
        assert result["status"] == "sent"
        assert result["message"] == "Hello, Darkhole!"
    
    @pytest.mark.asyncio
    async def test_discover_peers(self, client):
        """Test peer discovery."""
        # Empty initially
        peers = await client.discover_peers()
        assert peers == []
        
        # Add some peers manually for testing
        client._peers = ["peer1", "peer2"]
        peers = await client.discover_peers()
        assert peers == ["peer1", "peer2"]
    
    @pytest.mark.asyncio
    async def test_get_status_not_connected(self, client):
        """Test getting status when not connected."""
        status = await client.get_status()
        
        assert status["connected"] is False
        assert status["peers"] == 0
        assert status["config"]["host"] == "localhost"
        assert status["config"]["port"] == 8080
        assert status["config"]["encryption"] is True
    
    @pytest.mark.asyncio
    async def test_get_status_connected(self, client):
        """Test getting status when connected."""
        await client.connect()
        client._peers = ["peer1", "peer2"]
        
        status = await client.get_status()
        
        assert status["connected"] is True
        assert status["peers"] == 2
        assert status["config"]["host"] == "localhost"
    
    def test_is_connected_property(self, client):
        """Test is_connected property."""
        assert client.is_connected is False
        client._connected = True
        assert client.is_connected is True