"""Main client interface for Darkhole networking framework."""

from __future__ import annotations

from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import asyncio


@dataclass
class ClientConfig:
    """Configuration for Darkhole client."""
    
    host: str = "localhost"
    port: int = 8080
    timeout: float = 30.0
    max_retries: int = 3
    enable_encryption: bool = True
    debug: bool = False


class Client:
    """
    Main client interface for the Darkhole networking framework.
    
    This class provides the primary API for interacting with the Darkhole
    network, handling connections, encryption, and peer-to-peer communication.
    
    Example:
        Basic usage:
        
        >>> client = Client()
        >>> await client.connect()
        >>> result = await client.send_message("Hello, Darkhole!")
        >>> await client.disconnect()
    """
    
    def __init__(self, config: Optional[ClientConfig] = None) -> None:
        """
        Initialize the Darkhole client.
        
        Args:
            config: Optional client configuration. If not provided,
                   default configuration will be used.
        """
        self.config = config or ClientConfig()
        self._connected: bool = False
        self._peers: List[str] = []
        
    async def connect(self) -> None:
        """
        Establish connection to the Darkhole network.
        
        Raises:
            ConnectionError: If connection fails to establish.
        """
        # TODO: Implement actual connection logic
        self._connected = True
        
    async def disconnect(self) -> None:
        """Disconnect from the Darkhole network."""
        self._connected = False
        
    async def send_message(self, message: str) -> Dict[str, Any]:
        """
        Send a message through the Darkhole network.
        
        Args:
            message: The message to send.
            
        Returns:
            Dictionary containing response data.
            
        Raises:
            ConnectionError: If not connected to the network.
        """
        if not self._connected:
            raise ConnectionError("Not connected to Darkhole network")
            
        # TODO: Implement actual message sending logic
        return {"status": "sent", "message": message}
        
    async def discover_peers(self) -> List[str]:
        """
        Discover available peers in the network.
        
        Returns:
            List of discovered peer addresses.
        """
        # TODO: Implement peer discovery logic
        return self._peers
        
    async def get_status(self) -> Dict[str, Any]:
        """
        Get current client status and network information.
        
        Returns:
            Dictionary containing status information.
        """
        return {
            "connected": self._connected,
            "peers": len(self._peers),
            "config": {
                "host": self.config.host,
                "port": self.config.port,
                "encryption": self.config.enable_encryption,
            },
        }
        
    @property
    def is_connected(self) -> bool:
        """Check if client is currently connected."""
        return self._connected