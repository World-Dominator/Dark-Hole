"""Transport layer for Darkhole network communication.

This module provides the low-level networking and communication
infrastructure for the Darkhole framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Callable, Any, Union
from enum import Enum
import asyncio
import time
import socket
import ssl
from contextlib import asynccontextmanager


class TransportProtocol(Enum):
    """Supported transport protocols."""
    TCP = "tcp"
    UDP = "udp"
    QUIC = "quic"
    WEBSOCKET = "websocket"


class ConnectionState(Enum):
    """States for transport connections."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"


@dataclass
class ConnectionInfo:
    """Information about a network connection."""
    connection_id: str
    protocol: TransportProtocol
    remote_address: str
    remote_port: int
    local_address: str
    local_port: int
    state: ConnectionState = ConnectionState.DISCONNECTED
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_received: int = 0
    latency: float = 0.0
    is_encrypted: bool = False
    
    @property
    def is_active(self) -> bool:
        """Check if connection is currently active."""
        return self.state == ConnectionState.CONNECTED
    
    @property
    def age(self) -> float:
        """Get connection age in seconds."""
        return time.time() - self.created_at


@dataclass
class TransportConfig:
    """Configuration for transport layer."""
    protocol: TransportProtocol = TransportProtocol.TCP
    host: str = "0.0.0.0"
    port: int = 8080
    max_connections: int = 1000
    connection_timeout: float = 30.0
    read_timeout: float = 60.0
    write_timeout: float = 30.0
    enable_ssl: bool = False
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    enable_compression: bool = False
    buffer_size: int = 8192
    keep_alive: bool = True
    tcp_nodelay: bool = True


class TransportError(Exception):
    """Base exception for transport operations."""
    pass


class ConnectionError(TransportError):
    """Exception for connection-related errors."""
    pass


class TransportLayer:
    """
    Transport layer manager for Darkhole network communication.
    
    Provides unified interface for different transport protocols
    and handles connection management, multiplexing, and error recovery.
    """
    
    def __init__(self, config: Optional[TransportConfig] = None) -> None:
        """
        Initialize transport layer.
        
        Args:
            config: Transport configuration. Uses defaults if None.
        """
        self.config = config or TransportConfig()
        self.connections: Dict[str, ConnectionInfo] = {}
        self.message_handlers: Dict[str, Callable] = {}
        self.is_running: bool = False
        self.server_socket: Optional[socket.socket] = None
        self._lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "failed_connections": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "messages_sent": 0,
            "messages_received": 0,
        }
    
    async def start(self) -> None:
        """Start the transport layer server."""
        if self.is_running:
            return
        
        self.is_running = True
        
        if self.config.protocol == TransportProtocol.TCP:
            await self._start_tcp_server()
        elif self.config.protocol == TransportProtocol.UDP:
            await self._start_udp_server()
        else:
            raise TransportError(f"Protocol {self.config.protocol} not yet implemented")
    
    async def stop(self) -> None:
        """Stop the transport layer server."""
        if not self.is_running:
            return
        
        self.is_running = False
        
        # Close all connections
        for connection_id in list(self.connections.keys()):
            await self.disconnect(connection_id)
        
        # Close server socket
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
    
    async def _start_tcp_server(self) -> None:
        """Start TCP server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            if self.config.tcp_nodelay:
                self.server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            if self.config.keep_alive:
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            self.server_socket.bind((self.config.host, self.config.port))
            self.server_socket.listen(self.config.max_connections)
            
            print(f"TCP server started on {self.config.host}:{self.config.port}")
            
            # Start accepting connections
            asyncio.create_task(self._accept_tcp_connections())
            
        except Exception as e:
            raise TransportError(f"Failed to start TCP server: {e}")
    
    async def _start_udp_server(self) -> None:
        """Start UDP server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.bind((self.config.host, self.config.port))
            
            print(f"UDP server started on {self.config.host}:{self.config.port}")
            
            # Start receiving packets
            asyncio.create_task(self._receive_udp_packets())
            
        except Exception as e:
            raise TransportError(f"Failed to start UDP server: {e}")
    
    async def _accept_tcp_connections(self) -> None:
        """Accept incoming TCP connections."""
        while self.is_running and self.server_socket:
            try:
                client_socket, client_address = await asyncio.get_event_loop().run_in_executor(
                    None, self.server_socket.accept
                )
                
                connection_id = f"tcp_{client_address[0]}:{client_address[1]}_{int(time.time())}"
                
                connection_info = ConnectionInfo(
                    connection_id=connection_id,
                    protocol=TransportProtocol.TCP,
                    remote_address=client_address[0],
                    remote_port=client_address[1],
                    local_address=self.config.host,
                    local_port=self.config.port,
                    state=ConnectionState.CONNECTING
                )
                
                self.connections[connection_id] = connection_info
                self.stats["total_connections"] += 1
                
                # Start handling the connection
                asyncio.create_task(self._handle_tcp_connection(connection_id, client_socket))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error accepting connection: {e}")
    
    async def _handle_tcp_connection(self, connection_id: str, client_socket: socket.socket) -> None:
        """Handle an established TCP connection."""
        connection_info = self.connections.get(connection_id)
        if not connection_info:
            return
        
        try:
            connection_info.state = ConnectionState.CONNECTED
            
            while self.is_running and connection_info.is_active:
                # Read data from socket
                try:
                    data = await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(
                            None, client_socket.recv, self.config.buffer_size
                        ),
                        timeout=self.config.read_timeout
                    )
                    
                    if not data:
                        break
                    
                    # Update connection stats
                    connection_info.bytes_received += len(data)
                    connection_info.last_activity = time.time()
                    self.stats["bytes_received"] += len(data)
                    
                    # Handle received data
                    await self._handle_received_data(connection_id, data)
                    
                except asyncio.TimeoutError:
                    # Check if connection is still alive
                    if time.time() - connection_info.last_activity > self.config.read_timeout:
                        break
                    continue
                    
        except Exception as e:
            print(f"Error handling TCP connection {connection_id}: {e}")
        finally:
            await self.disconnect(connection_id)
            client_socket.close()
    
    async def _receive_udp_packets(self) -> None:
        """Receive incoming UDP packets."""
        while self.is_running and self.server_socket:
            try:
                data, client_address = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, self.server_socket.recvfrom, self.config.buffer_size
                    ),
                    timeout=1.0
                )
                
                connection_id = f"udp_{client_address[0]}:{client_address[1]}"
                
                # Update connection info for UDP
                if connection_id not in self.connections:
                    connection_info = ConnectionInfo(
                        connection_id=connection_id,
                        protocol=TransportProtocol.UDP,
                        remote_address=client_address[0],
                        remote_port=client_address[1],
                        local_address=self.config.host,
                        local_port=self.config.port,
                        state=ConnectionState.CONNECTED
                    )
                    self.connections[connection_id] = connection_info
                
                # Update stats
                self.connections[connection_id].bytes_received += len(data)
                self.stats["bytes_received"] += len(data)
                
                # Handle received data
                await self._handle_received_data(connection_id, data)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                if self.is_running:
                    print(f"Error receiving UDP packet: {e}")
    
    async def _handle_received_data(self, connection_id: str, data: bytes) -> None:
        """Handle received data from a connection."""
        # Call registered message handlers
        for handler in self.message_handlers.values():
            try:
                await handler(connection_id, data)
            except Exception as e:
                print(f"Error in message handler: {e}")
        
        self.stats["messages_received"] += 1
    
    async def connect(self, address: str, port: int, 
                     protocol: Optional[TransportProtocol] = None) -> str:
        """
        Establish a connection to a remote host.
        
        Args:
            address: Remote host address.
            port: Remote host port.
            protocol: Transport protocol to use. If None, uses configured protocol.
            
        Returns:
            Connection ID for the established connection.
            
        Raises:
            ConnectionError: If connection fails.
        """
        protocol = protocol or self.config.protocol
        connection_id = f"{protocol.value}_{address}:{port}_{int(time.time())}"
        
        try:
            if protocol == TransportProtocol.TCP:
                return await self._connect_tcp(connection_id, address, port)
            elif protocol == TransportProtocol.UDP:
                return await self._connect_udp(connection_id, address, port)
            else:
                raise ConnectionError(f"Protocol {protocol} not yet implemented")
                
        except Exception as e:
            self.stats["failed_connections"] += 1
            raise ConnectionError(f"Failed to connect to {address}:{port}: {e}")
    
    async def _connect_tcp(self, connection_id: str, address: str, port: int) -> str:
        """Establish TCP connection."""
        reader, writer = await asyncio.open_connection(address, port)
        
        connection_info = ConnectionInfo(
            connection_id=connection_id,
            protocol=TransportProtocol.TCP,
            remote_address=address,
            remote_port=port,
            local_address="",  # Will be filled by OS
            local_port=0,      # Will be filled by OS
            state=ConnectionState.CONNECTED
        )
        
        self.connections[connection_id] = connection_info
        self.stats["total_connections"] += 1
        
        # Start reading from connection
        asyncio.create_task(self._read_tcp_connection(connection_id, reader))
        
        return connection_id
    
    async def _connect_udp(self, connection_id: str, address: str, port: int) -> str:
        """Establish UDP connection (connectionless, but we track the peer)."""
        connection_info = ConnectionInfo(
            connection_id=connection_id,
            protocol=TransportProtocol.UDP,
            remote_address=address,
            remote_port=port,
            local_address=self.config.host,
            local_port=self.config.port,
            state=ConnectionState.CONNECTED
        )
        
        self.connections[connection_id] = connection_info
        self.stats["total_connections"] += 1
        
        return connection_id
    
    async def _read_tcp_connection(self, connection_id: str, reader: asyncio.StreamReader) -> None:
        """Read data from TCP connection."""
        connection_info = self.connections.get(connection_id)
        if not connection_info:
            return
        
        try:
            while self.is_running and connection_info.is_active:
                data = await reader.read(self.config.buffer_size)
                
                if not data:
                    break
                
                # Update stats
                connection_info.bytes_received += len(data)
                connection_info.last_activity = time.time()
                self.stats["bytes_received"] += len(data)
                
                # Handle received data
                await self._handle_received_data(connection_id, data)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Error reading from TCP connection {connection_id}: {e}")
        finally:
            await self.disconnect(connection_id)
    
    async def disconnect(self, connection_id: str) -> None:
        """
        Disconnect a connection.
        
        Args:
            connection_id: ID of connection to disconnect.
        """
        if connection_id in self.connections:
            connection_info = self.connections[connection_id]
            connection_info.state = ConnectionState.DISCONNECTED
            del self.connections[connection_id]
    
    async def send(self, connection_id: str, data: Union[str, bytes]) -> bool:
        """
        Send data through a connection.
        
        Args:
            connection_id: ID of connection to use.
            data: Data to send.
            
        Returns:
            True if send was successful.
            
        Raises:
            ConnectionError: If connection doesn't exist or is not active.
        """
        if connection_id not in self.connections:
            raise ConnectionError(f"Connection {connection_id} not found")
        
        connection_info = self.connections[connection_id]
        
        if not connection_info.is_active:
            raise ConnectionError(f"Connection {connection_id} is not active")
        
        # Convert string to bytes if necessary
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            if connection_info.protocol == TransportProtocol.TCP:
                return await self._send_tcp(connection_id, data)
            elif connection_info.protocol == TransportProtocol.UDP:
                return await self._send_udp(connection_id, data)
            else:
                raise ConnectionError(f"Protocol {connection_info.protocol} not implemented")
                
        except Exception as e:
            print(f"Error sending data on connection {connection_id}: {e}")
            return False
    
    async def _send_tcp(self, connection_id: str, data: bytes) -> bool:
        """Send data via TCP connection."""
        # For a complete implementation, we'd need to track the writer objects
        # This is a simplified version
        connection_info = self.connections[connection_id]
        connection_info.bytes_sent += len(data)
        connection_info.last_activity = time.time()
        self.stats["bytes_sent"] += len(data)
        self.stats["messages_sent"] += 1
        
        # TODO: Implement actual TCP writing
        return True
    
    async def _send_udp(self, connection_id: str, data: bytes) -> bool:
        """Send data via UDP."""
        if not self.server_socket:
            return False
        
        connection_info = self.connections[connection_id]
        
        try:
            sent = await asyncio.get_event_loop().run_in_executor(
                None,
                self.server_socket.sendto,
                data,
                (connection_info.remote_address, connection_info.remote_port)
            )
            
            connection_info.bytes_sent += sent
            connection_info.last_activity = time.time()
            self.stats["bytes_sent"] += sent
            self.stats["messages_sent"] += 1
            
            return True
            
        except Exception as e:
            print(f"Error sending UDP packet: {e}")
            return False
    
    def register_message_handler(self, handler_id: str, handler: Callable[[str, bytes], None]) -> None:
        """
        Register a message handler.
        
        Args:
            handler_id: Unique identifier for the handler.
            handler: Async function that takes (connection_id, data) parameters.
        """
        self.message_handlers[handler_id] = handler
    
    def get_connection_info(self, connection_id: str) -> Optional[ConnectionInfo]:
        """Get information about a connection."""
        return self.connections.get(connection_id)
    
    def get_all_connections(self) -> List[ConnectionInfo]:
        """Get information about all connections."""
        return list(self.connections.values())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get transport layer statistics."""
        active_count = sum(1 for conn in self.connections.values() if conn.is_active)
        self.stats["active_connections"] = active_count
        
        return {
            **self.stats,
            "config": {
                "protocol": self.config.protocol.value,
                "host": self.config.host,
                "port": self.config.port,
                "max_connections": self.config.max_connections,
            },
            "connections": {
                "total": len(self.connections),
                "active": active_count,
                "by_protocol": {
                    protocol.value: sum(1 for conn in self.connections.values() 
                                      if conn.protocol == protocol)
                    for protocol in TransportProtocol
                }
            }
        }