"""Test configuration for Darkhole package."""

import pytest
import asyncio
from typing import AsyncGenerator
import tempfile
import os


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def temp_dir() -> AsyncGenerator[str, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def sample_config():
    """Provide a sample configuration for testing."""
    from darkhole.config import Config, NetworkTier
    return Config(tier=NetworkTier.BASIC)


@pytest.fixture
def sample_keypair():
    """Provide a sample cryptographic key pair for testing."""
    from darkhole.crypto import KeyPair
    return KeyPair(
        public_key=b"test_public_key_32_bytes_long!!",
        private_key=b"test_private_key_32_bytes_long!"
    )


@pytest.fixture
def sample_packet():
    """Provide a sample packet for testing."""
    from darkhole.packet import Packet, PacketType
    return Packet(
        packet_type=PacketType.DATA,
        source="test_source",
        destination="test_destination",
        payload=b"test_payload"
    )


@pytest.fixture
def sample_node_info():
    """Provide a sample DHT node for testing."""
    from darkhole.dht import NodeInfo
    return NodeInfo(
        node_id="test_node_123",
        address="127.0.0.1",
        port=8080
    )


# Mark slow tests
pytestmark = pytest.mark.asyncio