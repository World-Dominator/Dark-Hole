#!/usr/bin/env python3
"""Basic Darkhole client example.

This example demonstrates the basic usage of the Darkhole framework
including client initialization, configuration, and simple operations.
"""

import asyncio
import sys
from pathlib import Path

# Add the parent directory to the path so we can import darkhole
sys.path.insert(0, str(Path(__file__).parent.parent))

from darkhole.client import Client, ClientConfig
from darkhole.config import Config, NetworkTier, CryptoConfig, SecurityLevel


async def basic_example():
    """Run a basic example of Darkhole client usage."""
    print("🚀 Darkhole Basic Client Example")
    print("=" * 40)
    
    # Example 1: Basic client with default configuration
    print("\n1. Creating client with default configuration...")
    client = Client()
    print(f"   ✓ Client created with config: {client.config.host}:{client.config.port}")
    
    # Example 2: Client with custom configuration
    print("\n2. Creating client with custom configuration...")
    config = Config(tier=NetworkTier.PREMIUM)
    custom_client = Client(config=ClientConfig(
        host="192.168.1.100",
        port=9090,
        timeout=60.0,
        enable_encryption=True,
        debug=True
    ))
    print(f"   ✓ Custom client created: {custom_client.config.host}:{custom_client.config.port}")
    
    # Example 3: Connecting to the network
    print("\n3. Connecting to the network...")
    await client.connect()
    print(f"   ✓ Connected: {client.is_connected}")
    
    # Example 4: Getting status
    print("\n4. Getting client status...")
    status = await client.get_status()
    print(f"   ✓ Status: {status}")
    
    # Example 5: Sending a message
    print("\n5. Sending a message...")
    response = await client.send_message("Hello from Darkhole example!")
    print(f"   ✓ Response: {response}")
    
    # Example 6: Discovering peers
    print("\n6. Discovering peers...")
    peers = await client.discover_peers()
    print(f"   ✓ Found {len(peers)} peers: {peers}")
    
    # Example 7: Configuration examples
    print("\n7. Configuration examples...")
    basic_config = Config(tier=NetworkTier.BASIC)
    standard_config = Config(tier=NetworkTier.STANDARD)
    premium_config = Config(tier=NetworkTier.PREMIUM)
    enterprise_config = Config(tier=NetworkTier.ENTERPRISE)
    
    print(f"   ✓ Basic tier max connections: {basic_config.get_tier_config().network.max_connections}")
    print(f"   ✓ Standard tier max connections: {standard_config.get_tier_config().network.max_connections}")
    print(f"   ✓ Premium tier max connections: {premium_config.get_tier_config().network.max_connections}")
    print(f"   ✓ Enterprise tier max connections: {enterprise_config.get_tier_config().network.max_connections}")
    
    # Example 8: Custom crypto configuration
    print("\n8. Custom cryptographic configuration...")
    crypto_config = CryptoConfig(
        algorithm="ChaCha20-Poly1305",
        security_level=SecurityLevel.MAXIMUM,
        key_length=32,
        enable_forward_secrecy=True
    )
    print(f"   ✓ Crypto algorithm: {crypto_config.algorithm}")
    print(f"   ✓ Security level: {crypto_config.security_level.value}")
    print(f"   ✓ Key length: {crypto_config.key_length}")
    
    # Example 9: Environment configuration
    print("\n9. Environment configuration...")
    import os
    os.environ["DARKHOLE_DEBUG"] = "true"
    
    debug_setting = config.get_from_environment(
        "debug_mode", 
        "DARKHOLE_DEBUG", 
        "false"
    )
    print(f"   ✓ Debug mode from env: {debug_setting}")
    
    # Cleanup
    print("\n10. Cleaning up...")
    await client.disconnect()
    print(f"   ✓ Disconnected: {not client.is_connected}")
    
    print("\n🎉 Basic example completed successfully!")
    print("\nNext steps:")
    print("- Try the secure_chat.py example for encrypted messaging")
    print("- Check out file_transfer.py for secure file sharing")
    print("- Explore custom_config.py for advanced configuration options")


if __name__ == "__main__":
    # Run the example
    asyncio.run(basic_example())