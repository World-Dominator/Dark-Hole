# Darkhole

A secure, decentralized networking framework built for privacy and performance.

[![CI](https://github.com/darkhole/darkhole/workflows/CI/badge.svg)](https://github.com/darkhole/darkhole/actions)
[![Coverage](https://codecov.io/gh/darkhole/darkhole/branch/main/graph/badge.svg)](https://codecov.io/gh/darkhole/darkhole)
[![PyPI version](https://badge.fury.io/py/darkhole.svg)](https://badge.fury.io/py/darkhole)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Darkhole is a production-ready Python framework for building secure, decentralized network applications. It provides cryptographic primitives, peer-to-peer networking, distributed hash tables (DHT), relay services, and transport layer abstractions.

## Features

- 🔐 **Cryptographic Operations**: Modern encryption with ChaCha20-Poly1305, X25519 key exchange, and forward secrecy
- 🌐 **Peer-to-Peer Networking**: Distributed node discovery and communication
- 📊 **Distributed Hash Table**: Kademlia-like DHT for efficient data storage and retrieval
- 🔄 **Relay Services**: Multi-hop packet forwarding for NAT traversal
- 🚀 **Transport Layer**: Support for TCP, UDP, and WebSocket protocols
- ⚡ **High Performance**: Async/await throughout for optimal concurrency
- 🛡️ **Security First**: Built-in security policies and threat modeling
- 📈 **Scalable Architecture**: Tier-based configuration for different use cases

## Quick Start

Install Darkhole from PyPI:

```bash
pip install darkhole
```

Basic usage:

```python
import asyncio
from darkhole import Client, Config, NetworkTier

async def main():
    # Create client with standard configuration
    config = Config(tier=NetworkTier.STANDARD)
    client = Client(config)
    
    # Connect to the network
    await client.connect()
    
    # Send a message
    response = await client.send_message("Hello, Darkhole!")
    print(f"Response: {response}")
    
    # Check status
    status = await client.get_status()
    print(f"Connected: {status['connected']}")
    print(f"Peers: {status['peers']}")
    
    await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

## Project Structure

```
darkhole/
├── crypto/              # Cryptographic primitives and operations
│   └── __init__.py
├── packet/              # Packet structures and serialization
│   └── __init__.py
├── dht/                 # Distributed Hash Table implementation
│   └── __init__.py
├── relay/               # Relay services and path management
│   └── __init__.py
├── transport/           # Transport layer and networking
│   └── __init__.py
├── client.py            # Main client interface
├── config.py            # Configuration management
└── __init__.py          # Package initialization

tests/
├── unit/                # Unit tests for individual modules
│   ├── test_client.py
│   ├── test_config.py
│   ├── test_crypto.py
│   ├── test_packet.py
│   └── test_dht.py
├── integration/         # Integration tests
└── conftest.py          # Test configuration

examples/                # Usage examples and tutorials
docs/                    # Documentation (Sphinx)
paper/                   # Research papers and specifications
```

## Configuration

Darkhole uses a tier-based configuration system to support different operational requirements:

### Basic Tier
- **Security**: Medium level encryption
- **Connections**: Up to 10 concurrent connections
- **Message Size**: 64KB maximum
- **Rate Limit**: 100 messages/minute
- **Use Case**: Development and testing

### Standard Tier (Default)
- **Security**: High level encryption with forward secrecy
- **Connections**: Up to 50 concurrent connections
- **Message Size**: 512KB maximum
- **Rate Limit**: 500 messages/minute
- **Use Case**: General production applications

### Premium Tier
- **Security**: High level encryption with extended features
- **Connections**: Up to 100 concurrent connections
- **Message Size**: 2MB maximum
- **Rate Limit**: 2000 messages/minute
- **Use Case**: High-performance applications

### Enterprise Tier
- **Security**: Maximum level encryption with UPNP
- **Connections**: Up to 500 concurrent connections
- **Message Size**: 10MB maximum
- **Rate Limit**: 10000 messages/minute
- **Use Case**: Enterprise-scale deployments

### Custom Configuration

```python
from darkhole.config import Config, CryptoConfig, NetworkTier, SecurityLevel

# Create custom configuration
config = Config(tier=NetworkTier.STANDARD)

# Override specific settings
crypto_config = CryptoConfig(
    algorithm="AES-256-GCM",
    security_level=SecurityLevel.MAXIMUM,
    key_length=64
)

config.set_custom_config("crypto", crypto_config)

# Use environment variables
api_key = config.get_from_environment("api_key", "DARKHOLE_API_KEY")
```

## Development

### Setting up the development environment

1. Clone the repository:
```bash
git clone https://github.com/darkhole/darkhole.git
cd darkhole
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate
```

3. Install development dependencies:
```bash
pip install -e ".[dev]"
```

4. Install pre-commit hooks:
```bash
pre-commit install
```

### Running tests

Run all tests with coverage:
```bash
pytest --cov=darkhole --cov-report=html
```

Run tests in parallel:
```bash
pytest -n auto
```

Run specific test categories:
```bash
pytest tests/unit/           # Unit tests only
pytest tests/integration/    # Integration tests only
pytest -m "not slow"         # Skip slow tests
```

### Code quality

Run all quality checks:
```bash
ruff check darkhole tests     # Linting
ruff format --check darkhole tests  # Formatting check
mypy darkhole                # Type checking
```

Fix auto-fixable issues:
```bash
ruff --fix darkhole tests
ruff format darkhole tests
```

### Documentation

Build documentation:
```bash
cd docs
make html
```

Serve documentation locally:
```bash
cd docs
python -m http.server 8000 -d _build/html
```

## Security

Darkhole implements security best practices:

- **Encryption**: ChaCha20-Poly1305 for symmetric encryption
- **Key Exchange**: X25519 for ephemeral key agreement
- **Forward Secrecy**: Automatic key rotation
- **Zero Trust**: All communications are encrypted by default
- **Security Audits**: Regular security reviews and automated scanning

### Security Reporting

If you discover a security vulnerability, please send an email to security@darkhole.dev rather than creating a public issue.

## API Reference

### Client

The `Client` class provides the main interface for Darkhole operations:

```python
from darkhole import Client, Config, NetworkTier

client = Client(Config(tier=NetworkTier.STANDARD))
await client.connect()
```

**Methods:**
- `connect()` - Establish connection to the network
- `disconnect()` - Close connection to the network  
- `send_message(message)` - Send a message through the network
- `discover_peers()` - Find available peers
- `get_status()` - Get current client and network status

### Configuration

The `Config` class manages framework settings:

```python
from darkhole.config import Config, NetworkTier

config = Config(tier=NetworkTier.PREMIUM)
tier_config = config.get_tier_config()
```

**Methods:**
- `get_tier_config(tier)` - Get configuration for a specific tier
- `set_custom_config(key, value)` - Set custom configuration
- `get(key, default)` - Get configuration value
- `validate()` - Validate current configuration

### Cryptography

The `Cryptography` class provides cryptographic operations:

```python
from darkhole.crypto import Cryptography

crypto = Cryptography()
keypair = crypto.generate_keypair()
ciphertext = crypto.encrypt_message("secret", keypair.public_key)
```

**Methods:**
- `generate_keypair(key_type)` - Generate cryptographic key pair
- `derive_shared_secret(private_key, peer_public_key)` - ECDH key agreement
- `encrypt_message(message, key)` - Encrypt data
- `decrypt_message(ciphertext, key)` - Decrypt data
- `hash_data(data, algorithm)` - Hash data

### DHT

The `DHT` class implements distributed hash table functionality:

```python
from darkhole.dht import DHT

dht = DHT()
dht.store_value("key", b"value")
value = dht.find_value("key")
```

**Methods:**
- `store_value(key, value, ttl)` - Store value in DHT
- `find_value(key)` - Retrieve value from DHT
- `find_node(target_id, count)` - Find nodes closest to target
- `ping_node(node_id)` - Check if node is alive

## Performance

Darkhole is designed for high performance:

- **Async/Await**: Non-blocking I/O throughout
- **Connection Pooling**: Efficient connection management
- **Message Batching**: Batch operations for reduced overhead
- **Adaptive Timeouts**: Dynamic timeout adjustment
- **Memory Efficiency**: Optimized data structures

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes with tests
4. Ensure quality checks pass: `make quality`
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a Pull Request

### Commit Message Convention

Use conventional commits:
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `style:` for formatting changes
- `refactor:` for code refactoring
- `test:` for adding tests
- `chore:` for maintenance

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.

## Support

- **Documentation**: [https://darkhole.readthedocs.io/](https://darkhole.readthedocs.io/)
- **Issues**: [GitHub Issues](https://github.com/darkhole/darkhole/issues)
- **Discussions**: [GitHub Discussions](https://github.com/darkhole/darkhole/discussions)
- **Email**: team@darkhole.dev

## Roadmap

- [ ] **v0.2.0**: WebSocket transport support
- [ ] **v0.3.0**: Advanced DHT features (content routing)
- [ ] **v0.4.0**: Relay load balancing algorithms
- [ ] **v0.5.0**: Production deployment tools
- [ ] **v1.0.0**: Stable API and comprehensive documentation

## Acknowledgments

- Kademlia paper for DHT inspiration
- NaCl cryptography library for security primitives
- The Python asyncio community for async patterns