# Darkhole Architecture

## Overview

Darkhole is a cryptographic foundation library providing secure communication primitives and packet layer encoding/decoding for resilient data transmission.

## Packet Layer Subsystem (`darkhole.packet`)

### Purpose

The packet layer provides:
- Fountain code encoding/decoding for resilient data transmission
- Tiered traffic modes with configurable padding strategies
- Versioned packet schema with support for cryptographic commitments
- Serialization/deserialization of packets with metadata

### Key Components

#### 1. Fountain Encoding (`fountain.py`)

Implements LT (Luby Transform) codes for fountain encoding, enabling recovery of original data from a sufficient number of encoded shards despite packet loss.

**Classes:**
- `LTCode`: Core LT code implementation with robust soliton distribution
- `FountainEncoder`: Encodes plaintext into redundant shards
- `FountainDecoder`: Reconstructs plaintext from received shards

**Key Concepts:**
- **Redundancy Factor**: Controls overhead (e.g., 1.5 = 50% extra shards)
- **Shard Size**: Fixed size of each encoded block
- **Loss Threshold**: Maximum packet loss rate the tier can tolerate

**Algorithm:**
The LT code implementation uses:
1. Robust soliton distribution for selecting number of input symbols per shard
2. XOR-based symbol combination for encoding
3. Deterministic seeding for reproducible shard generation

**Example:**
```python
from darkhole.config import TIER_BALANCED
from darkhole.packet import FountainEncoder, FountainDecoder

# Encoding
encoder = FountainEncoder(TIER_BALANCED)
plaintext = b"Secret message"
shards = encoder.encode(plaintext)  # Returns list of (shard_data, index, seed)

# Decoding
decoder = FountainDecoder(TIER_BALANCED)
for shard_data, shard_index, seed in shards[:encoder.k]:  # Need k shards minimum
    decoder.add_shard(shard_data, shard_index, seed)

if decoder.is_decodable():
    original = decoder.decode()
```

#### 2. Padding Strategies (`padding.py`)

Provides deterministic padding to ensure constant-length frames and timing obfuscation.

**Strategies:**
- `ZERO_PADDING`: Pad with null bytes
- `RANDOM_PADDING`: Pad with cryptographically random bytes
- `DETERMINISTIC_RANDOM`: Pad with deterministically random bytes based on tier

**Key Function:**
- `padding_for_tier()`: Generates padding to reach tier packet size

**Example:**
```python
from darkhole.packet.padding import padding_for_tier, PaddingStrategy
from darkhole.config import TIER_HIGH_SECURITY

padding = padding_for_tier(
    data_size=100,
    tier=TIER_HIGH_SECURITY,
    strategy=PaddingStrategy.DETERMINISTIC_RANDOM
)
```

#### 3. Packet Schema (`schema.py`)

Defines versioned packet format with support for cryptographic commitments.

**Packet Structure:**
```
[version (1B)] [flags (1B)] [shard_index (2B)] [seed (4B)] [tier_id (1B)]
[optional: ratchet_key_commitment (32B)] [optional: pow_commitment (32B)]
[payload (variable, padded to packet_size)]
```

**Features:**
- Version enum for forward compatibility
- Flags for optional fields (ratchet key, PoW commitment)
- Tier identification for configuration alignment
- Serialization/deserialization helpers

**Example:**
```python
from darkhole.packet import Packet, PacketVersion
from darkhole.config import TIER_BALANCED

packet = Packet(
    version=PacketVersion.V1,
    shard_index=0,
    seed=42,
    tier=TIER_BALANCED,
    payload=shard_data,
    ratchet_key_commitment=key_bytes,
    pow_commitment=pow_bytes,
)

serialized = packet.serialize()
deserialized = Packet.deserialize(serialized, TIER_BALANCED)
```

### Traffic Tiers (`config.py`)

Three predefined tiers for different security/performance tradeoffs:

#### High Security
- Payload: 256 bytes
- Packet: 512 bytes
- Shard: 64 bytes
- Redundancy: 1.5x (50% overhead)
- Max Loss: 30%

#### Balanced
- Payload: 512 bytes
- Packet: 1024 bytes
- Shard: 128 bytes
- Redundancy: 1.3x (30% overhead)
- Max Loss: 20%

#### High Throughput
- Payload: 2048 bytes
- Packet: 4096 bytes
- Shard: 512 bytes
- Redundancy: 1.2x (20% overhead)
- Max Loss: 10%

### Recovery Guarantees

The fountain code provides:
- **Deterministic Recovery**: With k shards (k = ceil(payload_size / shard_size)), original plaintext can be recovered
- **Loss Resilience**: Can tolerate up to (num_shards - k) shard losses per tier
- **Redundancy**: Extra shards provide buffer against packet drops beyond threshold

Example calculations:
```
High Security:
  - k = ceil(256 / 64) = 4 input symbols
  - num_shards = ceil(4 * 1.5) = 6 shards
  - Max loss = 6 * 0.3 = 1.8 ≈ 1 shard
  - Can lose 1 shard and still decode with remaining 5 ≥ 4

Balanced:
  - k = ceil(512 / 128) = 4 input symbols
  - num_shards = ceil(4 * 1.3) = 6 shards
  - Max loss = 6 * 0.2 = 1.2 ≈ 1 shard
  - Can lose 1 shard and still decode

High Throughput:
  - k = ceil(2048 / 512) = 4 input symbols
  - num_shards = ceil(4 * 1.2) = 5 shards
  - Max loss = 5 * 0.1 = 0.5 ≈ 0 shards
  - Need all 5 shards for recovery (minimal loss tolerance)
```

### Timing and Obfuscation

- **Constant-Length Frames**: All packets are padded to tier packet size, preventing size analysis
- **Deterministic Padding**: Same plaintext size and tier always produce identical padding
- **Seed-Based Generation**: Shards are reproducible from seed, enabling replay analysis resistance

### Integration Points

#### With Cryptographic Layer
The packet layer provides hooks for:
- `ratchet_key_commitment`: 32-byte commitment to ratcheted key
- `pow_commitment`: 32-byte proof-of-work commitment

These fields are optional but recommended for full security properties.

#### With Transport Layer
The encoder/decoder API is transport-agnostic:
1. Encode plaintext to shards
2. Wrap each shard in a Packet
3. Serialize and transmit packets
4. Receive and deserialize packets
5. Extract shards and add to decoder
6. Once decodable, reconstruct plaintext

## Testing

Comprehensive test suite in `tests/test_fountain.py` covers:

### Encoding Tests
- Initialization for all traffic tiers
- Encoding plaintext of various sizes
- Error handling for oversized payloads
- Deterministic behavior

### Decoding Tests
- Shard addition and validation
- Decodability checks with insufficient/sufficient shards
- Reconstruction of plaintext
- Handling of edge cases

### Loss Resilience Tests
- Random shard loss and recovery
- Validation of loss thresholds per tier
- Fuzzing with random shard selections

### Padding Tests
- All padding strategies
- Size validation
- Deterministic behavior for same inputs

### Schema Tests
- Packet creation and serialization
- Round-trip serialization/deserialization
- Handling of optional commitments
- Cross-tier compatibility

### End-to-End Tests
- Full encoding-packet-decoding pipeline
- Simulation of packet loss and recovery
- Multiple tier configurations

## Future Enhancements

1. **Improved Decoding**: Implement Gaussian elimination for iterative decoding
2. **Adaptive Parameters**: Adjust redundancy based on observed loss rates
3. **Batched Encoding**: Optimize for encoding multiple messages
4. **Erasure Codes**: Alternative fountain code implementations (Raptor, RaptorQ)
5. **Hardware Acceleration**: SIMD optimization for XOR operations
