from __future__ import annotations

from typing import Protocol


class RelayTransport(Protocol):
    """Transport abstraction for real relay-backed overlays.

    The mock overlay (`MockOverlayNetwork`) is synchronous and in-memory. A real
    implementation would implement this protocol and provide authenticated
    delivery over network links.
    """

    async def request(self, *, entry_node_id: bytes, packet_bytes: bytes) -> bytes | None: ...


class RelayDirectory(Protocol):
    """Directory abstraction for selecting routes/replicas in a real network."""

    def get_replica_node_ids(self, *, key: bytes, replicas: int) -> list[bytes]: ...

    def get_public_key(self, *, node_id: bytes) -> bytes: ...

    def get_tier(self, *, node_id: bytes) -> str: ...
