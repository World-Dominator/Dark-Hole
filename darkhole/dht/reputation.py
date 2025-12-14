from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class ReputationHook(Protocol):
    def on_relay_success(self, node_id: bytes) -> None: ...

    def on_relay_failure(self, node_id: bytes, *, reason: str) -> None: ...


@dataclass
class NullReputationHook:
    def on_relay_success(self, node_id: bytes) -> None:
        return None

    def on_relay_failure(self, node_id: bytes, *, reason: str) -> None:
        return None
