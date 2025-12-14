from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ReputationHooks:
    """Stub integration point for staking/slashing / relay reputation.

    The routing layer calls these hooks opportunistically. Production systems
    should wire these to on-chain accounting or an internal scoring system.
    """

    def on_pow_valid(self, relay_id: bytes) -> None:  # pragma: no cover
        pass

    def on_pow_invalid(self, relay_id: bytes) -> None:  # pragma: no cover
        pass

    def on_packet_tamper(self, relay_id: bytes) -> None:  # pragma: no cover
        pass

    def on_packet_forwarded(self, relay_id: bytes, next_relay_id: bytes) -> None:  # pragma: no cover
        pass

    def on_packet_delivered(self, relay_id: bytes) -> None:  # pragma: no cover
        pass
