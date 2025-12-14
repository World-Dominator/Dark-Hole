from __future__ import annotations

from dataclasses import dataclass, field


class TrafficShapingError(RuntimeError):
    pass


@dataclass
class TierTrafficShaper:
    """Simple tier-aware traffic accounting.

    This is a deterministic budget model used by the mock overlay. A real
    implementation would replace this with token buckets / paced scheduling.
    """

    budgets: dict[str, int]
    used: dict[str, int] = field(default_factory=dict)

    def reset(self) -> None:
        self.used.clear()

    def consume(self, tier: str, nbytes: int) -> None:
        if nbytes < 0:
            raise ValueError("nbytes must be non-negative")
        budget = self.budgets.get(tier)
        if budget is None:
            raise TrafficShapingError(f"unknown tier: {tier}")

        used = self.used.get(tier, 0) + nbytes
        if used > budget:
            raise TrafficShapingError(f"tier {tier} budget exceeded: {used} > {budget}")
        self.used[tier] = used
