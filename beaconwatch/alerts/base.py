"""Alerter protocol definition."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..analysis.grouping import Flow
    from ..analysis.scoring import BeaconScore


@runtime_checkable
class Alerter(Protocol):
    async def send(self, score: "BeaconScore", flow: "Flow") -> bool:
        """Send an alert. Returns True on success, False on failure."""
        ...
