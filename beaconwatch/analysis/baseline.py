"""Allowlist/baseline store for known-good processes (false positive suppression)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .grouping import Flow
    from .scoring import BeaconScore
    from ..store.db import Database


# Hardcoded suggestions — user must explicitly approve before they're applied
_BENIGN_PROCESS_SUGGESTIONS: list[dict] = [
    {
        "process_name": "systemd-timesyncd",
        "dst_port": 123,
        "reason": "System time sync (NTP) — connects to NTP pools on a regular schedule",
    },
    {
        "process_name": "chronyd",
        "dst_port": 123,
        "reason": "chrony NTP daemon — regular time sync connections to NTP servers",
    },
    {
        "process_name": "ntpd",
        "dst_port": 123,
        "reason": "NTP daemon — regular time sync to NTP pool",
    },
    {
        "process_name": "packagekitd",
        "dst_port": None,
        "reason": "PackageKit update checker — periodic metadata refresh from package mirrors",
    },
    {
        "process_name": "snapd",
        "dst_port": None,
        "reason": "Snap package daemon — periodic update checks to snapcraft.io",
    },
    {
        "process_name": "flatpak",
        "dst_port": None,
        "reason": "Flatpak update checker — periodic refresh from Flathub or configured remotes",
    },
    {
        "process_name": "NetworkManager",
        "dst_port": None,
        "reason": "NetworkManager — periodic connectivity checks (e.g. captive portal detection)",
    },
    {
        "process_name": "firefox",
        "dst_port": 443,
        "reason": "Firefox browser — background sync/telemetry (review before allowlisting)",
    },
    {
        "process_name": "chrome",
        "dst_port": 443,
        "reason": "Chrome browser — background sync/update checks (review before allowlisting)",
    },
    {
        "process_name": "dropbox",
        "dst_port": None,
        "reason": "Dropbox client — regular sync polling (review before allowlisting)",
    },
]


@dataclass
class AllowlistEntry:
    id: str
    process_path: str | None    # None = match any process path
    process_name: str | None    # used when path is None
    dst_ip: str | None          # None = match any destination IP
    dst_port: int | None        # None = match any port
    reason: str
    added_at: datetime


class BaselineStore:
    def __init__(self, db: "Database") -> None:
        self._db = db
        self._cache: dict[str, AllowlistEntry] | None = None

    def _get_entries(self) -> dict[str, AllowlistEntry]:
        if self._cache is None:
            self._cache = {e.id: e for e in self._db.list_allowlist()}
        return self._cache

    def _invalidate_cache(self) -> None:
        self._cache = None

    def is_allowlisted(
        self,
        process_path: str | None,
        process_name: str | None,
        dst_ip: str,
        dst_port: int,
    ) -> bool:
        for entry in self._get_entries().values():
            if _entry_matches(entry, process_path, process_name, dst_ip, dst_port):
                return True
        return False

    def add_to_allowlist(
        self,
        process_path: str | None,
        process_name: str | None,
        dst_ip: str | None,
        dst_port: int | None,
        reason: str,
    ) -> AllowlistEntry:
        if process_path is None and process_name is None and dst_ip is None and dst_port is None:
            raise ValueError("At least one of process_path, process_name, dst_ip, dst_port must be set")

        entry = AllowlistEntry(
            id=str(uuid.uuid4())[:8],
            process_path=process_path,
            process_name=process_name,
            dst_ip=dst_ip,
            dst_port=dst_port,
            reason=reason,
            added_at=datetime.now(tz=timezone.utc),
        )
        self._db.add_allowlist_entry(entry)
        self._invalidate_cache()
        return entry

    def remove_from_allowlist(self, entry_id: str) -> None:
        self._db.remove_allowlist_entry(entry_id)
        self._invalidate_cache()

    def list_allowlist(self) -> list[AllowlistEntry]:
        return list(self._get_entries().values())

    def suggest_allowlist_candidates(
        self, flows: list["Flow"], scores: list["BeaconScore"]
    ) -> list[tuple["Flow", "BeaconScore", str]]:
        """
        Return (flow, score, reason) tuples for flows that match common benign patterns.
        These are SUGGESTIONS — the user must explicitly approve before they're added.
        """
        score_by_id = {s.flow_id: s for s in scores}
        results: list[tuple[Flow, BeaconScore, str]] = []

        for flow in flows:
            beacon_score = score_by_id.get(flow.id)
            if beacon_score is None:
                continue

            # Only suggest flows that the scorer thinks are suspicious
            if beacon_score.classification == "benign":
                continue

            for suggestion in _BENIGN_PROCESS_SUGGESTIONS:
                name_match = (
                    suggestion.get("process_name")
                    and flow.process_name == suggestion["process_name"]
                )
                port_match = (
                    suggestion.get("dst_port") is None
                    or flow.dst_port == suggestion["dst_port"]
                )
                if name_match and port_match:
                    results.append((flow, beacon_score, suggestion["reason"]))
                    break  # Only suggest once per flow

        return results


def _entry_matches(
    entry: AllowlistEntry,
    process_path: str | None,
    process_name: str | None,
    dst_ip: str,
    dst_port: int,
) -> bool:
    """An entry matches if all non-None fields match."""
    if entry.process_path is not None:
        if process_path != entry.process_path:
            return False
    elif entry.process_name is not None:
        if process_name != entry.process_name:
            return False

    if entry.dst_ip is not None and dst_ip != entry.dst_ip:
        return False

    if entry.dst_port is not None and dst_port != entry.dst_port:
        return False

    return True
