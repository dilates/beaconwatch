"""Group connections into flows by (process, destination) and maintain rolling history."""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..capture.connection import Connection


def _make_flow_id(
    process_path: str | None,
    process_name: str | None,
    dst_ip: str,
    dst_port: int,
    proto: str,
) -> str:
    identity = process_path or process_name or "unknown"
    raw = f"{identity}|{dst_ip}|{dst_port}|{proto}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class Flow:
    id: str
    process_path: str | None
    process_name: str | None
    dst_ip: str
    dst_port: int
    proto: str
    first_seen: datetime
    last_seen: datetime
    connection_count: int
    _timestamps_deque: deque[datetime] = field(default_factory=deque, repr=False)

    @property
    def connection_timestamps(self) -> list[datetime]:
        return list(self._timestamps_deque)

    def add_timestamp(self, ts: datetime, max_history: int) -> None:
        if len(self._timestamps_deque) >= max_history:
            self._timestamps_deque.popleft()
        self._timestamps_deque.append(ts)

    def display_name(self) -> str:
        return self.process_name or self.process_path or "unknown"

    def destination(self) -> str:
        return f"{self.dst_ip}:{self.dst_port}"


class FlowTracker:
    def __init__(self, max_history: int = 200) -> None:
        self._max_history = max_history
        self._flows: dict[str, Flow] = {}

    def add_connection(self, conn: Connection) -> Flow:
        """Add a connection to its flow, creating the flow if it doesn't exist."""
        flow_id = _make_flow_id(
            conn.process_path,
            conn.process_name,
            conn.dst_ip,
            conn.dst_port,
            conn.proto,
        )

        if flow_id not in self._flows:
            self._flows[flow_id] = Flow(
                id=flow_id,
                process_path=conn.process_path,
                process_name=conn.process_name,
                dst_ip=conn.dst_ip,
                dst_port=conn.dst_port,
                proto=conn.proto,
                first_seen=conn.timestamp,
                last_seen=conn.timestamp,
                connection_count=0,
                _timestamps_deque=deque(maxlen=self._max_history),
            )

        flow = self._flows[flow_id]

        # Update process info if we now have it but didn't before
        if flow.process_path is None and conn.process_path is not None:
            flow.process_path = conn.process_path
        if flow.process_name is None and conn.process_name is not None:
            flow.process_name = conn.process_name

        flow.add_timestamp(conn.timestamp, self._max_history)
        flow.connection_count += 1
        flow.last_seen = conn.timestamp

        return flow

    def get_flow(self, flow_id: str) -> Flow | None:
        return self._flows.get(flow_id)

    def get_all_flows(self) -> list[Flow]:
        return list(self._flows.values())

    def prune_stale(self, max_age_hours: int = 24) -> int:
        """Remove flows not seen within max_age_hours. Returns count removed."""
        now = datetime.now(tz=timezone.utc)
        stale_ids = [
            fid
            for fid, flow in self._flows.items()
            if (now - flow.last_seen.replace(tzinfo=timezone.utc if flow.last_seen.tzinfo is None else flow.last_seen.tzinfo)).total_seconds()
            > max_age_hours * 3600
        ]
        for fid in stale_ids:
            del self._flows[fid]
        return len(stale_ids)

    def flow_count(self) -> int:
        return len(self._flows)
