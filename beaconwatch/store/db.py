"""SQLite storage — WAL mode for safe concurrent daemon-writes + TUI-reads."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..analysis.baseline import AllowlistEntry
    from ..capture.connection import Connection


_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS connections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       DATETIME NOT NULL,
    proto           TEXT NOT NULL,
    src_ip          TEXT NOT NULL,
    src_port        INTEGER NOT NULL,
    dst_ip          TEXT NOT NULL,
    dst_port        INTEGER NOT NULL,
    pid             INTEGER,
    process_name    TEXT,
    process_path    TEXT,
    bytes_sent      INTEGER,
    bytes_recv      INTEGER,
    state           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_conn_ts   ON connections(timestamp);
CREATE INDEX IF NOT EXISTS idx_conn_flow ON connections(process_path, dst_ip, dst_port, proto);

CREATE TABLE IF NOT EXISTS flow_scores (
    flow_id         TEXT PRIMARY KEY,
    process_path    TEXT,
    process_name    TEXT,
    dst_ip          TEXT NOT NULL,
    dst_port        INTEGER NOT NULL,
    proto           TEXT NOT NULL,
    score           REAL NOT NULL,
    classification  TEXT NOT NULL,
    reasons         TEXT NOT NULL,     -- JSON array
    mean_interval   REAL,
    cv              REAL,
    sample_count    INTEGER,
    first_seen      DATETIME,
    last_seen       DATETIME,
    updated_at      DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS allowlist (
    id              TEXT PRIMARY KEY,
    process_path    TEXT,
    process_name    TEXT,
    dst_ip          TEXT,
    dst_port        INTEGER,
    reason          TEXT NOT NULL,
    added_at        DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id         TEXT NOT NULL,
    score           REAL NOT NULL,
    classification  TEXT NOT NULL,
    triggered_at    DATETIME NOT NULL,
    acknowledged    INTEGER NOT NULL DEFAULT 0
);
"""


@dataclass
class FlowScoreRecord:
    flow_id: str
    process_path: str | None
    process_name: str | None
    dst_ip: str
    dst_port: int
    proto: str
    score: float
    classification: str
    reasons: list[str]
    mean_interval: float | None
    cv: float | None
    sample_count: int | None
    first_seen: datetime | None
    last_seen: datetime | None
    updated_at: datetime


@dataclass
class AlertRecord:
    id: int
    flow_id: str
    score: float
    classification: str
    triggered_at: datetime
    acknowledged: bool


def _dt(val: str | None) -> datetime | None:
    if val is None:
        return None
    try:
        dt = datetime.fromisoformat(val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._conn: sqlite3.Connection | None = None

    def open(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self._path),
            check_same_thread=False,
            detect_types=sqlite3.PARSE_DECLTYPES,
            timeout=10.0,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "Database":
        self.open()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def _db(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("Database not opened — call open() first")
        return self._conn

    # ── Connections ────────────────────────────────────────────────────────

    def insert_connection(self, conn: "Connection") -> None:
        self._db().execute(
            """
            INSERT INTO connections
              (timestamp, proto, src_ip, src_port, dst_ip, dst_port,
               pid, process_name, process_path, bytes_sent, bytes_recv, state)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                conn.timestamp.isoformat(),
                conn.proto,
                conn.src_ip,
                conn.src_port,
                conn.dst_ip,
                conn.dst_port,
                conn.pid,
                conn.process_name,
                conn.process_path,
                conn.bytes_sent,
                conn.bytes_recv,
                conn.state,
            ),
        )
        self._db().commit()

    def get_flow_history(self, flow_id: str, hours: int = 24) -> list["Connection"]:
        # Flow ID encodes (process_path, dst_ip, dst_port, proto)
        # We reconstruct by looking up the flow_score first
        from ..capture.connection import Connection as Conn

        score_row = self._db().execute(
            "SELECT process_path, process_name, dst_ip, dst_port, proto FROM flow_scores WHERE flow_id = ?",
            (flow_id,),
        ).fetchone()

        if score_row is None:
            return []

        cutoff = datetime.now(tz=timezone.utc).isoformat()
        rows = self._db().execute(
            """
            SELECT * FROM connections
            WHERE dst_ip = ? AND dst_port = ? AND proto = ?
              AND (process_path = ? OR (process_path IS NULL AND process_name = ?))
              AND timestamp > datetime(?, '-{} hours')
            ORDER BY timestamp ASC
            """.format(hours),
            (
                score_row["dst_ip"],
                score_row["dst_port"],
                score_row["proto"],
                score_row["process_path"],
                score_row["process_name"],
                cutoff,
            ),
        ).fetchall()

        results: list[Conn] = []
        for r in rows:
            ts = _dt(r["timestamp"])
            if ts is None:
                continue
            results.append(
                Conn(
                    timestamp=ts,
                    proto=r["proto"],
                    src_ip=r["src_ip"],
                    src_port=r["src_port"],
                    dst_ip=r["dst_ip"],
                    dst_port=r["dst_port"],
                    pid=r["pid"],
                    process_name=r["process_name"],
                    process_path=r["process_path"],
                    bytes_sent=r["bytes_sent"],
                    bytes_recv=r["bytes_recv"],
                    state=r["state"],
                )
            )
        return results

    def purge_old_connections(self, retention_days: int) -> int:
        cursor = self._db().execute(
            "DELETE FROM connections WHERE timestamp < datetime('now', '-{} days')".format(retention_days)
        )
        self._db().commit()
        return cursor.rowcount

    def get_recent_connection_count(self, hours: int = 24) -> int:
        row = self._db().execute(
            "SELECT COUNT(*) FROM connections WHERE timestamp > datetime('now', '-{} hours')".format(hours)
        ).fetchone()
        return int(row[0]) if row else 0

    def get_last_connection_time(self) -> datetime | None:
        row = self._db().execute(
            "SELECT MAX(timestamp) FROM connections"
        ).fetchone()
        if row and row[0]:
            return _dt(row[0])
        return None

    # ── Flow Scores ────────────────────────────────────────────────────────

    def upsert_flow_score(
        self,
        flow_id: str,
        process_path: str | None,
        process_name: str | None,
        dst_ip: str,
        dst_port: int,
        proto: str,
        score: float,
        classification: str,
        reasons: list[str],
        mean_interval: float | None,
        cv: float | None,
        sample_count: int | None,
        first_seen: datetime | None,
        last_seen: datetime | None,
    ) -> None:
        self._db().execute(
            """
            INSERT INTO flow_scores
              (flow_id, process_path, process_name, dst_ip, dst_port, proto,
               score, classification, reasons, mean_interval, cv, sample_count,
               first_seen, last_seen, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(flow_id) DO UPDATE SET
              process_path=excluded.process_path,
              process_name=excluded.process_name,
              score=excluded.score,
              classification=excluded.classification,
              reasons=excluded.reasons,
              mean_interval=excluded.mean_interval,
              cv=excluded.cv,
              sample_count=excluded.sample_count,
              last_seen=excluded.last_seen,
              updated_at=excluded.updated_at
            """,
            (
                flow_id,
                process_path,
                process_name,
                dst_ip,
                dst_port,
                proto,
                score,
                classification,
                json.dumps(reasons),
                mean_interval,
                cv,
                sample_count,
                first_seen.isoformat() if first_seen else None,
                last_seen.isoformat() if last_seen else None,
                _now_iso(),
            ),
        )
        self._db().commit()

    def get_top_scoring_flows(
        self, limit: int = 50, min_classification: str = "suspicious"
    ) -> list[FlowScoreRecord]:
        class_order = {
            "benign": 0,
            "suspicious": 1,
            "likely_beacon": 2,
            "high_confidence_beacon": 3,
        }
        min_class_val = class_order.get(min_classification, 1)

        rows = self._db().execute(
            """
            SELECT * FROM flow_scores
            ORDER BY score DESC
            LIMIT ?
            """,
            (limit * 4,),  # fetch more, then filter
        ).fetchall()

        results: list[FlowScoreRecord] = []
        for r in rows:
            if class_order.get(r["classification"], 0) < min_class_val:
                continue
            results.append(_row_to_flow_score(r))
            if len(results) >= limit:
                break

        return results

    def get_all_flow_scores(self, limit: int = 200) -> list[FlowScoreRecord]:
        rows = self._db().execute(
            "SELECT * FROM flow_scores ORDER BY score DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row_to_flow_score(r) for r in rows]

    def get_flow_score(self, flow_id: str) -> FlowScoreRecord | None:
        row = self._db().execute(
            "SELECT * FROM flow_scores WHERE flow_id = ?", (flow_id,)
        ).fetchone()
        return _row_to_flow_score(row) if row else None

    # ── Allowlist ──────────────────────────────────────────────────────────

    def add_allowlist_entry(self, entry: "AllowlistEntry") -> None:
        self._db().execute(
            """
            INSERT INTO allowlist (id, process_path, process_name, dst_ip, dst_port, reason, added_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.id,
                entry.process_path,
                entry.process_name if hasattr(entry, "process_name") else None,
                entry.dst_ip,
                entry.dst_port,
                entry.reason,
                entry.added_at.isoformat(),
            ),
        )
        self._db().commit()

    def remove_allowlist_entry(self, entry_id: str) -> None:
        self._db().execute("DELETE FROM allowlist WHERE id = ?", (entry_id,))
        self._db().commit()

    def list_allowlist(self) -> list["AllowlistEntry"]:
        from ..analysis.baseline import AllowlistEntry as AE

        rows = self._db().execute("SELECT * FROM allowlist ORDER BY added_at DESC").fetchall()
        results: list[AE] = []
        for r in rows:
            added = _dt(r["added_at"]) or datetime.now(tz=timezone.utc)
            results.append(
                AE(
                    id=r["id"],
                    process_path=r["process_path"],
                    process_name=r["process_name"] if "process_name" in r.keys() else None,
                    dst_ip=r["dst_ip"],
                    dst_port=r["dst_port"],
                    reason=r["reason"],
                    added_at=added,
                )
            )
        return results

    # ── Alert log ──────────────────────────────────────────────────────────

    def insert_alert(
        self, flow_id: str, score: float, classification: str
    ) -> int:
        cursor = self._db().execute(
            """
            INSERT INTO alert_log (flow_id, score, classification, triggered_at)
            VALUES (?, ?, ?, ?)
            """,
            (flow_id, score, classification, _now_iso()),
        )
        self._db().commit()
        return cursor.lastrowid or 0

    def get_alerts(self, unacknowledged_only: bool = False) -> list[AlertRecord]:
        q = "SELECT * FROM alert_log"
        if unacknowledged_only:
            q += " WHERE acknowledged = 0"
        q += " ORDER BY triggered_at DESC LIMIT 500"
        rows = self._db().execute(q).fetchall()
        return [_row_to_alert(r) for r in rows]

    def acknowledge_alert(self, alert_id: int) -> None:
        self._db().execute(
            "UPDATE alert_log SET acknowledged = 1 WHERE id = ?", (alert_id,)
        )
        self._db().commit()

    def get_flow_count(self) -> int:
        row = self._db().execute("SELECT COUNT(*) FROM flow_scores").fetchone()
        return int(row[0]) if row else 0


def _row_to_flow_score(r: sqlite3.Row) -> FlowScoreRecord:
    reasons_raw = r["reasons"]
    try:
        reasons = json.loads(reasons_raw) if reasons_raw else []
    except (json.JSONDecodeError, TypeError):
        reasons = []

    return FlowScoreRecord(
        flow_id=r["flow_id"],
        process_path=r["process_path"],
        process_name=r["process_name"],
        dst_ip=r["dst_ip"],
        dst_port=r["dst_port"],
        proto=r["proto"],
        score=float(r["score"]),
        classification=r["classification"],
        reasons=reasons,
        mean_interval=float(r["mean_interval"]) if r["mean_interval"] is not None else None,
        cv=float(r["cv"]) if r["cv"] is not None else None,
        sample_count=int(r["sample_count"]) if r["sample_count"] is not None else None,
        first_seen=_dt(r["first_seen"]),
        last_seen=_dt(r["last_seen"]),
        updated_at=_dt(r["updated_at"]) or datetime.now(tz=timezone.utc),
    )


def _row_to_alert(r: sqlite3.Row) -> AlertRecord:
    return AlertRecord(
        id=int(r["id"]),
        flow_id=r["flow_id"],
        score=float(r["score"]),
        classification=r["classification"],
        triggered_at=_dt(r["triggered_at"]) or datetime.now(tz=timezone.utc),
        acknowledged=bool(r["acknowledged"]),
    )
