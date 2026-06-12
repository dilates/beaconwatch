"""
Main daemon loop — wires capture → analysis → store → alerts.

Architecture note: The daemon writes to SQLite (WAL mode). The TUI and CLI read
from the same database file concurrently with no IPC needed — WAL mode allows
simultaneous readers while the daemon is writing.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timezone

from .alerts.desktop import DesktopAlerter
from .alerts.webhook import WebhookAlerter
from .analysis.baseline import BaselineStore
from .analysis.grouping import FlowTracker
from .analysis.interval_stats import compute_interval_stats
from .analysis.scoring import score_flow
from .capture.conntrack import ConntrackMonitor
from .capture.connection import Connection
from .config import Config
from .store.db import Database

logger = logging.getLogger(__name__)

# Classification rank for escalation detection
_CLASSIFICATION_RANK = {
    "benign": 0,
    "suspicious": 1,
    "likely_beacon": 2,
    "high_confidence_beacon": 3,
}


class BeaconwatchDaemon:
    def __init__(self, config: Config) -> None:
        self._config = config
        config.ensure_data_dir()

        self._db = Database(config.db_path)
        self._flow_tracker = FlowTracker(max_history=config.max_history_per_flow)
        self._baseline: BaselineStore | None = None

        self._alerters = []
        if config.alerts.desktop_enabled:
            self._alerters.append(DesktopAlerter())
        if config.alerts.webhook_enabled and config.alerts.webhook_url:
            self._alerters.append(
                WebhookAlerter(
                    url=config.alerts.webhook_url,
                    retry_count=config.alerts.webhook_retry_count,
                    timeout_seconds=config.alerts.webhook_timeout_seconds,
                )
            )

        # Track last-alerted classification per flow to detect escalation
        self._last_alerted_classification: dict[str, str] = {}

        self._monitor: ConntrackMonitor | None = None
        self._running = False

    async def run(self) -> None:
        self._db.open()
        self._baseline = BaselineStore(self._db)

        self._monitor = ConntrackMonitor(
            callback=self._on_connection,
            include_lan=self._config.include_lan_traffic,
        )

        logger.info("beaconwatch daemon starting (backend: %s)", self._monitor.backend_name)
        logger.info("Database: %s", self._config.db_path)

        self._running = True

        # Register signal handlers for clean shutdown
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._request_shutdown)

        await self._monitor.start()

        # Background maintenance task
        maintenance_task = asyncio.create_task(
            self._maintenance_loop(), name="maintenance"
        )

        try:
            while self._running:
                await asyncio.sleep(1.0)
        finally:
            maintenance_task.cancel()
            try:
                await maintenance_task
            except asyncio.CancelledError:
                pass
            await self.shutdown()

    def _request_shutdown(self) -> None:
        logger.info("Shutdown signal received")
        self._running = False

    async def shutdown(self) -> None:
        logger.info("Daemon shutting down…")
        if self._monitor is not None:
            await self._monitor.stop()
        self._db.close()
        logger.info("Daemon stopped.")

    def _on_connection(self, conn: Connection) -> None:
        """
        Called from the conntrack backend for every new/closed connection event.
        Stores the connection, updates flow state, rescores, and fires alerts.
        This runs in the asyncio event loop via run_in_executor or directly.
        """
        try:
            # 1. Store the raw connection
            self._db.insert_connection(conn)

            # 2. Update flow tracker
            flow = self._flow_tracker.add_connection(conn)

            # 3. Rescore if we have enough samples
            if flow.connection_count < self._config.min_samples:
                return

            timestamps = flow.connection_timestamps
            stats = compute_interval_stats(timestamps)

            assert self._baseline is not None
            is_allowlisted = self._baseline.is_allowlisted(
                flow.process_path,
                flow.process_name,
                flow.dst_ip,
                flow.dst_port,
            )

            beacon_score = score_flow(
                flow_id=flow.id,
                process_path=flow.process_path,
                process_name=flow.process_name,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                stats=stats,
                is_allowlisted=is_allowlisted,
                cv_threshold_high=self._config.scoring.cv_threshold_high,
                cv_threshold_medium=self._config.scoring.cv_threshold_medium,
                cv_threshold_low=self._config.scoring.cv_threshold_low,
            )

            # 4. Persist score
            self._db.upsert_flow_score(
                flow_id=flow.id,
                process_path=flow.process_path,
                process_name=flow.process_name,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                proto=flow.proto,
                score=beacon_score.score,
                classification=beacon_score.classification,
                reasons=beacon_score.reasons,
                mean_interval=stats.mean_interval if stats.mean_interval > 0 else None,
                cv=stats.coefficient_of_variation,
                sample_count=stats.sample_count,
                first_seen=flow.first_seen,
                last_seen=flow.last_seen,
            )

            # 5. Alert if classification escalated
            self._maybe_alert(beacon_score, flow)

        except Exception as exc:
            logger.error("Error processing connection %s→%s: %s", conn.src_ip, conn.dst_ip, exc)

    def _maybe_alert(self, beacon_score, flow) -> None:
        if beacon_score.classification == "benign":
            return

        prev_class = self._last_alerted_classification.get(flow.id)
        prev_rank = _CLASSIFICATION_RANK.get(prev_class, -1) if prev_class else -1
        new_rank = _CLASSIFICATION_RANK.get(beacon_score.classification, 0)

        if new_rank <= prev_rank:
            return  # No escalation

        self._last_alerted_classification[flow.id] = beacon_score.classification

        # Log the alert to the database
        self._db.insert_alert(flow.id, beacon_score.score, beacon_score.classification)

        # Fire async alerts (schedule on event loop without blocking the callback)
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(self._fire_alerts(beacon_score, flow))

    async def _fire_alerts(self, beacon_score, flow) -> None:
        for alerter in self._alerters:
            try:
                await alerter.send(beacon_score, flow)
            except Exception as exc:
                logger.warning("Alerter %s failed: %s", type(alerter).__name__, exc)

    async def _maintenance_loop(self) -> None:
        """Every 60s: prune stale flows and purge old connections from DB."""
        while True:
            await asyncio.sleep(60.0)
            try:
                pruned = self._flow_tracker.prune_stale(
                    max_age_hours=self._config.flow_stale_hours
                )
                if pruned > 0:
                    logger.debug("Pruned %d stale flows", pruned)

                deleted = self._db.purge_old_connections(
                    retention_days=self._config.connection_retention_days
                )
                if deleted > 0:
                    logger.debug("Purged %d old connection records", deleted)
            except Exception as exc:
                logger.warning("Maintenance error: %s", exc)
