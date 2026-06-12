"""Desktop notification alerts via libnotify / notify-send."""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..analysis.grouping import Flow
    from ..analysis.scoring import BeaconScore

logger = logging.getLogger(__name__)

# Classification rank — only re-alert if classification escalates
_CLASSIFICATION_RANK = {
    "benign": 0,
    "suspicious": 1,
    "likely_beacon": 2,
    "high_confidence_beacon": 3,
}


class DesktopAlerter:
    """
    Send desktop notifications via notify-send (libnotify).
    Tracks last-alerted classification per flow to avoid spamming.
    Only re-alerts if the classification escalates (e.g. suspicious → likely_beacon).
    """

    def __init__(self) -> None:
        self._last_classification: dict[str, str] = {}
        self._has_notify_send = shutil.which("notify-send") is not None

    def _should_alert(self, flow_id: str, new_classification: str) -> bool:
        prev = self._last_classification.get(flow_id)
        if prev is None:
            return True
        prev_rank = _CLASSIFICATION_RANK.get(prev, 0)
        new_rank = _CLASSIFICATION_RANK.get(new_classification, 0)
        return new_rank > prev_rank

    async def send(self, score: "BeaconScore", flow: "Flow") -> bool:
        if not self._should_alert(flow.id, score.classification):
            return True  # Suppressed (not an error)

        self._last_classification[flow.id] = score.classification

        process_name = flow.process_name or flow.process_path or "unknown"
        destination = f"{flow.dst_ip}:{flow.dst_port}"
        mean_iv = score.stats.mean_interval
        interval_str = _format_interval(mean_iv) if mean_iv > 0 else "unknown"
        top_reason = score.reasons[0] if score.reasons else "Suspicious beaconing pattern"

        title = "\U0001f6a8 Possible C2 Beacon Detected"
        body = (
            f"Process: {process_name}\n"
            f"Destination: {destination}\n"
            f"Interval: ~{interval_str}\n"
            f"Score: {score.score:.0f}/100 ({score.classification.replace('_', ' ')})\n"
            f"Reason: {top_reason}"
        )

        urgency = "critical" if score.classification == "high_confidence_beacon" else "normal"

        return await self._send_notification(title, body, urgency)

    async def _send_notification(self, title: str, body: str, urgency: str) -> bool:
        if not self._has_notify_send:
            # Try notify2 Python library as alternative
            return await self._try_notify2(title, body, urgency)

        try:
            proc = await asyncio.create_subprocess_exec(
                "notify-send",
                "--urgency", urgency,
                "--app-name", "beaconwatch",
                title,
                body,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            if proc.returncode != 0:
                logger.warning(
                    "notify-send failed (rc=%d): %s",
                    proc.returncode,
                    stderr.decode(errors="replace").strip(),
                )
                return False
            return True
        except asyncio.TimeoutError:
            logger.warning("notify-send timed out")
            return False
        except OSError as exc:
            logger.warning("notify-send OS error: %s", exc)
            return False

    async def _try_notify2(self, title: str, body: str, urgency: str) -> bool:
        try:
            import notify2  # type: ignore[import]
            loop = asyncio.get_event_loop()

            def _send():
                try:
                    notify2.init("beaconwatch")
                    n = notify2.Notification(title, body)
                    if urgency == "critical":
                        n.set_urgency(notify2.URGENCY_CRITICAL)
                    n.show()
                    return True
                except Exception as exc:
                    logger.warning("notify2 error: %s", exc)
                    return False

            return await loop.run_in_executor(None, _send)
        except ImportError:
            logger.debug("Neither notify-send nor notify2 available — desktop alerts disabled")
            return False


def _format_interval(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    else:
        return f"{seconds / 3600:.1f}h"
