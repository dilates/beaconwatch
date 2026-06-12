"""Webhook alerter — POST JSON to a configured URL with retry logic."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..analysis.grouping import Flow
    from ..analysis.scoring import BeaconScore

logger = logging.getLogger(__name__)


class WebhookAlerter:
    """
    POST a JSON alert payload to a configured webhook URL.
    Retries up to retry_count times with exponential backoff.
    """

    def __init__(
        self,
        url: str,
        retry_count: int = 3,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._url = url
        self._retry_count = retry_count
        self._timeout = timeout_seconds

    async def send(self, score: "BeaconScore", flow: "Flow") -> bool:
        payload = {
            "flow_id": flow.id,
            "process_name": flow.process_name,
            "process_path": flow.process_path,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "proto": flow.proto,
            "score": round(score.score, 2),
            "classification": score.classification,
            "reasons": score.reasons,
            "mean_interval": round(score.stats.mean_interval, 3) if score.stats.mean_interval else None,
            "sample_count": score.stats.sample_count,
            "cv": round(score.stats.coefficient_of_variation, 4) if score.stats.coefficient_of_variation else None,
        }

        for attempt in range(self._retry_count):
            success = await self._post(payload)
            if success:
                return True
            if attempt < self._retry_count - 1:
                delay = 2.0 ** attempt  # 1s, 2s, 4s
                logger.debug("Webhook attempt %d failed, retrying in %.1fs", attempt + 1, delay)
                await asyncio.sleep(delay)

        logger.error("Webhook delivery failed after %d attempts to %s", self._retry_count, self._url)
        return False

    async def _post(self, payload: dict) -> bool:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(self._url, json=payload)
                if resp.status_code >= 400:
                    logger.warning(
                        "Webhook returned HTTP %d from %s", resp.status_code, self._url
                    )
                    return False
                return True
        except ImportError:
            logger.error("httpx not installed — webhook alerts require: pip install httpx")
            return False
        except Exception as exc:
            logger.warning("Webhook POST error: %s", exc)
            return False
