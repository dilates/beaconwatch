"""Configuration loading and defaults."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[no-redef]
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]


_DEFAULT_DATA_DIR = Path("~/.local/share/beaconwatch").expanduser()
_CONFIG_SEARCH_PATHS = [
    Path(".beaconwatch.toml"),
    Path("~/.config/beaconwatch/config.toml").expanduser(),
    Path("/etc/beaconwatch/config.toml"),
]


@dataclass
class AlertsConfig:
    desktop_enabled: bool = True
    webhook_url: str = ""
    webhook_enabled: bool = False
    webhook_timeout_seconds: float = 10.0
    webhook_retry_count: int = 3


@dataclass
class ScoringConfig:
    cv_threshold_high: float = 0.05
    cv_threshold_medium: float = 0.15
    cv_threshold_low: float = 0.30


@dataclass
class Config:
    data_dir: Path = field(default_factory=lambda: _DEFAULT_DATA_DIR)
    min_samples: int = 5
    max_history_per_flow: int = 200
    flow_stale_hours: int = 24
    connection_retention_days: int = 7
    include_lan_traffic: bool = False
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "beaconwatch.db"

    def ensure_data_dir(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)


def _merge_alerts(raw: dict) -> AlertsConfig:
    a = AlertsConfig()
    a.desktop_enabled = bool(raw.get("desktop_enabled", a.desktop_enabled))
    a.webhook_url = str(raw.get("webhook_url", a.webhook_url))
    a.webhook_enabled = bool(raw.get("webhook_enabled", a.webhook_enabled))
    a.webhook_timeout_seconds = float(raw.get("webhook_timeout_seconds", a.webhook_timeout_seconds))
    a.webhook_retry_count = int(raw.get("webhook_retry_count", a.webhook_retry_count))
    return a


def _merge_scoring(raw: dict) -> ScoringConfig:
    s = ScoringConfig()
    s.cv_threshold_high = float(raw.get("cv_threshold_high", s.cv_threshold_high))
    s.cv_threshold_medium = float(raw.get("cv_threshold_medium", s.cv_threshold_medium))
    s.cv_threshold_low = float(raw.get("cv_threshold_low", s.cv_threshold_low))
    return s


def load_config(path: Path | None = None) -> Config:
    """Load config from TOML file, falling back to defaults."""
    config_path: Path | None = path

    if config_path is None:
        for candidate in _CONFIG_SEARCH_PATHS:
            if candidate.exists():
                config_path = candidate
                break

    if config_path is None:
        return Config()

    with open(config_path, "rb") as f:
        raw = tomllib.load(f)

    bw = raw.get("beaconwatch", {})

    cfg = Config()

    if "data_dir" in bw:
        cfg.data_dir = Path(os.path.expanduser(bw["data_dir"]))

    cfg.min_samples = int(bw.get("min_samples", cfg.min_samples))
    cfg.max_history_per_flow = int(bw.get("max_history_per_flow", cfg.max_history_per_flow))
    cfg.flow_stale_hours = int(bw.get("flow_stale_hours", cfg.flow_stale_hours))
    cfg.connection_retention_days = int(bw.get("connection_retention_days", cfg.connection_retention_days))
    cfg.include_lan_traffic = bool(bw.get("include_lan_traffic", cfg.include_lan_traffic))

    if "alerts" in bw:
        cfg.alerts = _merge_alerts(bw["alerts"])

    if "scoring" in bw:
        cfg.scoring = _merge_scoring(bw["scoring"])

    return cfg
