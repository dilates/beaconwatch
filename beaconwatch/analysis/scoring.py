"""Beacon score calculation and classification."""

from __future__ import annotations

from dataclasses import dataclass, field

from .interval_stats import IntervalStats

# Common ports that C2 often uses to blend with HTTPS/HTTP traffic
_COMMON_C2_BLEND_PORTS = {80, 443, 8080, 8443}

# Top ~20 common service ports — unusual ports outside this get extra suspicion
_COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443,
    465, 587, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443,
    8888, 9090, 9200, 27017,
}

# Paths that indicate a process running from a suspicious location
_SUSPICIOUS_PATH_PREFIXES = (
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/run/user/",
)

_SUSPICIOUS_PATH_COMPONENTS = (
    "/.cache/",
    "/.local/tmp/",
    "/proc/",
)

# Pre-classified score thresholds
_THRESHOLD_HIGH_CONFIDENCE = 70.0
_THRESHOLD_LIKELY = 45.0
_THRESHOLD_SUSPICIOUS = 20.0


def _is_public_ip(ip: str) -> bool:
    """Check if an IP is publicly routable (not RFC1918/loopback)."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return False


def _is_suspicious_path(process_path: str | None) -> bool:
    """Return True if the process path suggests a suspicious/unusual location."""
    if process_path is None:
        return False
    for prefix in _SUSPICIOUS_PATH_PREFIXES:
        if process_path.startswith(prefix):
            return True
    for component in _SUSPICIOUS_PATH_COMPONENTS:
        if component in process_path:
            return True
    # Hidden executable (dotfile directory in home)
    parts = process_path.split("/")
    for part in parts[:-1]:  # don't count the binary name itself
        if part.startswith("."):
            return True
    return False


@dataclass
class BeaconScore:
    flow_id: str
    score: float                # 0-100
    classification: str         # "benign" | "suspicious" | "likely_beacon" | "high_confidence_beacon"
    reasons: list[str]          # human-readable explanations, ordered by contribution desc
    stats: IntervalStats
    raw_contributions: list[tuple[float, str]] = field(default_factory=list, repr=False)


def score_flow(
    flow_id: str,
    process_path: str | None,
    process_name: str | None,
    dst_ip: str,
    dst_port: int,
    stats: IntervalStats,
    is_allowlisted: bool = False,
    cv_threshold_high: float = 0.05,
    cv_threshold_medium: float = 0.15,
    cv_threshold_low: float = 0.30,
) -> BeaconScore:
    """
    Compute a beaconing likelihood score (0-100) for a flow.
    Scoring is deterministic: same inputs always produce the same output.
    """
    contributions: list[tuple[float, str]] = []  # (points, reason)

    cv = stats.coefficient_of_variation
    mean_iv = stats.mean_interval
    sample_count = stats.sample_count
    autocorr = stats.autocorrelation_peak

    # ── 1. Coefficient of Variation (heaviest signal) ──────────────────────
    if cv < cv_threshold_high:
        cv_points = 50.0
        cv_reason = (
            f"Extremely regular interval (CV={cv:.3f}) — near-perfect periodicity"
        )
    elif cv < cv_threshold_medium:
        cv_points = 35.0
        cv_reason = (
            f"Highly regular interval (CV={cv:.3f}) — consistent with beaconing + jitter"
        )
    elif cv < cv_threshold_low:
        cv_points = 15.0
        cv_reason = f"Moderately regular interval (CV={cv:.3f})"
    else:
        cv_points = 0.0
        cv_reason = f"Irregular intervals (CV={cv:.3f}) — not characteristic of beaconing"

    # Always include CV reason (even if 0 pts) — important for user understanding
    contributions.append((cv_points, cv_reason))

    # ── 2. Interval magnitude ──────────────────────────────────────────────
    if mean_iv > 0:
        if mean_iv < 5.0:
            contributions.append(
                (10.0, "Very short interval — could be normal keepalive or aggressive beacon")
            )
        elif 30.0 <= mean_iv <= 3600.0:
            contributions.append(
                (10.0, f"Interval {_format_interval(mean_iv)} in common C2 range (30s–1h)")
            )
        # daily+ check-ins get no bonus (update checkers, less typical active C2)

    # ── 3. Autocorrelation bonus ───────────────────────────────────────────
    if autocorr > 0.7:
        contributions.append(
            (15.0, f"Strong periodicity detected via autocorrelation (peak={autocorr:.2f})")
        )

    # ── 4. Destination reputation (offline, heuristic) ────────────────────
    if _is_public_ip(dst_ip):
        if dst_port in _COMMON_C2_BLEND_PORTS:
            contributions.append(
                (5.0, f"Common C2 port {dst_port} over HTTPS/HTTP — blends with normal traffic")
            )
        elif dst_port not in _COMMON_PORTS:
            contributions.append(
                (10.0, f"Connecting to uncommon port {dst_port} on public IP")
            )

    # ── 5. Process reputation ──────────────────────────────────────────────
    if _is_suspicious_path(process_path):
        contributions.append(
            (20.0, f"Process running from unusual location: {process_path}")
        )
    elif process_name is None and process_path is None:
        contributions.append(
            (10.0, "Process could not be identified (resolution failed)")
        )

    if is_allowlisted:
        contributions.append(
            (-30.0, "Process is in user-approved baseline allowlist")
        )

    # ── Sum raw score ──────────────────────────────────────────────────────
    raw_score = sum(pts for pts, _ in contributions)

    # ── 6. Sample count confidence multiplier ─────────────────────────────
    if sample_count < 5:
        multiplier = 0.3
    elif sample_count < 16:
        multiplier = 0.7
    else:
        multiplier = 1.0

    final_score = max(0.0, min(100.0, raw_score * multiplier))

    # ── Sort reasons by contribution (descending), always keep CV first ──
    cv_entry = contributions[0]
    rest = sorted(contributions[1:], key=lambda x: abs(x[0]), reverse=True)
    ordered = [cv_entry] + rest

    reasons = [reason for _, reason in ordered]

    # ── Classification ─────────────────────────────────────────────────────
    if final_score >= _THRESHOLD_HIGH_CONFIDENCE:
        classification = "high_confidence_beacon"
    elif final_score >= _THRESHOLD_LIKELY:
        classification = "likely_beacon"
    elif final_score >= _THRESHOLD_SUSPICIOUS:
        classification = "suspicious"
    else:
        classification = "benign"

    return BeaconScore(
        flow_id=flow_id,
        score=final_score,
        classification=classification,
        reasons=reasons,
        stats=stats,
        raw_contributions=ordered,
    )


def _format_interval(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    else:
        return f"{seconds / 3600:.1f}h"
