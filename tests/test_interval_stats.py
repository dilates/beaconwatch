"""Tests for interval_stats.py — core beaconing detection algorithm."""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

import pytest

from beaconwatch.analysis.interval_stats import IntervalStats, compute_interval_stats


def _make_timestamps(
    start: datetime,
    interval_seconds: float,
    count: int,
) -> list[datetime]:
    """Generate perfectly regular timestamps."""
    return [start + timedelta(seconds=interval_seconds * i) for i in range(count)]


def _make_jittered_timestamps(
    start: datetime,
    interval_seconds: float,
    count: int,
    jitter_pct: float,
    seed: int = 42,
) -> list[datetime]:
    """Generate timestamps with bounded jitter (deterministic)."""
    import random
    rng = random.Random(seed)
    ts = start
    result = [ts]
    for _ in range(count - 1):
        jitter = rng.uniform(-jitter_pct, jitter_pct) * interval_seconds
        ts = ts + timedelta(seconds=interval_seconds + jitter)
        result.append(ts)
    return result


def _make_poisson_timestamps(
    start: datetime,
    mean_interval: float,
    count: int,
    seed: int = 42,
) -> list[datetime]:
    """Generate Poisson-process (random/exponential) timestamps — simulates normal traffic."""
    import random
    import math
    rng = random.Random(seed)
    ts = start
    result = [ts]
    for _ in range(count - 1):
        # Exponential inter-arrival for Poisson process
        interval = -math.log(1.0 - rng.random()) * mean_interval
        ts = ts + timedelta(seconds=max(0.1, interval))
        result.append(ts)
    return result


BASE = datetime(2026, 6, 12, 10, 0, 0, tzinfo=timezone.utc)


# ── Basic edge cases ──────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_zero_samples(self):
        stats = compute_interval_stats([])
        assert stats.sample_count == 0
        assert stats.mean_interval == 0.0
        assert stats.coefficient_of_variation == 0.0
        assert stats.dominant_period is None
        assert stats.intervals == []

    def test_one_sample(self):
        stats = compute_interval_stats([BASE])
        assert stats.sample_count == 1
        assert stats.mean_interval == 0.0
        assert stats.intervals == []

    def test_two_samples(self):
        ts = [BASE, BASE + timedelta(seconds=60)]
        stats = compute_interval_stats(ts)
        assert stats.sample_count == 2
        assert len(stats.intervals) == 1
        assert abs(stats.mean_interval - 60.0) < 0.01
        # Single interval has no stdev (or stdev=0 from statistics.stdev with 1 value would error)
        assert stats.stdev_interval == 0.0
        assert stats.coefficient_of_variation == 0.0

    def test_all_identical_intervals(self):
        """Perfect beacon: all intervals identical → CV=0, autocorrelation=1."""
        ts = _make_timestamps(BASE, 60.0, 20)
        stats = compute_interval_stats(ts)
        assert stats.sample_count == 20
        assert len(stats.intervals) == 19
        assert abs(stats.mean_interval - 60.0) < 0.01
        assert stats.stdev_interval == 0.0
        assert stats.coefficient_of_variation == 0.0
        assert stats.jitter_pct == 0.0
        assert stats.autocorrelation_peak == 1.0
        assert stats.dominant_period is not None
        assert abs(stats.dominant_period - 60.0) < 1.0

    def test_duplicate_timestamps(self):
        """Duplicate timestamps should produce empty/near-empty intervals."""
        ts = [BASE, BASE, BASE, BASE + timedelta(seconds=60)]
        stats = compute_interval_stats(ts)
        # Only non-zero intervals counted
        assert all(iv > 0 for iv in stats.intervals)


# ── Perfect beacon ────────────────────────────────────────────────────────────

class TestPerfectBeacon:
    def test_cv_is_zero(self):
        ts = _make_timestamps(BASE, 60.0, 30)
        stats = compute_interval_stats(ts)
        assert stats.coefficient_of_variation == 0.0

    def test_mean_matches_interval(self):
        ts = _make_timestamps(BASE, 300.0, 25)
        stats = compute_interval_stats(ts)
        assert abs(stats.mean_interval - 300.0) < 0.01
        assert abs(stats.median_interval - 300.0) < 0.01

    def test_mad_is_zero(self):
        ts = _make_timestamps(BASE, 120.0, 20)
        stats = compute_interval_stats(ts)
        assert stats.mad_interval == 0.0

    def test_autocorrelation_peak_is_one(self):
        ts = _make_timestamps(BASE, 60.0, 20)
        stats = compute_interval_stats(ts)
        assert stats.autocorrelation_peak == 1.0

    def test_dominant_period_detected(self):
        ts = _make_timestamps(BASE, 60.0, 20)
        stats = compute_interval_stats(ts)
        assert stats.dominant_period is not None
        # CV < 0.30 → dominant_period ≈ mean_interval
        assert abs(stats.dominant_period - 60.0) < 5.0

    def test_jitter_pct_is_zero(self):
        ts = _make_timestamps(BASE, 60.0, 20)
        stats = compute_interval_stats(ts)
        assert stats.jitter_pct == 0.0


# ── Jittered beacon (±10% noise) ──────────────────────────────────────────────

class TestJitteredBeacon:
    def test_cv_low_with_10pct_jitter(self):
        ts = _make_jittered_timestamps(BASE, 300.0, 30, jitter_pct=0.10)
        stats = compute_interval_stats(ts)
        # With ±10% jitter, CV should be roughly 0.05-0.12
        assert stats.coefficient_of_variation < 0.20, (
            f"Expected CV < 0.20 for ±10% jitter, got {stats.coefficient_of_variation:.4f}"
        )

    def test_mean_near_target_interval(self):
        ts = _make_jittered_timestamps(BASE, 300.0, 30, jitter_pct=0.10)
        stats = compute_interval_stats(ts)
        # Mean should be close to 300s
        assert abs(stats.mean_interval - 300.0) < 60.0, (
            f"Expected mean ~300s, got {stats.mean_interval:.1f}"
        )

    def test_dominant_period_still_detectable(self):
        ts = _make_jittered_timestamps(BASE, 300.0, 30, jitter_pct=0.10)
        stats = compute_interval_stats(ts)
        assert stats.dominant_period is not None

    def test_sample_count_correct(self):
        ts = _make_jittered_timestamps(BASE, 300.0, 20, jitter_pct=0.10)
        stats = compute_interval_stats(ts)
        assert stats.sample_count == 20
        assert len(stats.intervals) == 19


# ── Random / Poisson process (normal traffic) ─────────────────────────────────

class TestPoissonProcess:
    def test_cv_high_for_poisson(self):
        """Poisson/exponential inter-arrivals have CV ≈ 1.0 (high variance)."""
        ts = _make_poisson_timestamps(BASE, mean_interval=300.0, count=50)
        stats = compute_interval_stats(ts)
        # Exponential distribution has CV = 1.0 theoretically; with finite samples it varies
        assert stats.coefficient_of_variation > 0.4, (
            f"Expected high CV for Poisson traffic, got {stats.coefficient_of_variation:.4f}"
        )

    def test_autocorrelation_low_for_poisson(self):
        ts = _make_poisson_timestamps(BASE, mean_interval=300.0, count=50)
        stats = compute_interval_stats(ts)
        # Poisson process has near-zero autocorrelation
        assert stats.autocorrelation_peak < 0.5, (
            f"Expected low autocorrelation for Poisson, got {stats.autocorrelation_peak:.4f}"
        )


# ── Outlier robustness ────────────────────────────────────────────────────────

class TestOutlierRobustness:
    def test_single_large_outlier_mean_vs_median(self):
        """
        One huge outlier (e.g. laptop suspend) spikes mean/stdev
        but median and MAD should remain robust.
        """
        # Regular 60s beacon for 19 connections
        regular = _make_timestamps(BASE, 60.0, 19)
        # Then a 6-hour gap (laptop was suspended)
        outlier = [regular[-1] + timedelta(hours=6)]
        ts = regular + outlier

        stats = compute_interval_stats(ts)

        # Median interval should still be close to 60s
        assert abs(stats.median_interval - 60.0) < 5.0, (
            f"Expected median ~60s even with outlier, got {stats.median_interval:.1f}"
        )

        # MAD should be very small (most intervals are identical)
        assert stats.mad_interval < 10.0, (
            f"Expected small MAD, got {stats.mad_interval:.1f}"
        )

        # But mean will be inflated by the outlier
        assert stats.mean_interval > 100.0, (
            f"Expected mean to be inflated by outlier, got {stats.mean_interval:.1f}"
        )

    def test_mad_near_zero_for_perfect_beacon(self):
        ts = _make_timestamps(BASE, 60.0, 20)
        stats = compute_interval_stats(ts)
        assert stats.mad_interval == 0.0


# ── Numerical stability ───────────────────────────────────────────────────────

class TestNumericalStability:
    def test_very_short_intervals(self):
        """Sub-second intervals should not crash."""
        ts = _make_timestamps(BASE, 0.5, 20)
        stats = compute_interval_stats(ts)
        assert stats.mean_interval == pytest.approx(0.5, abs=0.001)

    def test_very_long_intervals(self):
        """Multi-hour intervals should work fine."""
        ts = _make_timestamps(BASE, 3600.0 * 24, 10)
        stats = compute_interval_stats(ts)
        assert abs(stats.mean_interval - 86400.0) < 1.0

    def test_sorted_output_with_unsorted_input(self):
        """Input timestamps not in order should be handled."""
        ts = _make_timestamps(BASE, 60.0, 10)
        shuffled = ts[5:] + ts[:5]  # out of order
        stats = compute_interval_stats(shuffled)
        # After sorting, intervals should still be ~60s each
        assert abs(stats.mean_interval - 60.0) < 1.0

    def test_large_sample_count(self):
        """200 samples (max history) should not cause issues."""
        ts = _make_timestamps(BASE, 60.0, 200)
        stats = compute_interval_stats(ts)
        assert stats.sample_count == 200
        assert len(stats.intervals) == 199
        assert stats.coefficient_of_variation == 0.0
