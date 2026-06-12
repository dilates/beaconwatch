"""Statistical analysis of connection intervals — the core beaconing detection algorithm."""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np


@dataclass
class IntervalStats:
    sample_count: int
    intervals: list[float]            # seconds between consecutive connections
    mean_interval: float
    median_interval: float
    stdev_interval: float
    coefficient_of_variation: float   # stdev / mean — lower = more regular = more suspicious
    mad_interval: float               # median absolute deviation (robust against outliers)
    autocorrelation_peak: float       # max autocorrelation at lags 1-5
    dominant_period: float | None     # estimated period in seconds if periodic
    jitter_pct: float                 # stdev / mean * 100 (same as CV but as percentage)


_EMPTY_STATS = IntervalStats(
    sample_count=0,
    intervals=[],
    mean_interval=0.0,
    median_interval=0.0,
    stdev_interval=0.0,
    coefficient_of_variation=0.0,
    mad_interval=0.0,
    autocorrelation_peak=0.0,
    dominant_period=None,
    jitter_pct=0.0,
)


def _compute_mad(values: list[float], median_val: float) -> float:
    """Median absolute deviation."""
    if not values:
        return 0.0
    deviations = [abs(v - median_val) for v in values]
    return statistics.median(deviations)


def _compute_autocorrelation(intervals: list[float], max_lag: int = 5) -> float:
    """
    Compute autocorrelation of the interval sequence at lags 1 through max_lag.
    Returns the maximum absolute correlation found (peak periodicity signal).
    Uses numpy for efficiency and correctness.
    """
    if len(intervals) < max_lag + 2:
        return 0.0

    arr = np.array(intervals, dtype=float)
    n = len(arr)
    mean = arr.mean()
    variance = arr.var()

    if variance == 0.0:
        # All identical intervals — perfect periodic signal, autocorrelation = 1
        return 1.0

    peak = 0.0
    for lag in range(1, min(max_lag + 1, n)):
        # Pearson autocorrelation at this lag
        cov = np.mean((arr[: n - lag] - mean) * (arr[lag:] - mean))
        corr = float(cov / variance)
        if abs(corr) > peak:
            peak = abs(corr)

    return peak


def _estimate_dominant_period_fft(
    timestamps: list[datetime], mean_interval: float
) -> float | None:
    """
    Estimate dominant period via FFT on a resampled time series.
    Requires at least 16 samples for meaningful frequency resolution.
    Returns period in seconds, or None if estimation is not reliable.
    """
    n = len(timestamps)
    if n < 16:
        return None

    sorted_ts = sorted(timestamps)
    t0 = sorted_ts[0].timestamp()
    total_span = sorted_ts[-1].timestamp() - t0

    if total_span <= 0:
        return None

    # Bin the connection events into time buckets of size mean_interval/4
    # so we oversample relative to the expected period (Nyquist)
    bin_size = max(mean_interval / 4.0, 1.0)
    num_bins = max(int(total_span / bin_size) + 1, 16)
    # Cap at 4096 bins to avoid excessive memory
    num_bins = min(num_bins, 4096)

    counts = np.zeros(num_bins, dtype=float)
    for ts in sorted_ts:
        idx = int((ts.timestamp() - t0) / bin_size)
        if 0 <= idx < num_bins:
            counts[idx] += 1.0

    # Remove DC component (mean)
    counts -= counts.mean()

    fft_vals = np.fft.rfft(counts)
    power = np.abs(fft_vals) ** 2

    # Ignore DC bin (index 0)
    if len(power) < 2:
        return None

    dominant_bin = int(np.argmax(power[1:]) + 1)

    if dominant_bin == 0:
        return None

    # Convert frequency bin to period in seconds
    freq_hz = dominant_bin / (num_bins * bin_size)
    if freq_hz <= 0:
        return None

    estimated_period = 1.0 / freq_hz

    # Sanity-check: the estimated period should be plausible relative to the data span
    if estimated_period > total_span * 2 or estimated_period < bin_size:
        return None

    return estimated_period


def compute_interval_stats(timestamps: list[datetime]) -> IntervalStats:
    """
    Compute statistical measures of connection timing regularity.
    This is the core beaconing detection algorithm.
    """
    n = len(timestamps)

    if n < 2:
        return IntervalStats(
            sample_count=n,
            intervals=[],
            mean_interval=0.0,
            median_interval=0.0,
            stdev_interval=0.0,
            coefficient_of_variation=0.0,
            mad_interval=0.0,
            autocorrelation_peak=0.0,
            dominant_period=None,
            jitter_pct=0.0,
        )

    sorted_ts = sorted(timestamps)
    intervals = [
        (sorted_ts[i + 1] - sorted_ts[i]).total_seconds()
        for i in range(len(sorted_ts) - 1)
    ]

    # Filter out non-positive intervals (duplicate timestamps)
    intervals = [iv for iv in intervals if iv > 0]

    if not intervals:
        return IntervalStats(
            sample_count=n,
            intervals=[],
            mean_interval=0.0,
            median_interval=0.0,
            stdev_interval=0.0,
            coefficient_of_variation=0.0,
            mad_interval=0.0,
            autocorrelation_peak=0.0,
            dominant_period=None,
            jitter_pct=0.0,
        )

    mean_iv = statistics.mean(intervals)
    median_iv = statistics.median(intervals)
    mad_iv = _compute_mad(intervals, median_iv)

    if len(intervals) >= 2:
        stdev_iv = statistics.stdev(intervals)
    else:
        stdev_iv = 0.0

    if mean_iv > 0:
        cv = stdev_iv / mean_iv
    else:
        cv = 0.0

    jitter_pct = cv * 100.0

    autocorr_peak = _compute_autocorrelation(intervals, max_lag=5)

    dominant_period: float | None = None
    if cv < 0.30:
        # Low-variance case: dominant period is approximately the mean
        dominant_period = mean_iv
    elif autocorr_peak > 0.4 and n >= 16:
        # Higher variance but strong periodicity signal — try FFT
        dominant_period = _estimate_dominant_period_fft(sorted_ts, mean_iv)
    elif n >= 16:
        dominant_period = _estimate_dominant_period_fft(sorted_ts, mean_iv)

    return IntervalStats(
        sample_count=n,
        intervals=intervals,
        mean_interval=mean_iv,
        median_interval=median_iv,
        stdev_interval=stdev_iv,
        coefficient_of_variation=cv,
        mad_interval=mad_iv,
        autocorrelation_peak=autocorr_peak,
        dominant_period=dominant_period,
        jitter_pct=jitter_pct,
    )
