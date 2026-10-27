"""Small-sample statistics for the benchmark. Pure Python: the host app adds no dependency.

With 2-3 trials per cell, a bare percentage overstates what was measured, so every rate the
page shows is a count (k of n) with a Wilson score interval (PROTOCOL.md section 4).
"""

from __future__ import annotations

from math import sqrt

_Z_95 = 1.959963984540054  # two-sided 95% normal quantile


def wilson_interval(k: int, n: int, z: float = _Z_95) -> tuple[float, float] | None:
    """Wilson score interval for k successes in n trials, or None when n == 0.

    Chosen over the plain normal interval because it stays inside [0, 1] and is still sensible
    at k == 0 or k == n, which is exactly where tiny benchmarks end up.
    """
    if n < 0 or k < 0 or k > n:
        raise ValueError(f"need 0 <= k <= n, got k={k}, n={n}")
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    # At the edges the exact bound is 0 / 1; the formula only gets there up to float noise.
    lower = 0.0 if k == 0 else max(0.0, (centre - margin) / denom)
    upper = 1.0 if k == n else min(1.0, (centre + margin) / denom)
    return lower, upper
