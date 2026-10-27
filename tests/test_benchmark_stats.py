"""Wilson interval: the only statistics the benchmark page shows."""

import pytest

from safetywebbing.benchmark.stats import wilson_interval


def test_no_trials_has_no_interval():
    assert wilson_interval(0, 0) is None


@pytest.mark.parametrize(("k", "n"), [(-1, 3), (4, 3), (1, -2)])
def test_invalid_counts_rejected(k, n):
    with pytest.raises(ValueError, match="0 <= k <= n"):
        wilson_interval(k, n)


@pytest.mark.parametrize("n", [1, 3, 10, 50])
def test_all_failures_start_exactly_at_zero(n):
    lo, hi = wilson_interval(0, n)
    assert lo == 0.0
    assert 0 < hi < 1


@pytest.mark.parametrize("n", [1, 3, 10, 50])
def test_all_successes_end_exactly_at_one(n):
    lo, hi = wilson_interval(n, n)
    assert hi == 1.0
    assert 0 < lo < 1


@pytest.mark.parametrize(("k", "n"), [(0, 3), (1, 3), (2, 3), (3, 3), (5, 12), (40, 41)])
def test_interval_contains_the_point_estimate_and_stays_in_unit_range(k, n):
    lo, hi = wilson_interval(k, n)
    assert 0.0 <= lo <= k / n <= hi <= 1.0


def test_fewer_trials_means_a_wider_interval():
    small = wilson_interval(1, 3)
    large = wilson_interval(100, 300)  # same 1/3 estimate, 100x the evidence
    assert (small[1] - small[0]) > (large[1] - large[0])


def test_more_successes_move_the_interval_up():
    lows = [wilson_interval(k, 10)[0] for k in range(11)]
    highs = [wilson_interval(k, 10)[1] for k in range(11)]
    assert lows == sorted(lows)
    assert highs == sorted(highs)


def test_large_sample_approaches_the_normal_interval():
    # 500/1000: the normal approximation is 0.5 +- 1.96 * sqrt(.25/1000) = 0.5 +- 0.031
    lo, hi = wilson_interval(500, 1000)
    assert lo == pytest.approx(0.469, abs=0.002)
    assert hi == pytest.approx(0.531, abs=0.002)


def test_zero_of_three_is_not_evidence_of_a_zero_rate():
    """The case the page hits first: 0/3 exploited. The honest reading is 'up to ~56%'."""
    lo, hi = wilson_interval(0, 3)
    assert lo == 0.0
    assert hi == pytest.approx(0.561, abs=0.005)
