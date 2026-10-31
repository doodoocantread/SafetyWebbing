"""Turn matches into metrics (BENCHMARK.md §2.2).

A *case* is one (target, scan_type). It is scored over N runs (the suite's `repeat`),
so the detection metrics are averaged across runs and reproducibility is measured as
how often the runs agree on each expected vulnerability.

Definitions:
  recall     = found expected / total expected          (per run, then averaged)
  precision  = findings matched to an expected / all findings on target
  f1         = harmonic mean of recall and precision
  cwe_acc    = of the expected that were found, fraction whose matched finding had
               the correct CWE
  owasp_acc  = likewise for the OWASP category
  sev_delta  = mean |severity rank error| over found expected
  reproducibility = 1 - (expected found in some-but-not-all runs / total expected)

Precision carries a caveat: an "unmatched finding" is only a false positive if the
ground truth is complete. For these targets the lists are focused, not exhaustive, so
read precision as a lower bound.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .matcher import MatchResult


def _f1(recall: float, precision: float) -> float:
    if recall + precision == 0:
        return 0.0
    return 2 * recall * precision / (recall + precision)


def _safe_mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


@dataclass
class RunScore:
    recall: float
    precision: float
    f1: float
    cwe_accuracy: float
    owasp_accuracy: float
    mean_severity_delta: float | None
    found: int
    expected_total: int
    total_findings: int
    unmatched_findings: int


def score_run(match: MatchResult) -> RunScore:
    expected_total = len(match.outcomes)
    found_outcomes = [o for o in match.outcomes if o.found]
    found = len(found_outcomes)

    recall = found / expected_total if expected_total else 0.0
    matched_findings = len(match.matched_finding_indexes)
    precision = matched_findings / match.total_findings if match.total_findings else 0.0
    cwe_acc = _safe_mean([1.0 if o.cwe_correct else 0.0 for o in found_outcomes])
    owasp_acc = _safe_mean([1.0 if o.owasp_correct else 0.0 for o in found_outcomes])
    sev_deltas = [float(o.severity_delta) for o in found_outcomes if o.severity_delta is not None]
    mean_sev = _safe_mean(sev_deltas) if sev_deltas else None

    return RunScore(
        recall=recall,
        precision=precision,
        f1=_f1(recall, precision),
        cwe_accuracy=cwe_acc,
        owasp_accuracy=owasp_acc,
        mean_severity_delta=mean_sev,
        found=found,
        expected_total=expected_total,
        total_findings=match.total_findings,
        unmatched_findings=match.unmatched_finding_count,
    )


@dataclass
class ExpectedStability:
    id: str
    found_in_runs: int
    n_runs: int

    @property
    def detection_rate(self) -> float:
        return self.found_in_runs / self.n_runs if self.n_runs else 0.0

    @property
    def flaky(self) -> bool:
        return 0 < self.found_in_runs < self.n_runs


@dataclass
class CaseScore:
    target: str
    scan_type: str
    n_runs: int
    expected_total: int
    recall_mean: float
    recall_best: float  # union across runs: ever found
    precision_mean: float
    f1_mean: float
    cwe_accuracy_mean: float
    owasp_accuracy_mean: float
    mean_severity_delta: float | None
    unmatched_findings_mean: float
    reproducibility: float
    per_expected: list[ExpectedStability] = field(default_factory=list)
    run_scores: list[RunScore] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "n_runs": self.n_runs,
            "expected_total": self.expected_total,
            "recall_mean": round(self.recall_mean, 4),
            "recall_best": round(self.recall_best, 4),
            "precision_mean": round(self.precision_mean, 4),
            "f1_mean": round(self.f1_mean, 4),
            "cwe_accuracy_mean": round(self.cwe_accuracy_mean, 4),
            "owasp_accuracy_mean": round(self.owasp_accuracy_mean, 4),
            "mean_severity_delta": (
                round(self.mean_severity_delta, 4)
                if self.mean_severity_delta is not None else None
            ),
            "unmatched_findings_mean": round(self.unmatched_findings_mean, 4),
            "reproducibility": round(self.reproducibility, 4),
            "per_expected": [
                {"id": e.id, "found_in_runs": e.found_in_runs, "n_runs": e.n_runs,
                 "detection_rate": round(e.detection_rate, 4), "flaky": e.flaky}
                for e in self.per_expected
            ],
        }


def score_case(target: str, scan_type: str, matches: list[MatchResult]) -> CaseScore:
    """Aggregate the per-run matches for one (target, scan_type) into a CaseScore."""
    if not matches:
        raise ValueError("score_case needs at least one run")
    run_scores = [score_run(m) for m in matches]
    n_runs = len(matches)
    expected_total = len(matches[0].outcomes)

    # Per-expected stability across runs (expected lists are identical across runs of
    # the same case, so index by expected id).
    found_counter: dict[str, int] = {}
    for m in matches:
        for o in m.outcomes:
            found_counter.setdefault(o.expected.id, 0)
            if o.found:
                found_counter[o.expected.id] += 1
    per_expected = [
        ExpectedStability(id=eid, found_in_runs=cnt, n_runs=n_runs)
        for eid, cnt in found_counter.items()
    ]
    flaky = sum(1 for e in per_expected if e.flaky)
    reproducibility = 1.0 - (flaky / expected_total) if expected_total else 1.0
    recall_best = (
        sum(1 for e in per_expected if e.found_in_runs > 0) / expected_total
        if expected_total else 0.0
    )

    sev_deltas = [r.mean_severity_delta for r in run_scores if r.mean_severity_delta is not None]

    return CaseScore(
        target=target,
        scan_type=scan_type,
        n_runs=n_runs,
        expected_total=expected_total,
        recall_mean=_safe_mean([r.recall for r in run_scores]),
        recall_best=recall_best,
        precision_mean=_safe_mean([r.precision for r in run_scores]),
        f1_mean=_safe_mean([r.f1 for r in run_scores]),
        cwe_accuracy_mean=_safe_mean([r.cwe_accuracy for r in run_scores]),
        owasp_accuracy_mean=_safe_mean([r.owasp_accuracy for r in run_scores]),
        mean_severity_delta=_safe_mean(sev_deltas) if sev_deltas else None,
        unmatched_findings_mean=_safe_mean([float(r.unmatched_findings) for r in run_scores]),
        reproducibility=reproducibility,
        per_expected=sorted(per_expected, key=lambda e: e.id),
        run_scores=run_scores,
    )
