"""Command-line entry point: `python -m safetywebbing.benchmark ...`.

Subcommands:
  run    — run a suite against a running server, save raw records + scores.
  score  — (re)score raw records saved earlier, no server needed.

Everything is written under a results directory (default `benchmark/results/<timestamp>/`):
  records.jsonl   — one line per scan (RunRecord), the raw evidence.
  scores.json     — per-case metrics.
  report.md       — a human-readable table.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from .matcher import match_report
from .runner import RunRecord, ScanParams, run_case
from .scoring import CaseScore, score_case
from .spec import Suite, load_ground_truth_dir, load_suite

_DEFAULT_GT_DIR = "benchmark/ground_truth"
_DEFAULT_RESULTS = "benchmark/results"


def _load_records(path: Path) -> list[RunRecord]:
    records: list[RunRecord] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        records.append(RunRecord(**d))
    return records


def _save_records(path: Path, records: list[RunRecord]) -> None:
    path.write_text(
        "\n".join(json.dumps(r.to_dict(), ensure_ascii=False) for r in records) + "\n",
        encoding="utf-8",
    )


def score_records(
    records: list[RunRecord], ground_truths: dict,
) -> tuple[list[CaseScore], list[RunRecord]]:
    """Group records by (target, scan_type), match each usable run against ground truth,
    and score the case. Returns (case_scores, failed_runs). Failed/report-less runs are
    excluded from detection scoring (a failed scan is inconclusive, not 'clean') but
    returned so the caller can report them."""
    groups: dict[tuple[str, str], list[RunRecord]] = {}
    failures: list[RunRecord] = []
    for r in records:
        if not r.ok:
            failures.append(r)
            continue
        groups.setdefault((r.target, r.scan_type), []).append(r)

    scores: list[CaseScore] = []
    for (target, scan_type), recs in sorted(groups.items()):
        gt = ground_truths.get(target)
        if gt is None:
            print(f"warning: no ground truth for target {target!r}, skipping", file=sys.stderr)
            continue
        expected = gt.for_scan_type(scan_type)
        matches = [
            match_report(r.report, gt.origin, expected, scan_type) for r in recs
        ]
        scores.append(score_case(target, scan_type, matches))
    return scores, failures


def _markdown_table(scores: list[CaseScore], failures: list[RunRecord]) -> str:
    lines = ["# SafetyWebbing benchmark results", ""]
    lines += [
        ("| Target | Scan | Runs | Expected | Recall (mean/best) | Precision | F1 | "
         "CWE acc | OWASP acc | Sev Δ | Repro |"),
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for s in scores:
        sev = "—" if s.mean_severity_delta is None else f"{s.mean_severity_delta:.2f}"
        lines.append(
            f"| {s.target} | {s.scan_type} | {s.n_runs} | {s.expected_total} | "
            f"{s.recall_mean:.0%}/{s.recall_best:.0%} | {s.precision_mean:.0%} | "
            f"{s.f1_mean:.2f} | {s.cwe_accuracy_mean:.0%} | {s.owasp_accuracy_mean:.0%} | "
            f"{sev} | {s.reproducibility:.0%} |"
        )
    if failures:
        lines += ["", "## Failed / inconclusive runs (excluded from scoring)", ""]
        for r in failures:
            lines.append(f"- `{r.target}/{r.scan_type}` run `{r.run_id or '—'}`: "
                         f"{r.status}{' — ' + r.error if r.error else ''}")
    lines += ["", ("> Precision is a lower bound: unmatched findings are only false "
                   "positives if the ground truth is exhaustive, which these focused "
                   "lists are not.")]
    return "\n".join(lines) + "\n"


def _write_outputs(out_dir: Path, scores: list[CaseScore], failures: list[RunRecord]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scores.json").write_text(
        json.dumps([s.to_dict() for s in scores], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (out_dir / "report.md").write_text(_markdown_table(scores, failures), encoding="utf-8")


def _cmd_run(args: argparse.Namespace) -> int:
    suite: Suite = load_suite(args.suite)
    ground_truths = load_ground_truth_dir(args.ground_truth)
    repeat = args.repeat if args.repeat is not None else suite.repeat
    params = ScanParams(
        agent=args.agent, model=args.model, mode=args.mode, timeout_s=args.timeout_s,
    )
    out_dir = Path(args.out or Path(_DEFAULT_RESULTS) / datetime.now().strftime("%Y%m%d-%H%M%S"))

    all_records: list[RunRecord] = []
    for case in suite.cases:
        gt = ground_truths.get(case.target)
        if gt is None:
            print(f"warning: no ground truth for {case.target!r}, skipping", file=sys.stderr)
            continue
        for scan_type in case.scan_types:
            recs = run_case(
                args.base_url, case.target, gt.origin, scan_type, repeat, params,
                poll_interval=args.poll_interval, max_wait_s=args.max_wait_s,
                on_event=lambda msg: print(msg, flush=True),
            )
            all_records.extend(recs)
            # Persist incrementally so a long run is never lost.
            out_dir.mkdir(parents=True, exist_ok=True)
            _save_records(out_dir / "records.jsonl", all_records)

    scores, failures = score_records(all_records, ground_truths)
    _write_outputs(out_dir, scores, failures)
    print(_markdown_table(scores, failures))
    print(f"\nResults written to {out_dir}")
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    records = _load_records(Path(args.records))
    ground_truths = load_ground_truth_dir(args.ground_truth)
    scores, failures = score_records(records, ground_truths)
    out_dir = Path(args.out) if args.out else Path(args.records).parent
    _write_outputs(out_dir, scores, failures)
    print(_markdown_table(scores, failures))
    print(f"\nScores written to {out_dir}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m safetywebbing.benchmark")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run", help="run a suite against a running server")
    pr.add_argument("--suite", default="benchmark/suites/default.json")
    pr.add_argument("--ground-truth", default=_DEFAULT_GT_DIR)
    pr.add_argument("--base-url", default="http://127.0.0.1:8000")
    pr.add_argument("--agent", default=None, help="agent key (default: server default)")
    pr.add_argument("--model", default=None, help="agent model id")
    pr.add_argument("--mode", default="docker", choices=["docker", "direct"])
    pr.add_argument("--timeout-s", type=float, default=None, help="per-scan budget")
    pr.add_argument("--repeat", type=int, default=None, help="override suite repeat")
    pr.add_argument("--poll-interval", type=float, default=3.0)
    pr.add_argument("--max-wait-s", type=float, default=3600.0)
    pr.add_argument("--out", default=None, help="results dir (default: timestamped)")
    pr.set_defaults(func=_cmd_run)

    ps = sub.add_parser("score", help="score saved records.jsonl (no server needed)")
    ps.add_argument("records", help="path to records.jsonl")
    ps.add_argument("--ground-truth", default=_DEFAULT_GT_DIR)
    ps.add_argument("--out", default=None, help="output dir (default: alongside records)")
    ps.set_defaults(func=_cmd_score)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
