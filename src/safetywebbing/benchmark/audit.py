"""Audit entries for benchmark runs.

A benchmark scan goes through the same audit log as any scan (safety rule 5), tagged so the
History page and the benchmark runner can tell it apart. It reuses the existing `project`
field instead of a new scan type: `scan_type` must stay the real one (sqli/xss/auth/general)
because history and the goal template key off it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..audit import record_scan

BENCHMARK_PROJECT = "benchmark"


def record_benchmark_event(
    runs_root: Path,
    *,
    event: str,
    run_id: str,
    target: str,
    goal: str,
    scan_type: str,
    suite: str,
    target_id: str,
    config: str,
    trial: int,
    **extra: Any,
) -> None:
    """Append one audit entry for a benchmark run. `suite` names the benchmark run set,
    `target_id`/`config` the manifest it is scored against, `trial` the repeat number."""
    record_scan(
        runs_root,
        event=event,
        run_id=run_id,
        target=target,
        goal=goal,
        scan_type=scan_type,
        project=BENCHMARK_PROJECT,
        benchmark={"suite": suite, "target": target_id, "config": config, "trial": trial},
        **extra,
    )


def is_benchmark_entry(entry: dict[str, Any]) -> bool:
    return entry.get("project") == BENCHMARK_PROJECT and isinstance(entry.get("benchmark"), dict)
