"""Drive scans over the SafetyWebbing HTTP API and collect their reports.

Stdlib only (urllib) so the benchmark adds no dependency to the app. The harness does
NOT bypass any safety gate: every scan goes through `POST /api/scan`, which enforces
the loopback whitelist and the fixed per-scan-type goal. The server must already be
running (see BENCHMARK.md), with the target containers up.

A `RunRecord` is one scan: its run_id, final status, cost/time, and the labeled report
dict (or None if the scan failed). `run_case` repeats a scan N times; `run_suite` walks
a whole suite and returns every record.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any

_DONE_STATES = {"done", "error", "cancelled"}


class BenchmarkRunError(RuntimeError):
    """A scan could not be started or did not finish in time."""


@dataclass
class RunRecord:
    target: str
    scan_type: str
    origin: str
    run_id: str
    status: str
    cost_usd: float = 0.0
    wall_duration_s: float = 0.0
    error: str | None = None
    report: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return self.status == "done" and self.report is not None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _post(base_url: str, path: str, body: dict[str, Any], timeout: float = 30.0) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        base_url.rstrip("/") + path, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise BenchmarkRunError(f"POST {path} -> {exc.code}: {detail}") from None
    except urllib.error.URLError as exc:
        raise BenchmarkRunError(f"POST {path} failed: {exc.reason} (is the server running?)") from None


def _get(base_url: str, path: str, timeout: float = 30.0) -> dict[str, Any]:
    req = urllib.request.Request(base_url.rstrip("/") + path, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


@dataclass
class ScanParams:
    agent: str | None = None
    model: str | None = None
    mode: str = "docker"
    timeout_s: float | None = None
    project: str | None = "benchmark"
    extra: dict[str, Any] = field(default_factory=dict)  # e.g. llm_provider / llm_api_key


def run_scan(
    base_url: str, origin: str, scan_type: str, params: ScanParams,
    poll_interval: float = 3.0, max_wait_s: float = 3600.0,
) -> RunRecord:
    """Start one scan and block until it finishes (or `max_wait_s` elapses)."""
    body: dict[str, Any] = {"target": origin, "scan_type": scan_type, "mode": params.mode}
    if params.agent:
        body["agent"] = params.agent
    if params.model:
        body["model"] = params.model
    if params.timeout_s is not None:
        body["timeout_s"] = params.timeout_s
    if params.project:
        body["project"] = params.project
    body.update(params.extra)

    started = _post(base_url, "/api/scan", body)
    job_id = started["job_id"]
    run_id = started["run_id"]

    deadline = time.monotonic() + max_wait_s
    job: dict[str, Any] = {"status": "queued"}
    while time.monotonic() < deadline:
        job = _get(base_url, f"/api/scan/{job_id}")
        if job.get("status") in _DONE_STATES:
            break
        time.sleep(poll_interval)
    else:
        raise BenchmarkRunError(f"scan {run_id} did not finish within {max_wait_s:.0f}s")

    report = job.get("report")
    cost = 0.0
    wall = 0.0
    if isinstance(report, dict):
        cost = float(report.get("cost_usd") or 0.0)
        wall = float(report.get("wall_duration_s") or 0.0)
    return RunRecord(
        target="", scan_type=scan_type, origin=origin, run_id=run_id,
        status=str(job.get("status")), cost_usd=cost, wall_duration_s=wall,
        error=job.get("error"), report=report if isinstance(report, dict) else None,
    )


def run_case(
    base_url: str, target: str, origin: str, scan_type: str, repeat: int, params: ScanParams,
    poll_interval: float = 3.0, max_wait_s: float = 3600.0,
    on_event=None,
) -> list[RunRecord]:
    """Run one (target, scan_type) `repeat` times. `on_event(str)` is an optional
    progress callback."""
    records: list[RunRecord] = []
    for i in range(1, repeat + 1):
        if on_event:
            on_event(f"[{target}/{scan_type}] run {i}/{repeat} starting…")
        try:
            rec = run_scan(base_url, origin, scan_type, params, poll_interval, max_wait_s)
            rec.target = target
        except BenchmarkRunError as exc:
            rec = RunRecord(target=target, scan_type=scan_type, origin=origin,
                            run_id="", status="start_error", error=str(exc))
        if on_event:
            on_event(f"[{target}/{scan_type}] run {i}/{repeat} -> {rec.status}"
                     + (f" ({rec.error})" if rec.error else ""))
        records.append(rec)
    return records
