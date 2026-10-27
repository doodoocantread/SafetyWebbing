"""Benchmark plumbing in the direct engine and the audit log: the agent starts in an empty
directory, and benchmark runs are tagged in the audit log without changing their scan_type."""

import json
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from safetywebbing.audit import read_entries
from safetywebbing.benchmark.audit import (
    BENCHMARK_PROJECT,
    is_benchmark_entry,
    record_benchmark_event,
)
from safetywebbing.engines.base import ScanFailed
from safetywebbing.engines.local import LocalAgentEngine

# A stub agent that reports where it was started and what it could see there.
_CWD_STUB = textwrap.dedent(
    """
    import argparse, json, os, pathlib
    p = argparse.ArgumentParser()
    for a in ("--goal", "--target", "--backend", "--run-id", "--runs-root",
              "--workspace-root", "--max-decisions", "--model"):
        p.add_argument(a)
    a = p.parse_args()
    run = pathlib.Path(a.runs_root) / a.run_id
    (run / "traces").mkdir(parents=True)
    (run / "summary.json").write_text(json.dumps({
        "run_id": a.run_id, "goal": a.goal, "targets": [a.target], "status": "completed",
        "tasks": [], "observations": [],
        "cwd": os.getcwd(), "cwd_listing": sorted(os.listdir(os.getcwd())),
    }), encoding="utf-8")
    """
)


def _engine(tmp_path, **kw) -> LocalAgentEngine:
    stub = tmp_path / "cwd_stub.py"
    stub.write_text(_CWD_STUB, encoding="utf-8")
    return LocalAgentEngine(runs_root=tmp_path / "runs", agent_cmd=[sys.executable, str(stub)], **kw)


# --- empty working directory --------------------------------------------------


async def test_default_cwd_is_the_parent_of_runs(tmp_path):
    result = await _engine(tmp_path).run(target="http://127.0.0.1:3000", goal="g", run_id="r1")
    assert Path(result.summary["cwd"]).resolve() == tmp_path.resolve()


async def test_empty_cwd_starts_the_agent_in_an_empty_scratch_dir(tmp_path):
    (tmp_path / "answer-key.txt").write_text("secret", encoding="utf-8")  # beside runs/
    result = await _engine(tmp_path, empty_cwd=True).run(
        target="http://127.0.0.1:3000", goal="g", run_id="r2"
    )
    cwd = Path(result.summary["cwd"])
    assert cwd.resolve() != tmp_path.resolve()
    assert result.summary["cwd_listing"] == []  # nothing from the repo/project is in view
    assert not cwd.exists()  # scratch dir removed once the agent is done


async def test_empty_cwd_dir_is_removed_even_when_the_agent_times_out(tmp_path, monkeypatch):
    eng = LocalAgentEngine(
        runs_root=tmp_path / "runs",
        agent_cmd=[sys.executable, "-c", "import time; time.sleep(60)"],
        empty_cwd=True,
        timeout_s=1.0,
    )
    created: list[Path] = []
    real = tempfile.TemporaryDirectory

    class Spy(real):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(Path(self.name))

    monkeypatch.setattr(tempfile, "TemporaryDirectory", Spy)
    with pytest.raises(ScanFailed, match="timed out"):
        await eng.run(target="http://127.0.0.1:3000", goal="g", run_id="r3")
    assert len(created) == 1
    assert not created[0].exists()


# --- audit tagging ------------------------------------------------------------


def test_benchmark_event_is_tagged_but_keeps_the_real_scan_type(tmp_path):
    runs = tmp_path / "runs"
    record_benchmark_event(
        runs, event="scan_requested", run_id="bench-1", target="http://127.0.0.1:3000",
        goal="goal", scan_type="sqli", suite="pilot-1", target_id="juice-shop",
        config="default", trial=2, agent="pentestgpt", mode="direct", model="claude-haiku-5-5",
    )
    (entry,) = read_entries(runs)
    assert entry["scan_type"] == "sqli"  # history and goal templates still key off this
    assert entry["project"] == BENCHMARK_PROJECT
    assert entry["benchmark"] == {"suite": "pilot-1", "target": "juice-shop", "config": "default", "trial": 2}
    assert entry["mode"] == "direct" and entry["model"] == "claude-haiku-5-5"
    assert is_benchmark_entry(entry)


def test_ordinary_scan_entries_are_not_benchmark_entries(tmp_path):
    from safetywebbing.audit import record_scan

    runs = tmp_path / "runs"
    record_scan(runs, event="scan_requested", run_id="live-1", target="http://127.0.0.1:3000",
                goal="g", scan_type="sqli", project="benchmark")  # label alone is not enough
    record_scan(runs, event="scan_requested", run_id="live-2", target="http://127.0.0.1:3000",
                goal="g", scan_type="sqli", project="My app")
    assert [is_benchmark_entry(e) for e in read_entries(runs)] == [False, False]
    json.dumps(read_entries(runs))  # entries stay plain JSON
