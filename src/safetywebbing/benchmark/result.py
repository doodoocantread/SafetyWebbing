"""One recorded benchmark trial: what ran, what it produced, and what produced it.

A trial is saved as `benchmark/results/<run_id>.json` and committed, so the page (and a
teacher) can read the evidence without re-running anything (PROTOCOL.md section 7). The full
labeled Report is stored, not a summary of it: scoring must be able to test oracle patterns
against EVERY observation, including the ones the labeler rated "info".
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from ..models import Report

# Why a run did not complete. `safety_filter`: the model provider's own cyber safeguards refused
# the request. `agent_error`: the agent (or its vendored planner) died on its own. Neither is
# "no vulnerabilities found" — both are inconclusive (PROTOCOL.md section 5).
FailureKind = Literal["safety_filter", "agent_error"]

_SAFETY_FILTER_MARK = "safeguards flagged"


class Provenance(BaseModel):
    """What this result was produced with, so a stale or mismatched one is visible."""

    repo_commit: str
    repo_dirty: bool = False
    protocol_sha256: str
    manifest_sha256: str | None = None  # None: no manifest exists for this target/config yet
    target_reference: str  # the target build actually run (version / commit)


class TrialResult(BaseModel):
    run_id: str
    suite: str  # "smoke" | "pilot" | "stage-a" ... — only stage-a onwards freezes thresholds
    target: Literal["juice-shop", "dvwa"]
    config: str
    scan_type: str
    agent: str
    mode: str
    model: str
    trial: int = Field(ge=1)
    started_at: str
    status: str  # completed | failed | error — the run's own status, as reported
    failure_kind: FailureKind | None = None
    error: str | None = None
    wall_duration_s: float = 0.0
    cost_usd: float = 0.0
    labeled_by: str = "none"
    # Challenges the target's own tracker flipped to solved DURING this trial (before/after
    # snapshot). Independent of the agent's and the labeler's claims.
    oracle_newly_solved: list[str] = Field(default_factory=list)
    # Raw hits of the trace-leak detector. UNREVIEWED: a hit is a prompt to look, not a verdict.
    leak_flags: list[str] = Field(default_factory=list)
    provenance: Provenance
    report: Report | None = None


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify_failure(run_dir: Path, status: str) -> FailureKind | None:
    """Tell a provider refusal from an agent crash by what the trace recorded.

    Completed runs have no failure. For the rest, the Anthropic safeguard refusal leaves a
    recognisable sentence in the trace; anything else is the agent's own error."""
    if status == "completed":
        return None
    for events in sorted((run_dir / "traces").glob("*/events.jsonl")):
        try:
            if _SAFETY_FILTER_MARK in events.read_text(encoding="utf-8"):
                return "safety_filter"
        except OSError:
            continue
    return "agent_error"


class ResultError(ValueError):
    """A result file is unreadable or invalid. Names the file so the fix is obvious."""


def load_trial(path: Path) -> TrialResult:
    try:
        return TrialResult.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:  # json and pydantic errors are both ValueErrors
        raise ResultError(f"{path}: {exc}") from None


def load_trials(directory: Path) -> list[TrialResult]:
    """Every `*.json` result in `directory`, oldest first. A missing directory is empty."""
    if not directory.is_dir():
        return []
    trials = [load_trial(p) for p in sorted(directory.glob("*.json"))]
    seen: set[str] = set()
    for t in trials:
        if t.run_id in seen:
            raise ResultError(f"duplicate run_id {t.run_id!r} in {directory}")
        seen.add(t.run_id)
    return sorted(trials, key=lambda t: t.started_at)


def save_trial(trial: TrialResult, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{trial.run_id}.json"
    path.write_text(trial.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path
