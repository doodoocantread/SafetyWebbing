"""Score one recorded trial against its ground-truth manifest (PROTOCOL.md section 5).

Two questions, answered independently so one cannot hide the other:
  - exploited: did an ORACLE confirm the weakness? The target's own solved-state, or a
    request/response pair in the trace. Neither the agent's words nor the labeler's verdict count.
  - reported: does the SafetyWebbing report carry a finding for it (same CWE, same endpoint)?
    This measures the adapter + labeler, not the agent.

Pure functions over already-recorded data: no network, no LLM, deterministic.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

from ..models import Finding, Severity
from .manifest import (
    Endpoint,
    FileOracle,
    JuiceChallengeOracle,
    KeyOracle,
    Manifest,
    TraceMatchOracle,
    Vuln,
)
from .result import FailureKind, TrialResult

_LOW = Severity.low.rank
_HIGH = Severity.high.rank
# Parameter names shorter than this ("q", "id") appear in almost any command line, so matching
# on them would credit findings that never touched the parameter. The path still has to match.
_MIN_PARAM_LEN = 3


class VulnOutcome(BaseModel):
    vuln_id: str
    title: str
    scan_type: str
    exploited: bool
    reported: bool


class ScoredTrial(BaseModel):
    run_id: str
    suite: str
    target: str
    config: str
    scan_type: str
    agent: str
    model: str
    trial: int
    started_at: str
    status: str
    failure_kind: FailureKind | None
    error: str | None
    wall_duration_s: float
    cost_usd: float
    labeled_by: str
    leak_flags: list[str]
    # Not completed => the result cannot say "nothing found". Excluded from every rate.
    inconclusive: bool
    # False when no manifest exists for this target/config: the run is shown, but not scored.
    scored: bool
    outcomes: list[VulnOutcome]
    false_positives: list[str]  # ids of `safe` controls that drew a high/critical finding
    findings_total: int
    unmatched: int  # findings (>= low) on no manifest endpoint: unverified, NOT false positives
    oracle_newly_solved: list[str]
    oracle_off_manifest: list[str]  # solved challenges that no manifest entry lists


def _path_needle(endpoint: Endpoint) -> str:
    """The fixed part of a templated path: `/rest/basket/{id}` -> `/rest/basket/`."""
    return endpoint.path.split("{", 1)[0]


def touches(finding: Finding, endpoint: Endpoint) -> bool:
    """Did this finding's request go to this endpoint (and carry its parameter, if a
    distinctive one is named)? A heuristic over the recorded shell command."""
    request = finding.request or ""
    if _path_needle(endpoint) not in request:
        return False
    param = endpoint.param
    if param and len(param) >= _MIN_PARAM_LEN:
        return re.search(rf"(?<![A-Za-z0-9_]){re.escape(param)}(?![A-Za-z0-9_])", request) is not None
    return True


def _oracle_satisfied(
    oracle: JuiceChallengeOracle | FileOracle | TraceMatchOracle,
    trial: TrialResult,
    findings: list[Finding],
) -> bool:
    if isinstance(oracle, KeyOracle):  # juice_challenge or file_oracle: server-confirmed key
        return oracle.key in trial.oracle_newly_solved
    # trace_match: when both patterns are given they must hold on the SAME request/response pair.
    for f in findings:
        if oracle.request_pattern and not re.search(oracle.request_pattern, f.request or ""):
            continue
        if oracle.response_pattern and not re.search(oracle.response_pattern, f.response or ""):
            continue
        return True
    return False


def _exploited(vuln: Vuln, trial: TrialResult, findings: list[Finding]) -> bool:
    return any(_oracle_satisfied(o, trial, findings) for o in vuln.oracles)


def _reported(vuln: Vuln, findings: list[Finding]) -> bool:
    for f in findings:
        label = f.label
        if label is None or label.severity.rank < _LOW:
            continue
        if (label.cwe or "").upper() != vuln.cwe:
            continue
        if any(touches(f, ep) for ep in vuln.endpoints):
            return True
    return False


def _false_positives(manifest: Manifest, findings: list[Finding]) -> list[str]:
    hits = []
    for control in manifest.controls():
        if any(
            f.label is not None
            and f.label.severity.rank >= _HIGH
            and any(touches(f, ep) for ep in control.endpoints)
            for f in findings
        ):
            hits.append(control.id)
    return hits


def score_trial(trial: TrialResult, manifest: Manifest | None) -> ScoredTrial:
    findings = list(trial.report.findings) if trial.report else []
    outcomes: list[VulnOutcome] = []
    false_positives: list[str] = []
    unmatched = 0
    off_manifest = sorted(trial.oracle_newly_solved)

    if manifest is not None:
        outcomes = [
            VulnOutcome(
                vuln_id=v.id, title=v.title, scan_type=v.scan_type,
                exploited=_exploited(v, trial, findings), reported=_reported(v, findings),
            )
            for v in manifest.expected_for(trial.scan_type)
        ]
        false_positives = _false_positives(manifest, findings)
        every_endpoint = [ep for v in manifest.vulns for ep in v.endpoints]
        unmatched = sum(
            1 for f in findings
            if f.label is not None and f.label.severity.rank >= _LOW
            and not any(touches(f, ep) for ep in every_endpoint)
        )
        listed = {
            o.key for v in manifest.vulns for o in v.oracles if isinstance(o, KeyOracle)
        }
        off_manifest = sorted(k for k in trial.oracle_newly_solved if k not in listed)

    return ScoredTrial(
        run_id=trial.run_id, suite=trial.suite, target=trial.target, config=trial.config,
        scan_type=trial.scan_type, agent=trial.agent, model=trial.model, trial=trial.trial,
        started_at=trial.started_at, status=trial.status, failure_kind=trial.failure_kind,
        error=trial.error, wall_duration_s=trial.wall_duration_s, cost_usd=trial.cost_usd,
        labeled_by=trial.labeled_by, leak_flags=trial.leak_flags,
        inconclusive=trial.status != "completed", scored=manifest is not None,
        outcomes=outcomes, false_positives=false_positives, findings_total=len(findings),
        unmatched=unmatched, oracle_newly_solved=list(trial.oracle_newly_solved),
        oracle_off_manifest=off_manifest,
    )
