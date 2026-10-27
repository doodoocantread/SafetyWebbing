"""Turn recorded trials into the payload behind the /benchmark page.

Everything here follows PROTOCOL.md: rates are counts with a Wilson interval, inconclusive runs
are counted but never enter a rate, and a cell whose runs are all smoke/pilot gets NO pass/fail
verdict (pilot results are "not used to report results", section 8). The verdict vocabulary:

    pass | fail          a frozen-threshold comparison on enough valid runs
    pilot_only           numbers shown, but no verdict: smoke/pilot runs
    insufficient         fewer than 70% of the cell's runs were valid (T5): no rate is shown
    report_only          no threshold is defined for this cell
    no_manifest          the target/config has no ground truth yet: the runs are listed, not scored
"""

from __future__ import annotations

import re
import subprocess
from collections import Counter, defaultdict
from fractions import Fraction
from pathlib import Path
from typing import Any

from .manifest import Manifest, ManifestError, load_manifest
from .result import TrialResult, load_trials, sha256_file
from .scorer import ScoredTrial, score_trial
from .stats import wilson_interval

# Suites whose results are shown but never judged against the thresholds (PROTOCOL.md section 8).
PILOT_SUITES = frozenset({"smoke", "pilot"})

# PROTOCOL.md section 4. The single place these numbers live in code; the test suite pins them to
# the document so the two cannot drift apart silently.
T1_MIN: dict[tuple[str, str, str], Fraction] = {
    ("juice-shop", "default", "sqli"): Fraction(1, 3),
    ("dvwa", "low", "sqli"): Fraction(1, 2),
    ("dvwa", "low", "xss"): Fraction(1, 2),
}
T2_MIN = Fraction(3, 4)  # reported / exploited
T3_MAX = Fraction(1, 5)  # runs with a false positive on a `safe` control
T5_MIN_VALID = Fraction(7, 10)  # valid runs / all runs in a cell
SMALL_SAMPLE = 3  # fewer valid runs than this: the page warns that n is too small to conclude

_PROTOCOL_VERSION_RE = re.compile(r"bản nháp (v\d+(?:\.\d+)*)")


def _rate(k: int, n: int) -> dict[str, Any]:
    ci = wilson_interval(k, n)
    return {"k": k, "n": n, "rate": (k / n) if n else None, "ci": list(ci) if ci else None}


def _git_head(repo: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() or None


def load_manifests_with_hash(directory: Path) -> dict[tuple[str, str], tuple[Manifest, str]]:
    """(target, config) -> (manifest, sha256 of its file). Same duplicate rule as manifest.py."""
    out: dict[tuple[str, str], tuple[Manifest, str]] = {}
    for path in sorted(directory.glob("*.toml")) if directory.is_dir() else []:
        m = load_manifest(path)
        key = (m.target, m.config)
        if key in out:
            raise ManifestError(f"{path}: duplicate manifest for {key}")
        out[key] = (m, sha256_file(path))
    return out


def _cell_stats(
    key: tuple[str, str, str, str, str],
    scored: list[ScoredTrial],
    manifest: Manifest | None,
) -> dict[str, Any]:
    target, config, scan_type, agent, model = key
    valid = [t for t in scored if not t.inconclusive]
    failure_kinds = Counter(t.failure_kind or "unknown" for t in scored if t.inconclusive)
    has_manifest = manifest is not None
    pilot = all(t.suite in PILOT_SUITES for t in scored)
    sufficient = bool(valid) and Fraction(len(valid), len(scored)) >= T5_MIN_VALID

    exploit = fidelity = false_positive = None
    if has_manifest and sufficient:
        pairs = [o for t in valid for o in t.outcomes]
        exploit = _rate(sum(o.exploited for o in pairs), len(pairs))
        exploited = [o for o in pairs if o.exploited]
        fidelity = _rate(sum(o.reported for o in exploited), len(exploited)) if exploited else None
        if manifest.controls():
            false_positive = _rate(sum(bool(t.false_positives) for t in valid), len(valid))

    t1_min = T1_MIN.get((target, config, scan_type))
    if not has_manifest:
        verdict = "no_manifest"
    elif not sufficient:
        verdict = "insufficient"
    elif pilot:
        verdict = "pilot_only"
    elif t1_min is None:
        verdict = "report_only"
    else:
        verdict = "pass" if Fraction(exploit["k"], exploit["n"]) >= t1_min else "fail"

    return {
        "target": target, "config": config, "scan_type": scan_type, "agent": agent, "model": model,
        "runs": len(scored), "valid": len(valid), "inconclusive": len(scored) - len(valid),
        "failure_kinds": dict(failure_kinds),
        "small_sample": len(valid) < SMALL_SAMPLE,
        "suites": sorted({t.suite for t in scored}),
        "scored": has_manifest and sufficient,
        "verdict": verdict,
        "t1_min": float(t1_min) if t1_min is not None else None,
        "exploit": exploit, "fidelity": fidelity, "false_positive": false_positive,
        "cost_usd": round(sum(t.cost_usd for t in scored), 4),
        "mean_wall_s": round(sum(t.wall_duration_s for t in scored) / len(scored), 1),
    }


def build_payload(
    *, results_dir: Path, targets_dir: Path, protocol_path: Path, repo_root: Path
) -> dict[str, Any]:
    trials: list[TrialResult] = load_trials(results_dir)
    manifests = load_manifests_with_hash(targets_dir)
    protocol_sha = sha256_file(protocol_path) if protocol_path.is_file() else None
    protocol_text = protocol_path.read_text(encoding="utf-8") if protocol_path.is_file() else ""
    version = _PROTOCOL_VERSION_RE.search(protocol_text)
    head = _git_head(repo_root)

    scored: list[ScoredTrial] = []
    trial_rows: list[dict[str, Any]] = []
    for t in trials:
        entry = manifests.get((t.target, t.config))
        manifest, manifest_sha = entry if entry else (None, None)
        s = score_trial(t, manifest)
        scored.append(s)
        p = t.provenance
        trial_rows.append({
            **s.model_dump(),
            "provenance": {
                "repo_commit": p.repo_commit, "repo_dirty": p.repo_dirty,
                "target_reference": p.target_reference,
                # Inputs that decide the score changed since this run: the result is stale.
                "inputs_changed": (p.protocol_sha256 != protocol_sha)
                or (manifest_sha is not None and p.manifest_sha256 != manifest_sha),
                "commit_differs": bool(head) and p.repo_commit != head,
            },
        })

    groups: dict[tuple[str, str, str, str, str], list[ScoredTrial]] = defaultdict(list)
    for s in scored:
        groups[(s.target, s.config, s.scan_type, s.agent, s.model)].append(s)
    cells = [
        _cell_stats(key, group, (manifests.get((key[0], key[1])) or (None, None))[0])
        for key, group in sorted(groups.items())
    ]

    return {
        "protocol": {
            "sha256": protocol_sha, "version": version.group(1) if version else None,
            "frozen": any(t.suite not in PILOT_SUITES for t in trials),
        },
        "repo": {"head": head},
        "thresholds": {
            "t1": {f"{k[0]}/{k[1]}/{k[2]}": float(v) for k, v in T1_MIN.items()},
            "t2_min": float(T2_MIN), "t3_max": float(T3_MAX), "t5_min_valid": float(T5_MIN_VALID),
            "small_sample": SMALL_SAMPLE,
        },
        "manifests": [
            {
                "target": m.target, "config": m.config, "reference": m.reference, "sha256": sha,
                "vulns": [
                    {"id": v.id, "title": v.title, "scan_type": v.scan_type, "cwe": v.cwe,
                     "expect": v.expect, "scoring": v.scoring, "sink": v.sink,
                     "requires_login": v.requires_login}
                    for v in m.vulns
                ],
            }
            for m, sha in manifests.values()
        ],
        "summary": {
            "runs": len(scored),
            "valid": sum(not s.inconclusive for s in scored),
            "inconclusive": sum(s.inconclusive for s in scored),
            "failure_kinds": dict(Counter(s.failure_kind or "unknown" for s in scored if s.inconclusive)),
            "cost_usd": round(sum(s.cost_usd for s in scored), 4),
            "pilot_only": all(s.suite in PILOT_SUITES for s in scored) if scored else True,
        },
        "cells": cells,
        "trials": trial_rows,
    }
