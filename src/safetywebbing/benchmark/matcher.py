"""Match a run's findings against a target's ground truth.

Reuses the exact origin/endpoint normalization from `insights.py` so the benchmark
sees endpoints the same way the product's cross-scan dedup does (numeric/hex id
segments collapsed to `:id`, loopback host folded to `localhost`).

Matching rule for an (expected, finding) pair:
  1. kind matches  — same normalized CWE, OR the vuln-class names overlap when a CWE
     is missing on either side.
  2. endpoint matches — only enforced when BOTH the expected entry and the finding
     have a known endpoint; a missing endpoint on either side never disqualifies
     (the labeler does not always carry the request through).

Assignment is greedy and one-to-one: each finding backs at most one expected entry,
so three scans that all report the same bug count it once, not three times.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..insights import _ID_SEGMENT_RE, endpoint_of, origin_of
from .spec import ANY_ENDPOINT, ExpectedFinding

_WORD_RE = re.compile(r"[a-z0-9]+")
# Class-name tokens that carry no discriminating signal.
_STOPWORDS = frozenset({"vulnerability", "vuln", "attack", "based", "the", "a", "of", "via"})


def normalize_cwe(cwe: str | None) -> str:
    """'CWE-89', 'cwe89', ' 89 ' -> '89'; None/'' -> ''."""
    if not cwe:
        return ""
    return re.sub(r"[^0-9]", "", str(cwe))


def _class_tokens(name: str | None) -> set[str]:
    toks = {t for t in _WORD_RE.findall((name or "").lower())}
    return toks - _STOPWORDS


def _class_overlap(a: str | None, b: str | None) -> bool:
    ta, tb = _class_tokens(a), _class_tokens(b)
    return bool(ta and tb and (ta & tb))


def _normalize_endpoint(path: str) -> str:
    """Collapse id segments the same way `insights.endpoint_of` does, so an expected
    endpoint written by hand matches the one recovered from a request."""
    if not path or path == ANY_ENDPOINT:
        return ""
    segments = [":id" if _ID_SEGMENT_RE.fullmatch(s) else s for s in path.split("/") if s]
    return "/" + "/".join(segments)


def _endpoint_compatible(expected: str, finding_request: str | None) -> bool:
    exp = _normalize_endpoint(expected)
    if not exp:  # expected endpoint is "*" / empty -> class match is enough
        return True
    found = endpoint_of(finding_request)
    if not found:  # finding carries no endpoint -> don't disqualify on it
        return True
    return exp == found


def _kind_compatible(exp: ExpectedFinding, cwe: str | None, vuln_class: str | None) -> bool:
    ec, fc = normalize_cwe(exp.cwe), normalize_cwe(cwe)
    if ec and fc:
        return ec == fc
    # No CWE on one side: fall back to class-name overlap.
    return _class_overlap(exp.vuln_class, vuln_class)


@dataclass
class ExpectedOutcome:
    expected: ExpectedFinding
    found: bool = False
    matched_finding_index: int | None = None
    cwe_correct: bool = False
    owasp_correct: bool = False
    severity_delta: int | None = None  # |rank(found) - rank(expected)|, None if unknown


@dataclass
class MatchResult:
    scan_type: str
    origin_ok: bool
    outcomes: list[ExpectedOutcome] = field(default_factory=list)
    matched_finding_indexes: set[int] = field(default_factory=set)
    total_findings: int = 0

    @property
    def unmatched_finding_count(self) -> int:
        return self.total_findings - len(self.matched_finding_indexes)


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_delta(expected: str | None, found: str | None) -> int | None:
    e, f = _SEV_RANK.get((expected or "").lower()), _SEV_RANK.get((found or "").lower())
    if e is None or f is None:
        return None
    return abs(e - f)


def _finding_origin(finding: dict[str, Any]) -> str:
    """Origin of a finding, from its target or (failing that) its request URL."""
    return origin_of(finding.get("target")) or origin_of(finding.get("request"))


def match_report(
    report: dict[str, Any], gt_origin: str, expected: list[ExpectedFinding], scan_type: str
) -> MatchResult:
    """Score one run's `report` dict against the `expected` list for `scan_type`.

    `report` is a `Report.model_dump()` (findings carry `request`, `target`, and a
    nullable `label` with `cwe`/`owasp`/`severity`/`vuln_class`). Only findings on the
    target's own origin are considered, so a stray localhost:other-port is ignored.
    """
    want_origin = origin_of(gt_origin)
    findings = report.get("findings") or []

    # Keep only labeled findings on the right origin, remembering their original index.
    candidates: list[tuple[int, dict[str, Any]]] = []
    for i, f in enumerate(findings):
        label = f.get("label")
        if not label:
            continue
        if want_origin and _finding_origin(f) and _finding_origin(f) != want_origin:
            continue
        candidates.append((i, f))

    result = MatchResult(
        scan_type=scan_type,
        origin_ok=bool(want_origin),
        total_findings=len(candidates),
    )

    used: set[int] = set()
    for exp in expected:
        outcome = ExpectedOutcome(expected=exp)
        for idx, f in candidates:
            if idx in used:
                continue
            label = f["label"]
            if not _kind_compatible(exp, label.get("cwe"), label.get("vuln_class")):
                continue
            if not _endpoint_compatible(exp.endpoint, f.get("request")):
                continue
            # Match.
            used.add(idx)
            outcome.found = True
            outcome.matched_finding_index = idx
            outcome.cwe_correct = bool(
                normalize_cwe(exp.cwe)
                and normalize_cwe(exp.cwe) == normalize_cwe(label.get("cwe"))
            )
            outcome.owasp_correct = bool(
                exp.owasp and label.get("owasp")
                and exp.owasp.strip() == str(label.get("owasp")).strip()
            )
            outcome.severity_delta = _severity_delta(exp.severity, label.get("severity"))
            break
        result.outcomes.append(outcome)

    result.matched_finding_indexes = used
    return result
