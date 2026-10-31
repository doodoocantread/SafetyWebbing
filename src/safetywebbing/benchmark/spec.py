"""Ground-truth model for the benchmark.

A ground-truth file lists the vulnerabilities a target is *known* to have, one entry
per vulnerability, tagged with the scan type that should surface it. The matcher scores
a run's findings against these entries. Files live in `benchmark/ground_truth/<target>.json`
and the suite that ties targets to scan types in `benchmark/suites/<name>.json`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

VALID_SCAN_TYPES = frozenset({"sqli", "xss", "auth", "general"})

# "*" or an empty endpoint means "don't require an endpoint match" — the vuln is
# counted as found on the vuln class / CWE alone.
ANY_ENDPOINT = "*"


@dataclass(frozen=True)
class ExpectedFinding:
    """One vulnerability the target is known to have."""

    id: str
    scan_type: str
    vuln_class: str
    cwe: str | None = None
    owasp: str | None = None
    endpoint: str = ANY_ENDPOINT
    severity: str | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        if self.scan_type not in VALID_SCAN_TYPES:
            raise ValueError(
                f"expected finding {self.id!r}: unknown scan_type {self.scan_type!r}; "
                f"valid: {', '.join(sorted(VALID_SCAN_TYPES))}"
            )


@dataclass(frozen=True)
class GroundTruth:
    """All known vulnerabilities for one target."""

    target: str
    origin: str
    expected: tuple[ExpectedFinding, ...]
    description: str = ""

    def for_scan_type(self, scan_type: str) -> list[ExpectedFinding]:
        """Entries a scan of this type is expected to find.

        A `general` scan is expected to surface *everything*; a focused scan
        (sqli/xss/auth) is scored only against entries tagged with that type.
        """
        if scan_type == "general":
            return list(self.expected)
        return [e for e in self.expected if e.scan_type == scan_type]


@dataclass(frozen=True)
class SuiteCase:
    target: str
    scan_types: tuple[str, ...]


@dataclass(frozen=True)
class Suite:
    name: str
    cases: tuple[SuiteCase, ...]
    repeat: int = 1
    description: str = ""
    extra: dict = field(default_factory=dict)


def load_ground_truth(path: str | Path) -> GroundTruth:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    expected = tuple(
        ExpectedFinding(
            id=e["id"],
            scan_type=e["scan_type"],
            vuln_class=e["vuln_class"],
            cwe=e.get("cwe"),
            owasp=e.get("owasp"),
            endpoint=e.get("endpoint", ANY_ENDPOINT) or ANY_ENDPOINT,
            severity=e.get("severity"),
            notes=e.get("notes", ""),
        )
        for e in data.get("expected", [])
    )
    seen: set[str] = set()
    for e in expected:
        if e.id in seen:
            raise ValueError(f"duplicate expected-finding id {e.id!r} in {path}")
        seen.add(e.id)
    return GroundTruth(
        target=data["target"],
        origin=data["origin"],
        expected=expected,
        description=data.get("description", ""),
    )


def load_ground_truth_dir(dir_path: str | Path) -> dict[str, GroundTruth]:
    """Load every `<target>.json` in a directory, keyed by target name."""
    out: dict[str, GroundTruth] = {}
    for p in sorted(Path(dir_path).glob("*.json")):
        gt = load_ground_truth(p)
        out[gt.target] = gt
    return out


def load_suite(path: str | Path) -> Suite:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = tuple(
        SuiteCase(target=c["target"], scan_types=tuple(c["scan_types"]))
        for c in data.get("cases", [])
    )
    for c in cases:
        bad = set(c.scan_types) - VALID_SCAN_TYPES
        if bad:
            raise ValueError(f"suite case {c.target!r}: unknown scan_types {sorted(bad)}")
    return Suite(
        name=data.get("name", "suite"),
        cases=cases,
        repeat=int(data.get("repeat", 1)),
        description=data.get("description", ""),
    )
