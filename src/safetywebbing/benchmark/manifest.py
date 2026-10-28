"""Ground-truth manifest: which weaknesses a benchmark target is KNOWN to have (or not have).

One TOML file per (target, config), e.g. `juice-shop.toml`, `dvwa-low.toml`. TOML because
it parses with the stdlib — the host app adds no dependency for the benchmark.

Two ideas the schema makes explicit, because scoring depends on them:
  - `oracles` decide whether an agent really EXPLOITED a weakness (an independent check:
    the target's own solved-state, or a pattern in the recorded HTTP trace). The report
    layer (labeler) is scored separately, so a labeler mistake cannot hide a real exploit.
  - `scoring` separates weaknesses that count from ones an HTTP-only agent cannot reach
    (browser-side XSS) or that no scan type asks about. Those stay visible on the page but
    are excluded from recall, so an agent is not blamed for what it cannot do.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ..config import SCAN_TYPES

_CWE_RE = re.compile(r"CWE-\d{1,5}")
_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,63}")
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


class JuiceChallengeOracle(BaseModel):
    """Juice Shop tracks solved challenges server-side (`GET /api/Challenges`, field
    `solved`). Snapshot it before and after a trial; a newly solved `key` means the agent
    really did it — no matter what the agent or the labeler claims."""

    kind: Literal["juice_challenge"]
    key: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]{2,63}$")


class FileOracle(BaseModel):
    """A target that confirms exploitation server-side by appending a marker to a file the
    runner snapshots before/after a trial (e.g. VulnShop writes the exploited vuln id, V01…,
    to data/oracle.jsonl). Like `juice_challenge`, `key` is matched against the trial's
    `oracle_newly_solved`; unlike it, it is not tied to Juice Shop's /api/Challenges."""

    kind: Literal["file_oracle"]
    key: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]{2,63}$")


class TraceMatchOracle(BaseModel):
    """A request/response pair in the agent's trace that proves exploitation (used where
    the target has no solved-state, e.g. DVWA). Patterns are regexes; when both are given,
    BOTH must match the same request/response pair."""

    kind: Literal["trace_match"]
    request_pattern: str | None = None
    response_pattern: str | None = None

    @field_validator("request_pattern", "response_pattern")
    @classmethod
    def _compiles(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid regex {value!r}: {exc}") from None
        return value

    @model_validator(mode="after")
    def _has_a_pattern(self) -> TraceMatchOracle:
        if not (self.request_pattern or self.response_pattern):
            raise ValueError("trace_match needs a request_pattern and/or a response_pattern")
        return self


Oracle = Annotated[
    JuiceChallengeOracle | FileOracle | TraceMatchOracle, Field(discriminator="kind")
]
# Oracle kinds whose `key` is matched against the trial's server-confirmed solved set.
KeyOracle = (JuiceChallengeOracle, FileOracle)


class Endpoint(BaseModel):
    """Where the weakness lives. The scorer matches a reported finding to this."""

    method: str | None = None  # None = any method
    path: str  # URL path, e.g. /rest/products/search
    param: str | None = None  # the vulnerable parameter, when there is one

    @field_validator("method")
    @classmethod
    def _method(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.upper()
        if value not in _METHODS:
            raise ValueError(f"unknown HTTP method {value!r}")
        return value

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError(f"path must start with '/': {value!r}")
        return value


class Vuln(BaseModel):
    id: str
    title: str
    # The scan type whose goal asks for this weakness. A `general` scan is scored against
    # every scored weakness, whatever its own scan_type.
    scan_type: str
    cwe: str
    endpoints: list[Endpoint] = Field(min_length=1)
    # `vulnerable`: the weakness exists. `safe`: a deliberate control (e.g. DVWA at the
    # `impossible` level) — a high/critical finding on it is a false positive.
    expect: Literal["vulnerable", "safe"] = "vulnerable"
    # `scored` counts toward recall. `out_of_capability`: exists, but an HTTP-only agent
    # cannot reach it (runs in a browser). `out_of_scope`: no scan type asks about it.
    scoring: Literal["scored", "out_of_capability", "out_of_scope"] = "scored"
    oracles: list[Oracle] = Field(default_factory=list)  # exploited if ANY one is satisfied
    # Weaknesses sharing one root cause (same code path) share a `sink`, so the scorer can
    # report both per-challenge and per-root-cause results.
    sink: str | None = None
    requires_login: bool = False
    notes: str = ""

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID_RE.fullmatch(value):
            raise ValueError(f"id must be lowercase letters, digits and dashes: {value!r}")
        return value

    @field_validator("scan_type")
    @classmethod
    def _scan_type(cls, value: str) -> str:
        if value not in SCAN_TYPES:
            raise ValueError(f"unknown scan_type {value!r}; valid: {', '.join(sorted(SCAN_TYPES))}")
        return value

    @field_validator("cwe")
    @classmethod
    def _cwe(cls, value: str) -> str:
        if not _CWE_RE.fullmatch(value):
            raise ValueError(f"cwe must look like 'CWE-89', got {value!r}")
        return value

    @model_validator(mode="after")
    def _oracle_rules(self) -> Vuln:
        if self.expect == "safe":
            if self.oracles:
                raise ValueError(f"{self.id}: a 'safe' control has nothing to exploit, so no oracles")
            if self.scoring != "scored":
                raise ValueError(f"{self.id}: a 'safe' control must be scored (it measures false positives)")
        elif self.scoring == "scored" and not self.oracles:
            # Without an oracle "did the agent exploit it?" has no independent answer, and
            # the benchmark would fall back on the agent's own claim.
            raise ValueError(f"{self.id}: a scored, vulnerable entry needs at least one oracle")
        return self


class Manifest(BaseModel):
    target: Literal["juice-shop", "dvwa", "vulnshop"]
    # Which configuration of the target this describes ("default", or a DVWA security level).
    config: str
    # Exactly which build was read to write this manifest (version / commit). Results record
    # the version actually run, so a mismatch is visible instead of silent.
    reference: str
    vulns: list[Vuln] = Field(alias="vuln", min_length=1)

    model_config = {"populate_by_name": True}

    @model_validator(mode="after")
    def _consistent(self) -> Manifest:
        seen: set[str] = set()
        for v in self.vulns:
            if v.id in seen:
                raise ValueError(f"duplicate vuln id {v.id!r}")
            seen.add(v.id)
            if self.target != "juice-shop" and any(
                o.kind == "juice_challenge" for o in v.oracles
            ):
                raise ValueError(f"{v.id}: juice_challenge oracles only apply to juice-shop")
        return self

    def scored(self) -> list[Vuln]:
        """Weaknesses that count toward recall (vulnerable and reachable)."""
        return [v for v in self.vulns if v.expect == "vulnerable" and v.scoring == "scored"]

    def controls(self) -> list[Vuln]:
        """Deliberately safe entries: findings on these are false positives."""
        return [v for v in self.vulns if v.expect == "safe"]

    def expected_for(self, scan_type: str) -> list[Vuln]:
        """What a scan of `scan_type` is expected to find. `general` expects everything."""
        if scan_type not in SCAN_TYPES:
            raise ValueError(f"unknown scan_type {scan_type!r}")
        return [v for v in self.scored() if scan_type == "general" or v.scan_type == scan_type]


class ManifestError(ValueError):
    """A manifest file is unreadable or invalid. Names the file so the fix is obvious."""


def load_manifest(path: Path) -> Manifest:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"{path}: {exc}") from None
    try:
        return Manifest.model_validate(data)
    except ValueError as exc:  # pydantic.ValidationError is a ValueError
        raise ManifestError(f"{path}: {exc}") from None


def load_manifests(directory: Path) -> dict[tuple[str, str], Manifest]:
    """Every `*.toml` manifest in `directory`, keyed by (target, config)."""
    out: dict[tuple[str, str], Manifest] = {}
    for path in sorted(directory.glob("*.toml")):
        m = load_manifest(path)
        key = (m.target, m.config)
        if key in out:
            raise ManifestError(f"{path}: duplicate manifest for {key}")
        out[key] = m
    return out
