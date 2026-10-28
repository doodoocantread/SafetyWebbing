"""Pipeline orchestration: RunResult → Report (ARCHITECTURE.md §5).

engine output → adapter (fact) → labeler (narrative) → Report.
"""

from __future__ import annotations

import os

from .adapter import adapt
from .engines.base import RunResult
from .labeling import HeuristicLabeler, Labeler, label_findings
from .models import Report


def default_llm_model() -> str:
    # A 4.x model: the 5.x line is refused outright on security evidence by the provider's
    # real-time cyber safeguards, which would silently drop every label back to the heuristic.
    return os.environ.get("SAFETYWEBBING_LLM_MODEL", "claude-sonnet-4-6")


def default_labeler() -> Labeler:
    """Which labeler builds a report's narrative.

    SAFETYWEBBING_LABELER chooses explicitly: `heuristic` (offline), `claude-cli` (the host's
    Claude Code login through `claude -p`, no API key) or `api` (Anthropic API, needs a key).
    Unset: the API labeler when ANTHROPIC_API_KEY is set, else the heuristic one. The CLI labeler
    is never picked implicitly: it spends the user's Claude session on every finding."""
    choice = os.environ.get("SAFETYWEBBING_LABELER", "").strip().lower()
    if choice == "heuristic":
        return HeuristicLabeler()
    if choice == "claude-cli":
        from .labeling_llm import ClaudeCLILabeler

        return ClaudeCLILabeler(model=default_llm_model())
    if choice == "api" or (not choice and os.environ.get("ANTHROPIC_API_KEY")):
        from .labeling_llm import LLMLabeler

        return LLMLabeler(model=default_llm_model())
    return HeuristicLabeler()


def build_report(result: RunResult, labeler: Labeler | None = None) -> Report:
    labeler = labeler or default_labeler()
    findings = adapt(result.summary, result.traces_dir)
    findings = label_findings(findings, labeler)
    s = result.summary
    return Report(
        run_id=result.run_id,
        goal=s.get("goal", ""),
        targets=list(s.get("targets", [])),
        status=result.status,
        engine=result.engine,
        cost_usd=float(s.get("cost_usd", 0) or 0),
        wall_duration_s=float(s.get("wall_duration_s", 0) or 0),
        error=s.get("error"),
        findings=findings,
        labeled_by=getattr(labeler, "name", "unknown"),
    )
