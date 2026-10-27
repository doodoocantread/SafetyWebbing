"""Tests for the hackingBuddy wrapper's LLM resolution (agent_image_hackingbuddy).

Pure env logic — no Docker, no hackingBuddy, no network. Pins how a scan's model
choice + the server's provider key become a litellm model string, including the
"use Claude via the Anthropic API" path, and (below) the claude_oauth path that
runs hackingBuddy on the host's Claude Code session instead of any API key.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from safetywebbing_hb_agent import cli  # made importable by conftest.py
from safetywebbing_hb_agent.cli import _resolve_llm

_KEYS = ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
         "SAFETYWEBBING_HB_LLM_MODEL", "SAFETYWEBBING_HB_LLM_API_BASE")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in _KEYS:
        monkeypatch.delenv(k, raising=False)


def test_no_key_exits(monkeypatch):
    with pytest.raises(SystemExit):
        _resolve_llm("claude-sonnet-5-5")


def test_claude_id_maps_to_anthropic_api(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    api_key, model, api_base = _resolve_llm("claude-sonnet-5-5")
    assert api_key == "sk-ant"
    assert model == "anthropic/claude-sonnet-5-5"  # Claude id → Anthropic via litellm
    assert api_base is None


def test_anthropic_default_model_when_none(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    _, model, _ = _resolve_llm(None)
    assert model.startswith("anthropic/")


def test_litellm_format_model_passes_through(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    _, model, _ = _resolve_llm("anthropic/claude-3-5-sonnet-20241022")
    assert model == "anthropic/claude-3-5-sonnet-20241022"


def test_explicit_env_model_wins(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    monkeypatch.setenv("SAFETYWEBBING_HB_LLM_MODEL", "openrouter/anthropic/claude-3.5-sonnet")
    _, model, _ = _resolve_llm("claude-sonnet-5-5")
    assert model == "openrouter/anthropic/claude-3.5-sonnet"


def test_gemini_id_maps_to_gemini_provider(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    api_key, model, base = _resolve_llm("gemini-1.5-pro")
    assert api_key == "g-key"
    assert model == "gemini/gemini-1.5-pro"  # bare Gemini id → Google AI Studio via litellm
    assert base is None


def test_gemini_default_model_when_none(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    _, model, _ = _resolve_llm(None)
    assert model.startswith("gemini/")


def test_openai_bare_id_passes_through(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai")
    _, model, base = _resolve_llm("gpt-4o")
    assert model == "gpt-4o" and base is None


def test_openrouter_sets_api_base_and_default(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or")
    # a bare Claude id is NOT force-mapped under OpenRouter (routing is provider-specific)
    _, model, base = _resolve_llm("claude-sonnet-5-5")
    assert model.startswith("openrouter/")
    assert base == "https://openrouter.ai/api"


def test_anthropic_preferred_over_others(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai")
    api_key, model, _ = _resolve_llm(None)
    assert api_key == "sk-ant" and model.startswith("anthropic/")


# --- claude_oauth: runs hackingBuddy on the host's Claude Code session, no API key ----


def test_claude_credentials_present_checks_dot_credentials_json(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))  # Path.home() follows $HOME on POSIX
    assert cli._claude_credentials_present() is False
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / ".credentials.json").write_text("{}")
    assert cli._claude_credentials_present() is True


def test_build_wintermute_cmd_claude_oauth_runs_bridge_module_no_api_base():
    cmd = cli._build_wintermute_cmd(
        target="http://127.0.0.1:3000", goal="pentest", model="claude-code/claude-sonnet-5-5",
        api_base="https://ignored.example", max_rounds=20, log_dir="logs", run_id="r1",
        context_size="30000", claude_oauth=True,
    )
    assert cmd[:3] == [sys.executable, "-m", "safetywebbing_hb_agent.run_wintermute"]
    assert "--llm.api_key=unused" in cmd
    assert not any(c.startswith("--llm.api_base") for c in cmd)  # api_base is ignored on this path
    assert "--llm.model=claude-code/claude-sonnet-5-5" in cmd


def test_build_wintermute_cmd_llm_api_key_runs_wintermute_console_script():
    cmd = cli._build_wintermute_cmd(
        target="http://127.0.0.1:3000", goal="pentest", model="anthropic/claude-sonnet-5-5",
        api_base=None, max_rounds=20, log_dir="logs", run_id="r1", context_size="30000",
    )
    assert cmd[0] == "wintermute"
    assert not any(c.startswith("--llm.api_key") for c in cmd)


def test_main_claude_oauth_without_credentials_fails_clearly(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "empty-home"))
    monkeypatch.setenv("SAFETYWEBBING_LLM_AUTH", "claude_oauth")
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append((a, k)))
    runs_root = tmp_path / "runs"
    rc = cli.main([
        "--goal", "pentest", "--target", "http://127.0.0.1:3000", "--run-id", "r1",
        "--runs-root", str(runs_root),
    ])
    assert rc == 1 and calls == []  # must fail before ever spawning a process
    summary = json.loads((runs_root / "r1" / "summary.json").read_text())
    assert summary["status"] == "error"
    assert "Claude Code credentials" in summary["error"]


def test_main_claude_oauth_with_credentials_uses_bridge_model_and_no_env_file(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / ".credentials.json").write_text("{}")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SAFETYWEBBING_LLM_AUTH", "claude_oauth")

    seen_cmd = {}

    def fake_run(cmd, *, cwd, check):
        seen_cmd["cmd"] = cmd
        seen_cmd["cwd"] = cwd
        log_dir = next(Path(c.split("=", 1)[1]) for c in cmd if c.startswith("--log.log_dir="))
        # A minimal OK root span is enough to reach translate() and get status="completed".
        root_span = {
            "span_id": "root1", "parent_span_id": None, "attributes": {},
            "status": {"code": "OK"},
            "start_time": "2024-01-01T00:00:00Z", "end_time": "2024-01-01T00:00:01Z",
        }
        (log_dir / "log-1.jsonl").write_text(json.dumps(root_span) + "\n")
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    runs_root = tmp_path / "runs"
    rc = cli.main([
        "--goal", "pentest", "--target", "http://127.0.0.1:3000", "--run-id", "r1",
        "--runs-root", str(runs_root),
    ])
    assert rc == 0
    cmd = seen_cmd["cmd"]
    assert cmd[:3] == [sys.executable, "-m", "safetywebbing_hb_agent.run_wintermute"]
    assert f"--llm.model=claude-code/{cli.claude_bridge.DEFAULT_MODEL}" in cmd
    assert not (Path(seen_cmd["cwd"]) / ".env").exists()  # no API key to keep off the argv
    summary = json.loads((runs_root / "r1" / "summary.json").read_text())
    assert summary["model"] == cli.claude_bridge.DEFAULT_MODEL  # display model, not the bridge-prefixed one
