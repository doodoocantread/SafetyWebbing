"""Tests for the Claude Code bridge (agent_image_hackingbuddy/.../claude_bridge.py).

No network, no real `claude`, no hackingBuddy: the CLI is replaced by a tiny fake
executable that records how it was called and replays canned `--output-format json`
envelopes, so these pin the prompt we build, the tool-call parsing/validation/retry,
and the argv/env hygiene.
"""

import json
import os
import stat
import sys
from types import SimpleNamespace

import pytest
from safetywebbing_hb_agent import claude_bridge as cb  # made importable by conftest.py

TOOLS = [
    {"type": "function", "function": {
        "name": "HTTPRequest", "description": "Send an HTTP request.",
        "parameters": {"type": "object", "required": ["method", "path"],
                       "properties": {"method": {"type": "string"}, "path": {"type": "string"}}}}},
    {"type": "function", "function": {
        "name": "EndRun", "description": "Stop.", "parameters": {"type": "object", "properties": {}}}},
]


def envelope(message="ok", tool_calls=(), **extra):
    env = {
        "type": "result", "is_error": False, "total_cost_usd": 0.01,
        "usage": {"input_tokens": 10, "cache_read_input_tokens": 5, "output_tokens": 3},
        "structured_output": {"message": message, "tool_calls": list(tool_calls)},
    }
    env.update(extra)
    return env


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    """A `claude` stand-in. Returns (path, queue(list of envelopes), calls() -> recorded calls)."""
    queue_file, log_file = tmp_path / "queue.json", tmp_path / "calls.jsonl"
    script = tmp_path / "claude"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        f"q = json.load(open({str(queue_file)!r}))\n"
        f"open({str(log_file)!r}, 'a').write(json.dumps({{'argv': sys.argv[1:], 'stdin': sys.stdin.read(),\n"
        "    'has_key': 'ANTHROPIC_API_KEY' in os.environ, 'cwd': os.getcwd()}) + '\\n')\n"
        "out = q.pop(0)\n"
        f"json.dump(q, open({str(queue_file)!r}, 'w'))\n"
        "print(json.dumps(out)); sys.exit(out.pop('_exit', 0) if isinstance(out, dict) else 0)\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    queue_file.write_text("[]")
    monkeypatch.setenv("SAFETYWEBBING_CLAUDE_BIN", str(script))

    def queue(*envs):
        queue_file.write_text(json.dumps(list(envs)))

    def calls():
        return [json.loads(line) for line in log_file.read_text().splitlines()] if log_file.exists() else []

    return queue, calls


# --- transcript -------------------------------------------------------------------


def test_render_transcript_handles_dicts_and_message_objects():
    tool_call = SimpleNamespace(id="call_1", function=SimpleNamespace(name="HTTPRequest", arguments='{"path": "/"}'))
    assistant = SimpleNamespace(role="assistant", content="probing", tool_calls=[tool_call])
    system, transcript = cb.render_transcript([
        {"role": "system", "content": "You are a pentester."},
        {"role": "user", "content": "Your limits are: 5 rounds"},
        assistant,
        {"role": "tool", "tool_call_id": "call_1", "content": "HTTP/1.1 200"},
    ])
    assert system == "You are a pentester."
    assert "[user]\nYour limits are: 5 rounds" in transcript
    assert 'called tool HTTPRequest (id call_1)] {"path": "/"}' in transcript
    assert "[tool result for call_1]\nHTTP/1.1 200" in transcript


def test_schema_restricts_tool_names():
    schema = cb.build_schema(["A", "B"])
    items = schema["properties"]["tool_calls"]["items"]["properties"]
    assert items["name"]["enum"] == ["A", "B"]
    assert schema["required"] == ["message", "tool_calls"]


# --- parsing ----------------------------------------------------------------------


def test_parse_valid_tool_call_with_usage_and_cost():
    env = envelope("go", [{"name": "HTTPRequest", "arguments": {"method": "GET", "path": "/"}}])
    result, problems = cb.parse_result(env, TOOLS)
    assert problems == []
    assert result.content == "go"
    assert [(c.name, c.arguments) for c in result.tool_calls] == [("HTTPRequest", {"method": "GET", "path": "/"})]
    assert result.tool_calls[0].id.startswith("call_")
    assert (result.prompt_tokens, result.completion_tokens) == (15, 3)  # cache reads count as prompt
    assert result.cost_usd == pytest.approx(0.01)


@pytest.mark.parametrize("bad, expect", [
    ({"name": "Nope", "arguments": {}}, "unknown tool"),
    ({"name": "HTTPRequest", "arguments": "x"}, "must be a JSON object"),
    ({"name": "HTTPRequest", "arguments": {"method": "GET"}}, "missing required"),
    ("not-an-object", "not an object"),
])
def test_bad_tool_calls_are_dropped_and_reported(bad, expect):
    result, problems = cb.parse_result(envelope("x", [bad]), TOOLS)
    assert result.tool_calls == []
    assert expect in problems[0]


def test_result_text_fallbacks():
    fenced = {"result": '```json\n{"message": "hi", "tool_calls": []}\n```'}
    assert cb.parse_result(fenced, TOOLS)[0].content == "hi"
    prose = {"result": "I cannot continue."}
    assert cb.parse_result(prose, TOOLS)[0].content == "I cannot continue."
    with pytest.raises(cb.ClaudeBridgeError):
        cb.parse_result({"result": ""}, TOOLS)


# --- running the CLI ----------------------------------------------------------------


def test_complete_calls_cli_with_safe_argv_and_prompt_on_stdin(fake_claude, monkeypatch):
    queue, calls = fake_claude
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-not-reach-claude")
    queue(envelope("go", [{"name": "EndRun", "arguments": {}}]))
    messages = [{"role": "system", "content": "SYS"}, {"role": "user", "content": "scan http://x <SECRET-BODY>"}]
    result = cb.complete(messages, TOOLS, None, model="claude-sonnet-5-5")
    assert [c.name for c in result.tool_calls] == ["EndRun"]
    (call,) = calls()
    argv = call["argv"]
    assert argv[argv.index("--tools") + 1] == ""  # CLI's own tools are off
    assert argv[argv.index("--model") + 1] == "claude-sonnet-5-5"
    assert "--no-session-persistence" in argv and "--json-schema" in argv
    assert "SECRET-BODY" not in " ".join(argv)  # untrusted/large content is on stdin only
    assert "SECRET-BODY" in call["stdin"] and "[available tools]" in call["stdin"]
    assert "SYS" in argv[argv.index("--system-prompt") + 1]
    assert call["has_key"] is False  # the OAuth session must not be overridden by a key
    assert call["cwd"] != os.getcwd()  # not run inside the work dir (no stray CLAUDE.md)


def test_malformed_call_is_retried_once_with_the_problem_stated(fake_claude):
    queue, calls = fake_claude
    queue(envelope("a", [{"name": "Nope", "arguments": {}}]),
          envelope("b", [{"name": "EndRun", "arguments": {}}], total_cost_usd=0.02))
    result = cb.complete([{"role": "user", "content": "go"}], TOOLS, None, model="m")
    assert [c.name for c in result.tool_calls] == ["EndRun"]
    assert len(calls()) == 2 and "unknown tool 'Nope'" in calls()[1]["stdin"]
    assert result.cost_usd == pytest.approx(0.03)  # both attempts are paid for


def test_persistent_garbage_degrades_to_plain_text(fake_claude):
    queue, calls = fake_claude
    queue(envelope("a", [{"name": "Nope", "arguments": {}}]), envelope("b", [{"name": "Nope", "arguments": {}}]))
    result = cb.complete([{"role": "user", "content": "go"}], TOOLS, None, model="m")
    assert result.tool_calls == [] and result.content == "b"
    assert len(calls()) == 2  # exactly one retry


def test_required_tool_choice_retries_when_no_tool_called(fake_claude):
    queue, calls = fake_claude
    queue(envelope("thinking", []), envelope("act", [{"name": "EndRun", "arguments": {}}]))
    result = cb.complete([{"role": "user", "content": "go"}], TOOLS, "required", model="m")
    assert [c.name for c in result.tool_calls] == ["EndRun"]
    assert "at least one tool" in calls()[1]["stdin"]


def test_cli_error_envelope_raises(fake_claude):
    queue, _ = fake_claude
    queue({"is_error": True, "result": "safeguards flagged this message", "_exit": 1})
    with pytest.raises(cb.ClaudeBridgeError, match="safeguards"):
        cb.complete([{"role": "user", "content": "go"}], TOOLS, None, model="m")


def test_missing_cli_raises_clear_error(monkeypatch):
    monkeypatch.setenv("SAFETYWEBBING_CLAUDE_BIN", "/nonexistent/claude")
    with pytest.raises(cb.ClaudeBridgeError, match="not found"):
        cb.complete([{"role": "user", "content": "go"}], TOOLS, None, model="m")
