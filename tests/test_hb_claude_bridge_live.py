"""Integration tests for claude_bridge.install() against the REAL hackingBuddyGPT/litellm
classes (agent_image_hackingbuddy/.../claude_bridge.py).

hackingBuddyGPT (and the litellm it pulls in) is NOT a dependency of the host app or its
test suite (see conftest.py) — it only exists inside the Docker image. This file is kept
SEPARATE from test_hb_claude_bridge.py (which is pure and always runs) for exactly that
reason: a module-level ``importorskip`` skips the whole module at collection time, and that
must never take the pure tests down with it. Run these in a venv built from
agent_image_hackingbuddy/pyproject.toml (`uv pip install -e ./agent_image_hackingbuddy`);
elsewhere they are skipped, not failed.
"""

import json
import stat
import sys

import pytest

litellm = pytest.importorskip("litellm")
hackingbuddy_llm = pytest.importorskip("hackingBuddyGPT.utils.llm")
http_request = pytest.importorskip("hackingBuddyGPT.capabilities.http_request")

from safetywebbing_hb_agent import claude_bridge as cb


def envelope(message="ok", tool_calls=(), **extra):
    env = {
        "type": "result", "is_error": False, "total_cost_usd": 0.01,
        "usage": {"input_tokens": 10, "output_tokens": 3},
        "structured_output": {"message": message, "tool_calls": list(tool_calls)},
    }
    env.update(extra)
    return env


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    """A `claude` stand-in that always replays the one queued envelope (see test_hb_claude_bridge.py
    for the fuller multi-call version; these tests only ever need a single reply)."""
    script = tmp_path / "claude"
    reply_file = tmp_path / "reply.json"
    script.write_text(f"#!{sys.executable}\nimport sys\nsys.stdout.write(open({str(reply_file)!r}).read())\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("SAFETYWEBBING_CLAUDE_BIN", str(script))

    def queue(env):
        reply_file.write_text(json.dumps(env))

    return queue


def _make_llm(model="claude-code/claude-sonnet-5-5"):
    llm = hackingbuddy_llm.LiteLLM(api_key="unused", model=model, context_size=30000)
    llm.init()
    return llm


def test_get_response_round_trips_text_tool_call_tokens_and_cost(fake_claude):
    """install() makes a real LiteLLM.get_response() call return the CLI's text, tool call
    and dollar cost — the exact numbers a hand-run smoke test would also see."""
    fake_claude(envelope("probing", [{"name": "HTTPRequest", "arguments": {"method": "GET", "path": "/"}}],
                         total_cost_usd=0.015, usage={"input_tokens": 20, "output_tokens": 5}))
    cb.install()
    llm = _make_llm()
    caps = {"HTTPRequest": http_request.HTTPRequest("http://example.invalid")}
    result = llm.get_response([{"role": "system", "content": "sys"}, {"role": "user", "content": "go"}],
                               capabilities=caps)
    assert result.result.content == "probing"
    (tool_call,) = result.result.tool_calls
    assert tool_call.function.name == "HTTPRequest"
    assert json.loads(tool_call.function.arguments) == {"method": "GET", "path": "/"}
    assert (result.tokens_query, result.tokens_response) == (20, 5)
    # The regression this guards: litellm.completion_cost() doesn't know this model and
    # silently returns 0 for it rather than raising, so get_response()'s fallback to
    # usage.cost never fires unless install() also patches completion_cost itself.
    assert result.cost == pytest.approx(0.015)


def test_non_bridge_model_falls_through_to_real_litellm(monkeypatch, fake_claude):
    """A model that isn't ours must reach litellm.completion untouched — proven offline by
    swapping that one call for a sentinel, instead of a real (network-dependent) failure."""
    sentinel = RuntimeError("real litellm.completion was reached")

    def fake_completion(*a, **kw):
        raise sentinel

    monkeypatch.setattr(litellm, "completion", fake_completion)
    cb.install()

    with pytest.raises(RuntimeError, match="real litellm.completion was reached"):
        _make_llm(model="definitely-not-a-claude-code-model").raw_completion(
            [{"role": "user", "content": "go"}]
        )

    # The bridge path, in contrast, never touches litellm.completion at all.
    fake_claude(envelope("ok", []))
    _make_llm().raw_completion([{"role": "user", "content": "go"}])
