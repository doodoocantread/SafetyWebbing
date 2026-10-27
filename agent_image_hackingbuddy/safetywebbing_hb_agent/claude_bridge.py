"""Run hackingBuddyGPT on the host's Claude Code session instead of an API key.

hackingBuddy reaches its LLM through ONE method, ``LiteLLM.raw_completion(messages,
tools, tool_choice)``, which returns a litellm ``ModelResponse``. This module replaces
that method (see :func:`install`) with a call to the Claude Code CLI (``claude -p``),
authenticated by the Claude Code credentials the engine mounts into the container —
the same auth path the PentestGPT agent uses. Everything else in hackingBuddy (the
agent loop, prompts, capabilities, JSONL span log) is untouched, so
:mod:`safetywebbing_hb_agent.translate` keeps working unchanged.

The Claude CLI has no OpenAI-style function calling, so tool use is emulated with
structured output: each turn we send the transcript plus the tool definitions and ask
for ``{"message": str, "tool_calls": [{"name": str, "arguments": object}]}``
(``--json-schema``). The CLI's own tools are switched off (``--tools ""``): hackingBuddy
executes the capabilities, Claude only decides which to call.

Everything above :func:`install` is pure (no hackingBuddy / litellm import) so it is
unit-testable with a fake ``claude`` executable; ``install`` imports them lazily.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from typing import Any

# litellm model prefix that selects this bridge (``--llm.model=claude-code/<claude id>``).
MODEL_PREFIX = "claude-code/"
DEFAULT_MODEL = "claude-sonnet-5-5"

# Credentials the CLI would prefer over the mounted OAuth session. This path is the
# session path, so never let a stray key in the environment change who is billed.
_STRIP_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")

_PROTOCOL = (
    "You are the reasoning engine of an autonomous tool-using agent. You have no tools of "
    "your own: the agent runtime executes the tools listed in the user message and feeds "
    "the results back as tool messages in the next turn.\n"
    "Reply ONLY with the JSON object requested by the schema. Put your reasoning and "
    "commentary in `message`. To act, add entries to `tool_calls` (several independent "
    "calls per turn are fine); `name` must be one of the listed tools and `arguments` "
    "must match that tool's parameters exactly. Leave `tool_calls` empty only when you "
    "have nothing left to do."
)


class ClaudeBridgeError(RuntimeError):
    """The Claude CLI could not produce a usable answer (missing, refused, timed out…)."""


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]
    id: str = field(default_factory=lambda: f"call_{uuid.uuid4().hex[:24]}")


@dataclass
class BridgeResult:
    content: str
    tool_calls: list[ToolCall]
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0


# --- messages -> prompt ---------------------------------------------------------


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` from a dict message or a litellm Message object alike."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _content_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # OpenAI-style content parts
        return "\n".join(
            str(p.get("text", "")) if isinstance(p, dict) else str(p) for p in content
        )
    return str(content)


def _call_parts(tool_call: Any) -> tuple[str, str, str]:
    fn = _get(tool_call, "function")
    return (
        str(_get(tool_call, "id", "")),
        str(_get(fn, "name", "")),
        _content_text(_get(fn, "arguments", "")),
    )


def render_transcript(messages: list[Any]) -> tuple[str, str]:
    """Split a chat history into ``(system_text, transcript_text)``.

    Assistant tool calls and tool results are written out with their call ids so Claude
    can pair a result with the call that produced it.
    """
    system: list[str] = []
    lines: list[str] = []
    for m in messages:
        role = _get(m, "role", "user")
        text = _content_text(_get(m, "content"))
        if role == "system":
            system.append(text)
        elif role == "tool":
            lines.append(f"[tool result for {_get(m, 'tool_call_id', '?')}]\n{text}")
        elif role == "assistant":
            parts = [f"[assistant]\n{text}" if text else "[assistant]"]
            for tc in _get(m, "tool_calls") or []:
                call_id, name, args = _call_parts(tc)
                parts.append(f"[assistant called tool {name} (id {call_id})] {args}")
            lines.append("\n".join(parts))
        else:
            lines.append(f"[{role}]\n{text}")
    return "\n\n".join(system), "\n\n".join(lines)


def tools_prompt(tools: list[dict[str, Any]]) -> str:
    out = []
    for t in tools:
        fn = t.get("function", {})
        out.append(
            f"- {fn.get('name')}: {fn.get('description', '').strip()}\n"
            f"  parameters (JSON schema): {json.dumps(fn.get('parameters', {}), sort_keys=True)}"
        )
    return "\n".join(out)


def build_schema(tool_names: list[str]) -> dict[str, Any]:
    name_schema: dict[str, Any] = {"type": "string"}
    if tool_names:
        name_schema["enum"] = list(tool_names)
    return {
        "type": "object",
        "properties": {
            "message": {"type": "string"},
            "tool_calls": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"name": name_schema, "arguments": {"type": "object"}},
                    "required": ["name", "arguments"],
                },
            },
        },
        "required": ["message", "tool_calls"],
    }


# --- CLI output -> result ---------------------------------------------------------

_FENCE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL)


def _payload(cli: dict[str, Any]) -> dict[str, Any]:
    """The model's JSON answer from the CLI envelope (structured_output, else result text)."""
    structured = cli.get("structured_output")
    if isinstance(structured, dict):
        return structured
    raw = cli.get("result")
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        raise ClaudeBridgeError("claude returned no answer")
    text = raw.strip()
    m = _FENCE.match(text)
    if m:
        text = m.group(1)
    try:
        data = json.loads(text)
    except ValueError:
        # Not JSON: treat the prose as a message with no tool calls rather than failing.
        return {"message": raw, "tool_calls": []}
    if not isinstance(data, dict):
        raise ClaudeBridgeError("claude answer was not a JSON object")
    return data


def _usage(cli: dict[str, Any]) -> tuple[int, int]:
    u = cli.get("usage") or {}
    prompt = sum(
        int(u.get(k) or 0)
        for k in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
    )
    return prompt, int(u.get("output_tokens") or 0)


def validate_tool_call(tools: list[dict[str, Any]], call: Any) -> str | None:
    """Return a problem description, or None when ``call`` is a well-formed call to a known tool.

    Deliberately shallow (known tool, object arguments, required keys present): the
    capability itself re-validates its arguments when it runs.
    """
    if not isinstance(call, dict):
        return "tool call is not an object"
    name = call.get("name")
    spec = next((t.get("function", {}) for t in tools if t.get("function", {}).get("name") == name), None)
    if spec is None:
        return f"unknown tool {name!r}"
    args = call.get("arguments")
    if not isinstance(args, dict):
        return f"arguments of {name} must be a JSON object"
    missing = [k for k in (spec.get("parameters", {}).get("required") or []) if k not in args]
    if missing:
        return f"{name} is missing required argument(s): {', '.join(missing)}"
    return None


def parse_result(cli: dict[str, Any], tools: list[dict[str, Any]]) -> tuple[BridgeResult, list[str]]:
    """Build a BridgeResult from the CLI envelope. Second value: problems found in tool calls
    (those calls are dropped from the result)."""
    data = _payload(cli)
    problems: list[str] = []
    calls: list[ToolCall] = []
    for raw in data.get("tool_calls") or []:
        problem = validate_tool_call(tools, raw)
        if problem:
            problems.append(problem)
            continue
        calls.append(ToolCall(name=raw["name"], arguments=raw["arguments"]))
    prompt_tokens, completion_tokens = _usage(cli)
    result = BridgeResult(
        content=str(data.get("message") or ""),
        tool_calls=calls,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        cost_usd=float(cli.get("total_cost_usd") or 0.0),
    )
    return result, problems


# --- running the CLI --------------------------------------------------------------


def run_claude(
    prompt: str,
    *,
    system: str,
    schema: dict[str, Any],
    model: str,
    timeout: float = 300.0,
    claude_bin: str | None = None,
    cwd: str | None = None,
) -> dict[str, Any]:
    """One non-interactive ``claude -p`` call; returns the parsed ``--output-format json`` envelope.

    The prompt goes over stdin (it can be large and contains untrusted web content); only
    the short, fixed-shape system prompt and schema are on the argv.
    """
    binary = claude_bin or os.environ.get("SAFETYWEBBING_CLAUDE_BIN", "claude")
    cmd = [
        binary, "-p",
        "--output-format", "json",
        "--tools", "",
        "--no-session-persistence",
        "--setting-sources", "",
        "--model", model,
        "--system-prompt", system,
        "--json-schema", json.dumps(schema),
    ]
    env = {k: v for k, v in os.environ.items() if k not in _STRIP_ENV}
    try:
        proc = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True, timeout=timeout,
            env=env, cwd=cwd or tempfile.gettempdir(), check=False,
        )
    except FileNotFoundError:
        raise ClaudeBridgeError(f"Claude Code CLI not found ({binary!r})") from None
    except subprocess.TimeoutExpired:
        raise ClaudeBridgeError(f"claude timed out after {timeout:.0f}s") from None
    try:
        cli = json.loads(proc.stdout)
    except ValueError:
        tail = (proc.stderr or proc.stdout or "").strip()[-500:]
        raise ClaudeBridgeError(f"claude exited {proc.returncode} without JSON output: {tail}") from None
    if not isinstance(cli, dict):
        raise ClaudeBridgeError("unexpected claude output")
    if cli.get("is_error") or proc.returncode != 0:
        detail = cli.get("result") if isinstance(cli.get("result"), str) else cli.get("subtype")
        raise ClaudeBridgeError(f"claude failed (exit {proc.returncode}): {detail}")
    return cli


def complete(
    messages: list[Any],
    tools: list[dict[str, Any]] | None,
    tool_choice: Any,
    *,
    model: str,
    timeout: float = 300.0,
    claude_bin: str | None = None,
    max_attempts: int = 2,
) -> BridgeResult:
    """One LLM turn: transcript + tools in, text + validated tool calls out.

    A malformed tool call (unknown tool, bad arguments) — or no call at all when
    ``tool_choice`` requires one — gets ONE retry with the problem spelled out; after that
    the turn is returned as-is (plain text, no tool calls) and the agent carries on.
    """
    tools = list(tools or [])
    system_text, transcript = render_transcript(messages)
    system = _PROTOCOL + ("\n\n" + system_text if system_text else "")
    schema = build_schema([t["function"]["name"] for t in tools])
    prompt = transcript
    if tools:
        prompt += "\n\n[available tools]\n" + tools_prompt(tools)
    # "required" or a forced {"type": "function", ...} choice: a reply without a tool call is invalid.
    required = bool(tools) and (tool_choice == "required" or isinstance(tool_choice, dict))
    prompt += "\n\n[your turn] Reply with the JSON object now."

    best: BridgeResult | None = None
    total_cost = 0.0
    p_tokens = c_tokens = 0
    for attempt in range(max_attempts):
        cli = run_claude(
            prompt, system=system, schema=schema, model=model, timeout=timeout, claude_bin=claude_bin,
        )
        result, problems = parse_result(cli, tools)
        total_cost += result.cost_usd
        p_tokens += result.prompt_tokens
        c_tokens += result.completion_tokens
        best = result
        if not problems and not (required and not result.tool_calls):
            break
        if attempt + 1 < max_attempts:
            issue = "; ".join(problems) if problems else "you must call at least one tool"
            prompt += (
                f"\n\n[runtime] Your previous reply was rejected: {issue}. "
                "Reply again with a corrected JSON object."
            )
    assert best is not None
    best.cost_usd, best.prompt_tokens, best.completion_tokens = total_cost, p_tokens, c_tokens
    return best


# --- hooking into hackingBuddy ------------------------------------------------------


def to_model_response(result: BridgeResult, model: str) -> Any:
    """A real litellm ModelResponse, so hackingBuddy's downstream code cannot tell the difference."""
    from litellm.types.utils import (
        ChatCompletionMessageToolCall,
        Choices,
        Function,
        Message,
        ModelResponse,
        Usage,
    )

    tool_calls = [
        ChatCompletionMessageToolCall(
            id=tc.id, type="function",
            function=Function(name=tc.name, arguments=json.dumps(tc.arguments)),
        )
        for tc in result.tool_calls
    ] or None
    message = Message(content=result.content, role="assistant", tool_calls=tool_calls)
    usage = Usage(
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        total_tokens=result.prompt_tokens + result.completion_tokens,
    )
    response = ModelResponse(
        model=model,
        choices=[Choices(index=0, message=message, finish_reason="tool_calls" if tool_calls else "stop")],
        usage=usage,
    )
    # get_response() prices a turn by calling litellm.completion_cost(response) first and,
    # only if THAT raises, falling back to response.usage.cost. completion_cost does not
    # raise for an unrecognized model like ours — it quietly returns 0 — so the fallback
    # never fires; install() patches completion_cost itself (keyed off this same
    # _hidden_params entry) to make the CLI's own dollar figure win instead.
    response._hidden_params["response_cost"] = result.cost_usd
    return response


def install() -> None:
    """Route ``LiteLLM.raw_completion`` through the Claude CLI for models named ``claude-code/<id>``."""
    import litellm
    from hackingBuddyGPT.utils.llm import LiteLLM

    original_raw_completion = LiteLLM.raw_completion
    original_completion_cost = litellm.completion_cost

    def raw_completion(self, messages, *, tools=None, tool_choice=None):
        if not str(self.model).startswith(MODEL_PREFIX):
            return original_raw_completion(self, messages, tools=tools, tool_choice=tool_choice)
        claude_model = str(self.model)[len(MODEL_PREFIX):] or DEFAULT_MODEL
        result = complete(
            messages, list(tools) if tools else None, tool_choice,
            model=claude_model, timeout=float(self.api_timeout),
        )
        return to_model_response(result, str(self.model))

    def completion_cost(*args, completion_response=None, **kwargs):
        if completion_response is not None and str(getattr(completion_response, "model", "")).startswith(
            MODEL_PREFIX
        ):
            hidden = getattr(completion_response, "_hidden_params", None) or {}
            if "response_cost" in hidden:
                return hidden["response_cost"]
        return original_completion_cost(*args, completion_response=completion_response, **kwargs)

    LiteLLM.raw_completion = raw_completion
    litellm.completion_cost = completion_cost
