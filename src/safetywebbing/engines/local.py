"""LocalAgentEngine — run an agent CLI directly on the host.

This is the "direct" mode: the same agent CLI the Docker image runs, started as a
plain subprocess against the original loopback target. There is NO container, so the
agent shares the user's machine, files and network (ARCHITECTURE.md §2.3 is
deliberately not met). It is for fast local iteration on a trusted dev box;
config.validate_mode gates it behind a server-side opt-in.

Two agents can run this way, selected by the engine's `exe`/`venv_dir`/`extra_env`:
  - `pentestgpt` (default): the vendored PentestGPT agent (`pentestgpt-agent`,
    `.agent-venv`). It has a FULL_ACCESS shell, so this path carries the real risk the
    container exists to contain.
  - `hackingbuddy_claude`: hackingBuddyGPT's web use-case wrapper
    (`safetywebbing-hackingbuddy-agent`, `.hb-venv`) with `SAFETYWEBBING_LLM_AUTH=
    claude_oauth`. That use-case only exposes HTTP capabilities to the model (no shell),
    so it is narrower than the PentestGPT path, but it still runs uncontained.

Like LiveAgentEngine it never imports the agent — the agent lives in its own
environment (a separate venv) and the only contract is summary.json + traces/ on disk.

Differences from the Docker engine, all consequences of having no container:
  - Target is used as-is (no host.docker.internal rewrite): loopback is the host.
  - Auth is the host's own, already logged-in Claude Code — nothing to copy.
  - A timeout must kill the whole process tree (claude, node, curl…), not just the
    launcher, otherwise the agent keeps running after we report failure.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import signal
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .base import RunResult, ScanFailed, load_run_result

AGENT_CMD_ENV = "SAFETYWEBBING_AGENT_CMD"
_AGENT_EXE = "pentestgpt-agent"
_AGENT_VENV = ".agent-venv"

# Mirrors the ENV block of agent_image/Dockerfile.
_AGENT_ENV_DEFAULTS = {
    "PYTHONUNBUFFERED": "1",
    "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_AUTOUPDATER": "1",
}
# The host app may hold this for the LLM labeler. The Docker agent never sees it, so
# the direct agent must not either: it reads untrusted web content (prompt injection).
_SCRUBBED_ENV = ("ANTHROPIC_API_KEY",)


def resolve_agent_command(
    search_dirs: tuple[Path, ...] = (),
    env: Mapping[str, str] | None = None,
    *,
    exe: str = _AGENT_EXE,
    venv_dir: str = _AGENT_VENV,
    cmd_env: str = AGENT_CMD_ENV,
) -> list[str] | None:
    """Find the argv prefix that launches the agent CLI, or None.

    Order: $<cmd_env> (may be several words, e.g. `uv run --project agent_image
    pentestgpt-agent`) → a dedicated `<venv_dir>` in `search_dirs` → `<exe>` on PATH.
    Defaults resolve the PentestGPT agent; the hackingbuddy_claude engine passes its own
    `exe`/`venv_dir`/`cmd_env`.
    """
    env = os.environ if env is None else env
    explicit = (env.get(cmd_env) or "").strip()
    if explicit:
        posix = os.name != "nt"
        return [t.strip('"') for t in shlex.split(explicit, posix=posix)]
    bin_dir, exe_name = ("Scripts", f"{exe}.exe") if os.name == "nt" else ("bin", exe)
    for base in search_dirs:
        candidate = base / venv_dir / bin_dir / exe_name
        if candidate.is_file():
            return [str(candidate)]
    found = shutil.which(exe)
    return [found] if found else None


def agent_env(
    base: Mapping[str, str] | None = None, extra: Mapping[str, str] | None = None
) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    for key in _SCRUBBED_ENV:
        env.pop(key, None)
    env.update(_AGENT_ENV_DEFAULTS)
    if extra:
        env.update(extra)  # e.g. SAFETYWEBBING_LLM_AUTH for the hackingbuddy_claude wrapper
    return env


async def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    """Terminate `proc` and everything it spawned."""
    if proc.returncode is not None:
        return
    if sys.platform == "win32":
        killer = await asyncio.create_subprocess_exec(
            "taskkill", "/PID", str(proc.pid), "/T", "/F",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        await killer.wait()
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)  # started with start_new_session=True
        except ProcessLookupError:
            pass
    try:
        proc.kill()  # no-op if the tree kill already got it
    except ProcessLookupError:
        pass
    await proc.wait()


@dataclass
class LocalAgentEngine:
    """Runs one scan per call. Inputs are already validated by config.py."""

    name: str = "direct"
    runs_root: Path = Path("runs")
    # Extra places to look for `.agent-venv` (the repo root, normally).
    search_dirs: tuple[Path, ...] = ()
    agent_cmd: list[str] | None = None  # explicit override; skips discovery
    backend: str = "claude"
    model: str | None = None
    max_decisions: int = 20
    timeout_s: float = 600.0
    # Start the agent in a fresh, empty temp directory instead of the repo root. By default
    # the agent's cwd is the repo, so a model that wanders reads src/ (README: a Sonnet run
    # did exactly that) — and during a benchmark that includes the answer key in benchmark/.
    # This removes the accident, NOT the capability: direct mode has no isolation, so the
    # agent can still `cd` anywhere. The benchmark's integrity check looks for that in the
    # trace. Needs an agent command made of ABSOLUTE paths (the `.agent-venv` lookup is).
    empty_cwd: bool = False
    # Which agent CLI this engine launches (see the module docstring). Defaults to the
    # PentestGPT agent; the hackingbuddy_claude engine overrides exe/venv_dir/cmd_env and
    # sets extra_env={"SAFETYWEBBING_LLM_AUTH": "claude_oauth"} to pick its LLM path.
    exe: str = _AGENT_EXE
    venv_dir: str = _AGENT_VENV
    cmd_env: str = AGENT_CMD_ENV
    extra_env: Mapping[str, str] = field(default_factory=dict)

    def command(self) -> list[str] | None:
        return self.agent_cmd or resolve_agent_command(
            self.search_dirs, exe=self.exe, venv_dir=self.venv_dir, cmd_env=self.cmd_env
        )

    @property
    def workspace_root(self) -> Path:
        # Next to runs/, not inside it, so it never shows up as a scan result.
        return self.runs_root.resolve().parent / "agent-workspaces"

    def build_command(self, *, target: str, goal: str, run_id: str) -> list[str]:
        """The exact argv. Pure given a resolvable agent command — unit-testable."""
        prefix = self.command()
        if not prefix:
            raise ScanFailed(
                f"agent CLI {self.exe!r} not found. Install it into {self.venv_dir} "
                f"(see README) or set {self.cmd_env}."
            )
        cmd = [
            *prefix,
            "--goal", goal,
            "--target", target,  # loopback is the host here: no rewrite
            "--backend", self.backend,
            "--run-id", run_id,
            "--runs-root", str(self.runs_root.resolve()),
            "--workspace-root", str(self.workspace_root),
            "--max-decisions", str(self.max_decisions),
        ]
        if self.model:
            cmd += ["--model", self.model]
        return cmd

    async def run(self, *, target: str, goal: str, run_id: str) -> RunResult:
        cmd = self.build_command(target=target, goal=goal, run_id=run_id)
        self.runs_root.mkdir(parents=True, exist_ok=True)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        scratch = (
            tempfile.TemporaryDirectory(prefix="sw-agent-cwd-", ignore_cleanup_errors=True)
            if self.empty_cwd
            else None
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=agent_env(extra=self.extra_env),
                cwd=scratch.name if scratch else str(self.workspace_root.parent),
                start_new_session=(sys.platform != "win32"),  # own process group for killpg
            )
            try:
                raw, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout_s)
            except TimeoutError:
                await _kill_tree(proc)
                raise ScanFailed(f"scan {run_id} timed out after {self.timeout_s}s") from None
            except asyncio.CancelledError:
                await _kill_tree(proc)
                raise
        finally:
            if scratch:
                scratch.cleanup()  # after the process (tree) is dead, so Windows holds no handle
        return load_run_result(
            self.runs_root, run_id, engine=self.name,
            stdout=raw.decode("utf-8", errors="replace"), returncode=proc.returncode,
        )
