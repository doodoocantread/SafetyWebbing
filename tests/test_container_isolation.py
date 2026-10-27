"""Container isolation (code-review finding #3) — everything checkable without Docker.

The scan container runs a FULL_ACCESS agent that reads untrusted web content, so it must
hold up against a prompt-injected agent. These tests pin the controls on the `docker run`
command, the policy inputs, and the entrypoint script. The behaviour of the firewall itself
is proven against a real container in test_isolation_docker.py (opt-in).
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from safetywebbing.config import (
    CLAUDE_OAUTH_HOSTS,
    EXTRA_EGRESS_ENV,
    InvalidEgressDomain,
    InvalidRunId,
    InvalidTargetPort,
    extra_egress_domains,
    target_port,
    validate_egress_domain,
)
from safetywebbing.engines.live import LiveAgentEngine

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = [REPO / "agent_image" / "sw-entrypoint.sh",
           REPO / "agent_image_hackingbuddy" / "sw-entrypoint.sh"]


def _cmd(tmp_path, **kw):
    eng = LiveAgentEngine(runs_root=tmp_path / "runs", claude_creds_dir=tmp_path / "nope", **kw)
    return eng, eng.build_command(target="http://127.0.0.1:3000", goal="g", run_id="r1", env={})


def _env_arg(cmd: list[str], name: str) -> str:
    vals = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e" and cmd[i + 1].startswith(name + "=")]
    assert len(vals) == 1, f"{name} passed {len(vals)} times"
    return vals[0].split("=", 1)[1]


# --- filesystem: only this run's folder is shared -----------------------------------

def test_only_this_runs_folder_is_mounted_not_the_whole_runs_tree(tmp_path):
    _, cmd = _cmd(tmp_path)
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    container_paths = [m.split(":")[1] for m in mounts]
    assert "/work/runs/r1" in container_paths
    # no mount may expose the runs/ root (audit.log, triage.json, other runs)
    assert "/work/runs" not in container_paths
    run_mount = next(m for m in mounts if m.endswith(":/work/runs/r1"))
    assert run_mount.split(":")[0] == str((tmp_path / "runs" / "r1").resolve())


@pytest.mark.parametrize("bad", ["../x", "a/b", "..", "r1\n", "", "-rf"])
def test_run_id_is_validated_before_it_reaches_a_mount_path(tmp_path, bad):
    eng = LiveAgentEngine(runs_root=tmp_path / "runs")
    with pytest.raises(InvalidRunId):
        eng.build_command(target="http://localhost:3000", goal="g", run_id=bad, env={})


def test_prepare_run_dir_creates_the_shared_folder_writable_for_the_agent(tmp_path):
    eng = LiveAgentEngine(runs_root=tmp_path / "runs")
    d = eng._prepare_run_dir("live-abc")
    assert d == (tmp_path / "runs" / "live-abc").resolve() and d.is_dir()
    assert stat.S_IMODE(d.stat().st_mode) == 0o777  # uid 1000 in the container must write
    with pytest.raises(InvalidRunId):
        eng._prepare_run_dir("../escape")
    assert not (tmp_path / "escape").exists()


# --- privileges and resources ---------------------------------------------------------

def test_capabilities_dropped_with_only_the_entrypoints_needs_added_back(tmp_path):
    _, cmd = _cmd(tmp_path)
    assert cmd[cmd.index("--cap-drop") + 1] == "ALL"
    added = {cmd[i + 1] for i, a in enumerate(cmd) if a == "--cap-add"}
    assert added == {"NET_ADMIN", "SETUID", "SETGID", "SETPCAP"}
    assert cmd[cmd.index("--security-opt") + 1] == "no-new-privileges"


def test_no_privileged_host_network_or_docker_socket(tmp_path):
    _, cmd = _cmd(tmp_path)
    for flag in ("--privileged", "--network", "--net", "--pid", "--ipc", "--uts", "--userns",
                 "--device"):
        assert flag not in cmd
    assert "docker.sock" not in " ".join(cmd)


def test_resource_limits_are_set_and_swap_is_disabled(tmp_path):
    eng, cmd = _cmd(tmp_path)
    assert cmd[cmd.index("--memory") + 1] == eng.memory == cmd[cmd.index("--memory-swap") + 1]
    assert float(cmd[cmd.index("--cpus") + 1]) == eng.cpus > 0
    assert int(cmd[cmd.index("--pids-limit") + 1]) == eng.pids_limit > 0


def test_flags_come_before_the_image_so_the_agent_cannot_inject_any(tmp_path):
    _, cmd = _cmd(tmp_path)
    image = cmd.index("safetywebbing-agent")
    for flag in ("--cap-drop", "--security-opt", "--memory", "--pids-limit", "-v", "-e"):
        assert cmd.index(flag) < image


# --- egress policy inputs ---------------------------------------------------------------

def test_firewall_is_switched_on_with_the_target_port(tmp_path):
    eng = LiveAgentEngine(runs_root=tmp_path / "runs")
    cmd = eng.build_command(target="http://localhost:4567/x", goal="g", run_id="r1", env={})
    assert _env_arg(cmd, "SAFETYWEBBING_FIREWALL") == "1"
    assert _env_arg(cmd, "SAFETYWEBBING_TARGET_PORT") == "4567"


@pytest.mark.parametrize("url,port", [
    ("http://127.0.0.1:3000", 3000), ("http://localhost", 80),
    ("https://localhost", 443), ("http://[::1]:8080/a?b=c", 8080),
])
def test_target_port(url, port):
    assert target_port(url) == port


@pytest.mark.parametrize("url", ["http://localhost:99999", "http://localhost:0", "http://localhost:x"])
def test_unusable_target_port_is_rejected_not_passed_to_the_firewall(url):
    with pytest.raises(InvalidTargetPort):
        target_port(url)


def test_oauth_agent_may_reach_only_the_claude_hosts(tmp_path):
    eng = LiveAgentEngine(runs_root=tmp_path / "runs", auth="claude_oauth")
    assert eng.egress_domains(env={}) == CLAUDE_OAUTH_HOSTS
    cmd = eng.build_command(target="http://localhost:3000", goal="g", run_id="r1", env={})
    assert _env_arg(cmd, "SAFETYWEBBING_ALLOW_DOMAINS").split(",") == list(CLAUDE_OAUTH_HOSTS)


def test_api_key_agent_may_reach_only_the_provider_it_uses(tmp_path):
    eng = LiveAgentEngine(runs_root=tmp_path / "runs", auth="llm_api_key")
    assert eng.egress_domains(env={"OPENAI_API_KEY": "x"}) == ("api.openai.com",)
    assert eng.egress_domains(env={}) == ()  # no key, no provider, no hosts
    # a per-scan key (not in the server env) still opens exactly its provider
    scan = LiveAgentEngine(auth="llm_api_key", llm_api_key="k", llm_env_name="GEMINI_API_KEY")
    assert scan.egress_domains(env={"OPENAI_API_KEY": "x"}) == (
        "generativelanguage.googleapis.com",
    )


def test_operator_can_extend_the_allowlist_from_the_server_env(tmp_path):
    eng = LiveAgentEngine(runs_root=tmp_path / "runs", auth="claude_oauth")
    env = {EXTRA_EGRESS_ENV: "Proxy.Example.com, api.anthropic.com ,"}
    got = eng.egress_domains(env=env)
    assert got[-1] == "proxy.example.com"
    assert got.count("api.anthropic.com") == 1  # de-duplicated


def test_a_bad_extra_domain_fails_loudly_instead_of_widening_the_policy():
    with pytest.raises(InvalidEgressDomain):
        extra_egress_domains({EXTRA_EGRESS_ENV: "ok.example.com,evil.com;rm -rf /"})


@pytest.mark.parametrize("bad", [
    "1.2.3.4", "169.254.169.254", "localhost", "*.example.com", "a..b.com", ".example.com",
    "example.com.", "-x.example.com", "evil.com;x", "a b.com", "ex\nample.com", "x.com:443",
    "http://x.com", "", " ", "a" * 64 + ".com", ("a" * 60 + ".") * 5 + "com",
])
def test_egress_domain_must_be_a_plain_dns_name(bad):
    with pytest.raises(InvalidEgressDomain):
        validate_egress_domain(bad)


def test_egress_domain_is_normalised():
    assert validate_egress_domain(" API.Anthropic.COM ") == "api.anthropic.com"


# --- the entrypoint script ------------------------------------------------------------------

def test_both_images_ship_an_identical_executable_entrypoint():
    assert SCRIPTS[0].read_text() == SCRIPTS[1].read_text()
    for s in SCRIPTS:
        assert s.stat().st_mode & stat.S_IXUSR, f"{s} is not executable"


def test_entrypoint_is_valid_shell():
    for s in SCRIPTS:
        subprocess.run(["sh", "-n", str(s)], check=True)


def test_entrypoint_drops_every_capability_before_the_agent_runs():
    text = SCRIPTS[0].read_text()
    for needle in ("--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                   "--no-new-privs", '--reuid="$AGENT_USER"'):
        assert needle in text
    # the agent is only ever started through drop_and_exec
    assert text.count('"$AGENT_BIN"') == 1


@pytest.mark.parametrize("image,agent_bin", [
    ("agent_image", "pentestgpt-agent"),
    ("agent_image_hackingbuddy", "safetywebbing-hackingbuddy-agent"),
])
def test_dockerfiles_install_the_firewall_and_use_the_entrypoint(image, agent_bin):
    text = (REPO / image / "Dockerfile").read_text()
    assert "iptables" in text
    assert "COPY sw-entrypoint.sh /usr/local/bin/sw-entrypoint" in text
    assert 'ENTRYPOINT ["/usr/local/bin/sw-entrypoint"]' in text
    assert f"SAFETYWEBBING_AGENT_BIN={agent_bin}" in text


def _run_entrypoint(**env):
    base = {"PATH": os.environ["PATH"], "SAFETYWEBBING_AGENT_BIN": "/bin/true",
            "SAFETYWEBBING_FIREWALL": "1"}
    return subprocess.run(["sh", str(SCRIPTS[0])], env={**base, **env},
                          capture_output=True, text=True, timeout=20, check=False)


@pytest.mark.parametrize("env", [
    {"SAFETYWEBBING_TARGET_PORT": ""},
    {"SAFETYWEBBING_TARGET_PORT": "abc"},
    {"SAFETYWEBBING_TARGET_PORT": "3000 -j ACCEPT"},
    {"SAFETYWEBBING_TARGET_PORT": "0"},
    {"SAFETYWEBBING_TARGET_PORT": "70000"},
    {"SAFETYWEBBING_TARGET_PORT": "3000", "SAFETYWEBBING_ALLOW_DOMAINS": "evil.com;touch /x"},
    {"SAFETYWEBBING_TARGET_PORT": "3000", "SAFETYWEBBING_ALLOW_DOMAINS": "$(id).example.com"},
    {"SAFETYWEBBING_TARGET_PORT": "3000", "SAFETYWEBBING_ALLOW_DOMAINS": "localhost"},
    {"SAFETYWEBBING_TARGET_PORT": "3000", "SAFETYWEBBING_ALLOW_DOMAINS": "a..example.com"},
])
def test_entrypoint_refuses_bad_policy_input_and_never_starts_the_agent(env):
    r = _run_entrypoint(**env)
    assert r.returncode == 97, r.stderr
    assert "FATAL" in r.stderr


def test_entrypoint_requires_to_know_which_agent_to_start():
    r = subprocess.run(["sh", str(SCRIPTS[0])], env={"PATH": os.environ["PATH"]},
                       capture_output=True, text=True, timeout=20, check=False)
    assert r.returncode != 0


# --- API: bad policy inputs are refused up front -----------------------------------------------

async def test_api_rejects_an_unusable_target_port_before_anything_is_recorded(
    tmp_path, monkeypatch
):
    from fastapi import HTTPException

    from safetywebbing import api

    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path / "runs")
    with pytest.raises(HTTPException) as exc:
        await api.start_scan(api.ScanRequest(target="http://localhost:99999", scan_type="sqli"))
    assert exc.value.status_code == 400
    assert not (tmp_path / "runs" / "audit.log").exists()  # nothing was authorised or spawned
    assert not api._jobs


async def test_api_refuses_to_scan_with_a_malformed_operator_allowlist(tmp_path, monkeypatch):
    from fastapi import HTTPException

    from safetywebbing import api

    monkeypatch.setattr(api, "_LIVE_RUNS", tmp_path / "runs")
    monkeypatch.setenv(EXTRA_EGRESS_ENV, "good.example.com,evil.com;rm -rf /")
    with pytest.raises(HTTPException) as exc:
        await api.start_scan(api.ScanRequest(target="http://localhost:3000", scan_type="sqli"))
    assert exc.value.status_code == 500
    assert "allowlist" in exc.value.detail
    assert not (tmp_path / "runs" / "audit.log").exists()
    assert not api._jobs
