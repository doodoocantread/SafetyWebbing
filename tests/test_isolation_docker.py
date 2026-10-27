"""End-to-end proof of container isolation against a REAL container (finding #3).

Opt-in: it needs a running Docker daemon and an already-built scan image, so it is skipped
unless SAFETYWEBBING_ISOLATION_IMAGE names that image:

    docker build -t safetywebbing-agent ./agent_image
    SAFETYWEBBING_ISOLATION_IMAGE=safetywebbing-agent uv run pytest tests/test_isolation_docker.py -v

It launches the image with the exact `docker run` argv LiveAgentEngine builds, but swaps the
agent for a probe (SAFETYWEBBING_AGENT_BIN) that does what a prompt-injected agent would:
call out to the host, write to the shared folder, tamper with the firewall. The probe runs
AFTER the entrypoint has installed the firewall and dropped privileges, i.e. in exactly
the position the real agent would be in.

Needs outbound DNS for the LLM API hosts (the firewall resolves them at start-up).
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from safetywebbing.engines.live import LiveAgentEngine

IMAGE = os.environ.get("SAFETYWEBBING_ISOLATION_IMAGE")
pytestmark = pytest.mark.skipif(
    not IMAGE, reason="set SAFETYWEBBING_ISOLATION_IMAGE to a built scan image to run"
)

PROBE = r'''#!/usr/bin/env python3
import json, os, urllib.request

def get(port):
    try:
        urllib.request.urlopen(f"http://host.docker.internal:{port}/", timeout=4)
        return "reachable"
    except Exception:
        return "blocked"

def url(u):
    try:
        urllib.request.urlopen(u, timeout=4)
        return "reachable"
    except Exception:
        return "blocked"

def status(key):
    return [l.split()[1] for l in open("/proc/self/status") if l.startswith(key)][0]

def rw(path):
    try:
        open(path, "w").write("TAMPERED\n")
        return "written"
    except OSError:
        return "denied"

def sh_ok(cmd):
    import subprocess
    return subprocess.run(cmd, shell=True, capture_output=True).returncode == 0

out = {
    "uid": os.getuid(),
    "cap_eff": status("CapEff"), "cap_bnd": status("CapBnd"), "no_new_privs": status("NoNewPrivs"),
    "target": get(int(os.environ["PROBE_TARGET_PORT"])),
    "other_host_port": get(int(os.environ["PROBE_OTHER_PORT"])),
    "metadata": url("http://169.254.169.254/"),
    "internet": url("http://1.1.1.1/"),
    "firewall_flush": sh_ok("iptables -F OUTPUT") if os.path.exists("/usr/sbin/iptables") else False,
    "firewall_accept_all": sh_ok("iptables -P OUTPUT ACCEPT") if os.path.exists("/usr/sbin/iptables") else False,
    "runs_listing": sorted(os.listdir("/work/runs")),
}
rid = os.environ["PROBE_RUN_ID"]
with open(f"/work/runs/{rid}/summary.json", "w") as fh:
    json.dump({"probe": out}, fh)
'''


class _Ok(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture
def host_services():
    servers = []
    for _ in range(2):  # a "target" and some other service on the host (e.g. this app's API)
        srv = ThreadingHTTPServer(("0.0.0.0", 0), _Ok)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    yield servers[0].server_address[1], servers[1].server_address[1]
    for srv in servers:
        srv.shutdown()


def test_container_is_isolated_from_the_host_and_the_network(tmp_path, host_services):
    target_port, other_port = host_services
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "audit.log").write_text("ORIGINAL\n")
    (runs / "triage.json").write_text("{}")
    (runs / "live-other").mkdir()
    (runs / "live-other" / "summary.json").write_text('{"secret": "another run"}')
    probe = tmp_path / "probe.py"
    probe.write_text(PROBE)
    probe.chmod(0o755)

    rid = "live-isolation-test"
    eng = LiveAgentEngine(runs_root=runs, image=IMAGE, auth="claude_oauth",
                          claude_creds_dir=tmp_path / "no-creds")
    eng._prepare_run_dir(rid)
    cmd = eng.build_command(target=f"http://127.0.0.1:{target_port}", goal="g", run_id=rid)
    i = cmd.index(IMAGE)
    cmd[i:i] = [  # extra flags go BEFORE the image, like the engine's own
        "-v", f"{probe}:/probe.py:ro",
        "-e", "SAFETYWEBBING_AGENT_BIN=/probe.py",
        "-e", f"PROBE_TARGET_PORT={target_port}", "-e", f"PROBE_OTHER_PORT={other_port}",
        "-e", f"PROBE_RUN_ID={rid}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
    assert proc.returncode == 0, f"container failed:\n{proc.stderr[-2000:]}"
    got = json.loads((runs / rid / "summary.json").read_text())["probe"]

    # the one thing the agent is allowed to do
    assert got["target"] == "reachable"
    # everything else on the host and the network is refused
    assert got["other_host_port"] == "blocked"  # e.g. SafetyWebbing's own API
    assert got["metadata"] == "blocked"
    assert got["internet"] == "blocked"
    # the agent holds no privileges and cannot lift the firewall
    assert got["uid"] == 1000
    assert got["cap_eff"] == got["cap_bnd"] == "0000000000000000"
    assert got["no_new_privs"] == "1"
    assert got["firewall_flush"] is False and got["firewall_accept_all"] is False
    # only this run's folder is shared: no audit log, triage file or other run
    assert got["runs_listing"] == [rid]
    assert (runs / "audit.log").read_text() == "ORIGINAL\n"
    assert (runs / "triage.json").read_text() == "{}"
    assert (runs / "live-other" / "summary.json").read_text() == '{"secret": "another run"}'


def test_container_refuses_to_start_the_agent_when_the_firewall_cannot_be_installed(
    tmp_path, host_services
):
    """Fail closed: without NET_ADMIN the rules cannot be installed, so the agent must
    never run (exit 97) rather than run unfiltered."""
    target_port, _ = host_services
    runs = tmp_path / "runs"
    eng = LiveAgentEngine(runs_root=runs, image=IMAGE, claude_creds_dir=tmp_path / "no-creds")
    eng._prepare_run_dir("live-failclosed")
    cmd = eng.build_command(target=f"http://127.0.0.1:{target_port}", goal="g",
                            run_id="live-failclosed")
    j = cmd.index("NET_ADMIN")
    del cmd[j - 1:j + 1]  # drop `--cap-add NET_ADMIN`
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
    assert proc.returncode == 97, proc.stderr[-1000:]
    assert not (Path(runs) / "live-failclosed" / "summary.json").exists()
