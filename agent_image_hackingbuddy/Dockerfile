# SafetyWebbing scan image: hackingBuddyGPT's web pentest use-case, wrapped to speak
# SafetyWebbing's agent contract. Like the PentestGPT image, the agent runs ONLY
# inside this container — the container is the isolation boundary (ARCHITECTURE.md §2.3).
#
# Build (from repo root):
#   docker build -t safetywebbing-hackingbuddy ./agent_image_hackingbuddy
#
# Unlike the PentestGPT image, hackingBuddy talks to an LLM through litellm, NOT
# the Claude Code CLI. There is no credential mount: LiveAgentEngine forwards a
# provider API key (ANTHROPIC_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY) from
# the server's environment at RUN time. Nothing secret is baked into the image.

# hackingBuddyGPT requires Python >=3.13.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# build-essential + libffi-dev: cffi/asyncssh and a few hackingBuddy deps build
# native extensions. curl/ca-certificates: TLS + a common agent tool.
# iptables: the entrypoint's egress firewall (sw-entrypoint.sh).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential libffi-dev curl ca-certificates iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/agent
COPY pyproject.toml ./
COPY safetywebbing_hb_agent ./safetywebbing_hb_agent
RUN pip install .

# The AGENT runs non-root, for parity with the PentestGPT image and defence in depth. It
# needs no host credentials; its LLM key arrives as an env var at run time.
RUN useradd --create-home --uid 1000 agent \
    && mkdir -p /work/runs /work/agent-workspaces \
    && chown -R agent:agent /work /home/agent
ENV HOME=/home/agent

# The container STARTS as root only so the entrypoint can install the egress firewall;
# it then execs the agent as `agent` with every capability dropped (sw-entrypoint.sh).
COPY sw-entrypoint.sh /usr/local/bin/sw-entrypoint
RUN chmod 0755 /usr/local/bin/sw-entrypoint
ENV SAFETYWEBBING_AGENT_BIN=safetywebbing-hackingbuddy-agent
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/sw-entrypoint"]
