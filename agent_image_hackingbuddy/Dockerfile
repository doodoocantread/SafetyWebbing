# SafetyWebbing scan image: hackingBuddyGPT's web pentest use-case, wrapped to speak
# SafetyWebbing's agent contract. Like the PentestGPT image, the agent runs ONLY
# inside this container — the container is the isolation boundary (ARCHITECTURE.md §2.3).
#
# Build (from repo root):
#   docker build -t safetywebbing-hackingbuddy ./agent_image_hackingbuddy
#
# hackingBuddy reaches an LLM in one of two ways, chosen at RUN time by the engine
# (SAFETYWEBBING_LLM_AUTH, see safetywebbing_hb_agent/cli.py); both agents share this image:
#   llm_api_key  — litellm with a provider API key forwarded from the server's env
#                  (ANTHROPIC_API_KEY / GEMINI_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY).
#   claude_oauth — the Claude Code CLI below, authenticated by an ephemeral copy of the
#                  host's Claude Code credentials that LiveAgentEngine mounts into the
#                  non-root user's home (/home/agent/.claude), exactly like the PentestGPT image.
# Nothing secret is baked into the image.

# hackingBuddyGPT requires Python >=3.13.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CLAUDE_CODE_DISABLE_AUTO_MEMORY=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    DISABLE_AUTOUPDATER=1

# build-essential + libffi-dev: cffi/asyncssh and a few hackingBuddy deps build
# native extensions. curl/ca-certificates: TLS + a common agent tool.
# iptables: the entrypoint's egress firewall (sw-entrypoint.sh).
# git: pip fetches hackingBuddyGPT from a pinned git commit (see pyproject.toml).
# nodejs/npm: needed by the Claude Code CLI (the claude_oauth LLM path).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential libffi-dev curl ca-certificates iptables git nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Claude Code CLI (driven by safetywebbing_hb_agent/claude_bridge.py). Installed in the
# image either way; it is only used when the engine selects the claude_oauth path.
RUN npm install -g @anthropic-ai/claude-code \
    && npm cache clean --force

WORKDIR /opt/agent
COPY pyproject.toml ./
COPY safetywebbing_hb_agent ./safetywebbing_hb_agent
RUN pip install .

# The AGENT runs non-root: the Claude Code CLI refuses --dangerously-skip-permissions as
# root, and it is defence in depth anyway. Credentials (claude_oauth) or an LLM key
# (llm_api_key) arrive at run time; the claude_oauth mount target is /home/agent/.claude.
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
