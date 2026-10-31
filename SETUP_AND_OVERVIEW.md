# SafetyWebbing — Setup & Overview for New Users

A plain-language onboarding guide: what the project is, how to get it running, and what each part of the site does. For the authoritative detail, see [`README.md`](README.md); this report condenses it into a path a newcomer can follow start to finish.

---

## 1. What SafetyWebbing is

SafetyWebbing is a school science project that turns an AI pentest agent's raw output into a **structured, traceable vulnerability report** for a web app running **on your own machine**.

The guiding principle: **the AI explains, it does not decide.** The agent never chooses its own target, never decides what to attack, and never writes new exploit code. Those limits are enforced in code (with tests), not left to the model's good behavior.

The flow, end to end:

1. **Input** — you give a local URL (e.g. `http://127.0.0.1:3000`) and pick a scan type.
2. **Scan** — a pentest agent runs inside an isolated Docker container against that URL, using a fixed goal template (not free text).
3. **Adapt** — the agent writes `summary.json` + `traces/`; SafetyWebbing joins them into *findings* with request/response evidence. No LLM involved here.
4. **Label** — each finding gets a vulnerability class, severity, CWE and remediation note, from an LLM (optional) or an offline heuristic. CWE→OWASP mapping comes from a static table.
5. **Report** — read it in the browser, export Markdown or PDF, then triage each finding and rescan to confirm.

The host app only orchestrates. It never runs the agent in-process; the only contract between them is the files in `runs/<run_id>/`.

---

## 2. Safety model (read before scanning)

Five invariants live in code (`tests/test_safety.py`):

| Rule | Meaning |
|---|---|
| **Local targets only** | Only `http`/`https` on `localhost`, `127.0.0.0/8` or `::1` are accepted; anything else is rejected before anything spawns. |
| **Fixed scope** | A scan type maps to a goal template in code — neither user nor agent can change what is searched for. |
| **Isolation** | The agent has full shell access, so by default it runs only in a Docker container. The container *is* the security boundary. |
| **No unsupported claims** | The LLM layer only interprets evidence; raw request/response data enters prompts as untrusted, delimited data (prompt-injection defense). |
| **Audit log** | Every scan request is appended to `runs/audit.log` before anything runs. |

Other limits: max 2 parallel scans, per-scan timeout (30–3600 s, default 600), validated model names, and API keys passed by environment-variable *name* so they never hit a command line.

> **Only scan systems you own or have explicit permission to test.**

---

## 3. Getting set up

### 3a. Prerequisites

What you need depends on how far you want to go. The app is built in layers, and each layer adds one dependency:

| You want to… | You need |
|---|---|
| See the app and replay the demo | Python 3.12+, `uv`, a browser with internet (for the CDN) |
| Run a real scan in Docker (recommended) | The above **+** Docker running, the agent image built, a local target, and **either** a Claude Code login **or** an LLM API key |
| Run a real scan without Docker (`direct`) | A Claude Code login on the host **+** the agent installed in its own venv **+** the server started with the direct opt-in |

Work top to bottom — each step below builds on the one before it, and you can stop as soon as you have what you need.

### Step 1 — Install and run the app

Requires **Python 3.12+** and [`uv`](https://docs.astral.sh/uv/). Nothing else is needed for this step.

```bash
git clone https://github.com/doodoocantread/SafetyWebbing.git
cd SafetyWebbing
uv sync --extra dev
uv run uvicorn safetywebbing.api:app --port 8000
```

`uv sync` installs **only the host app** (FastAPI, uvicorn, pydantic). It does **not** install Docker, the Claude CLI, or any agent — those are separate and covered below.

Open <http://127.0.0.1:8000>. Use the **VI / EN** button to switch language and the sun icon for light/dark theme; both are remembered in the browser.

> The pages load React and Babel from a CDN, so the browser needs internet access. There is no frontend build step.

### Step 2 — Try it with zero extra setup (demo replay)

Before installing anything else, confirm the app works: open **New scan** → under **Demo — saved runs (replay)** click `sqli-claude-03`. This replays a real earlier scan (a SQL-injection login bypass against OWASP Juice Shop). It's free, deterministic and offline — no Docker, no agent, no login. Ideal for a first look or a demo.

If you only want to *see* SafetyWebbing, you can stop here.

### Step 3 — Set up Claude (for real scans with the default agent)

**This is not done by `uv sync`.** SafetyWebbing never logs Claude in for you and never prompts for a password or key. Claude comes in as a **separate Claude Code CLI** (the npm package `@anthropic-ai/claude-code`), and you set it up once, yourself:

```bash
npm install -g @anthropic-ai/claude-code   # needs Node/npm
claude                                      # runs the OAuth login once
```

That login writes OAuth credentials to `~/.claude` (`.credentials.json`, optionally `.claude.json`). SafetyWebbing then **reuses** that session — it never asks you to log in again.

Where the CLI needs to live depends on the run mode:

- **Docker mode** — the CLI *binary* is already baked into the agent image (`agent_image/Dockerfile` runs `npm install -g @anthropic-ai/claude-code` at build time), so you do **not** install the CLI on the host. You only need to be **logged in on the host once**: the engine copies your `~/.claude` credentials into a fresh temp dir and mounts that copy **read-write** into the container (at the non-root user's home — Claude Code refuses to run as root). The container refreshes its own token; your real host credentials are never exposed to the agent's writes, and the copy is deleted after the run.
- **Direct mode, or the Claude-CLI report labeler** — Claude runs on the **host**, so the CLI must be installed on the host and on `PATH` (the code checks with `shutil.which("claude")`).

**Prefer not to use the Claude CLI?** Two alternatives need no Claude login:
- The `hackingbuddy` agent with an LLM **API key** (`ANTHROPIC_API_KEY`, or `GEMINI_`/`OPENAI_`/`OPENROUTER_API_KEY`).
- The offline **heuristic labeler** for report narrative (the default when no key/login is present).

Either way, open the **System** page (`/system`) to confirm what's detected — it reports whether the `claude` CLI is present and which labeler is active, showing only *whether* a secret exists, never its value.

### Step 4 — Run a real scan in Docker (recommended)

1. Build the agent image once:
   ```bash
   docker build -t safetywebbing-agent ./agent_image
   ```
2. Start a target you're allowed to test (e.g. OWASP Juice Shop on `http://127.0.0.1:3000`).
3. In the UI, open **New scan**, fill the form, press **Start scan** — or POST to `/api/scan`. Output lands in `runs/<run_id>/` and shows up in History.

For running **without** Docker, see [§6a](#6a-running-without-docker).

---

## 4. A tour of the site (seven pages)

| Page | Path | What it's for |
|---|---|---|
| **Overview** | `/` | Big picture across all scans: open vulns by severity, OWASP Top 10 spread, risk per target, scans per day, and a "needs attention" list. A `failed` scan is never counted as "clean". |
| **New scan** | `/scan` | Enter target, scan type, agent, run mode, optional model/timeout, then **Start scan**. Live terminal log and a **Cancel** button while running. Demo runs sit below the form. |
| **Scan history** | `/history` | Every live scan newest-first, with target, type, mode, model, status, cost, duration. Filter by project/status; open a row to see the report plus exact settings used. Reports are cached in `runs/<run_id>/report.json`, so reopening never re-calls the LLM. |
| **Vulnerabilities** | `/vulns` | Findings de-duplicated across scans (fingerprint = target + CWE/class + endpoint). Set a status per finding — **New / Fixing / Fixed / False positive / Risk accepted** — with an optional note. Flags **recurring** bugs. **Rescan to confirm** pre-fills the scan form. Decisions stored in `runs/triage.json`. |
| **Benchmark** | `/benchmark` | How SafetyWebbing scores against apps with known weaknesses, read from committed files in `benchmark/results/`. Read-only; it cannot start a run. Current results are pilot/smoke data, labelled as such. Method is in [`benchmark/PROTOCOL.md`](benchmark/PROTOCOL.md). |
| **Method & Contributions** | `/about` | Static page for the science-project audience: what PentestGPT does, what SafetyWebbing adds, the pipeline, the safety design, and limits. |
| **System** | `/system` | Pre-flight check: Docker CLI/daemon/image status, direct-mode agent availability, which labeler is active, limits in force, fixed scan scope, storage counts, and the `audit.log` viewer. Shows only *whether* a secret is set, never its value. |

---

## 5. Choosing an agent

Picked per scan, independent of run mode. All agents write the same on-disk contract, so the report is identical whichever ran.

| Agent | LLM auth | Modes |
|---|---|---|
| `pentestgpt` (default) | Your host's Claude Code OAuth session (temp copy mounted) | `docker`, `direct` |
| `hackingbuddy` | An LLM API key via litellm (UI per-scan or server env) | `docker` only |
| `hackingbuddy_claude` | Host's Claude Code session (no key) | `docker`, `direct` |

Only hackingBuddyGPT's **web** use-case is included (takes a URL); its shell/SSH privilege-escalation use-cases are deliberately excluded.

---

## 6. Run modes

| Mode | Isolation | Use when |
|---|---|---|
| `docker` (default) | **Yes** — the container is the boundary | Default, demos, any target you can't fully trust |
| `direct` | **No** — agent runs uncontained on your machine | Fast iteration on a dev machine without Docker |

The whitelist, fixed goal, audit log, adapter and report are identical in both. `direct` can only be enabled **server-side** (`SAFETYWEBBING_ALLOW_DIRECT=1`); a request or the UI can't turn it on. It needs the relevant agent installed in its own venv (`.agent-venv` / `.hb-venv`).

### 6a. Running without Docker

Docker is only the default because it's the safety boundary. The non-Docker path is **`direct` mode**, which runs the agent CLI as an ordinary host process with **no isolation** — so use it only on targets you fully trust. Three things are required:

**1. Be logged into the Claude Code CLI** on the host (see [Step 3](#step-3--set-up-claude-for-real-scans-with-the-default-agent)).

**2. Install the agent into its own venv** (the host app never imports the agent):

```bash
# PentestGPT agent → .agent-venv (use Python 3.12)
uv venv .agent-venv --python 3.12
uv pip install --python .agent-venv/Scripts/python.exe ./agent_image   # Linux/macOS: .agent-venv/bin/python

# or hackingbuddy_claude → .hb-venv (requires Python 3.13)
uv venv .hb-venv --python 3.13
uv pip install --python .hb-venv/Scripts/python.exe ./agent_image_hackingbuddy
```

**3. Start the server with the opt-in flag** (PowerShell):

```bash
$env:SAFETYWEBBING_ALLOW_DIRECT = "1"; uv run uvicorn safetywebbing.api:app --port 8000
```

On Linux/macOS: `SAFETYWEBBING_ALLOW_DIRECT=1 uv run uvicorn safetywebbing.api:app --port 8000`.

Then in **New scan**, the **Run mode** field unlocks "Directly on this machine" once a direct agent is detected; pick `direct` per scan. In direct mode the host's `ANTHROPIC_API_KEY` is scrubbed from the agent's environment to match the container, and the whole process tree is killed on timeout. For a non-standard agent location, point to it with `SAFETYWEBBING_AGENT_CMD` (PentestGPT) or `SAFETYWEBBING_HB_AGENT_CMD` (hackingbuddy_claude).

> The **demo/replay** run (`sqli-claude-03`) needs no Docker *and* no agent install — it just replays a saved scan offline. That's the zero-dependency way to see the app; direct mode is for running *new* scans without a container.

---

## 7. Reports & labeling

A report separates **facts** (deterministic: goal, target, status, cost, duration, and each finding's request/response/evidence) from **narrative** (interpretive: class, severity, CWE, explanation, remediation). Three labelers produce the narrative, chosen by `SAFETYWEBBING_LABELER`:

- **Claude CLI** — uses your existing Claude login, no API key; never chosen implicitly.
- **LLM API** — needs `ANTHROPIC_API_KEY` + the `anthropic` package.
- **Heuristic** — offline, free, rule-based; the default fallback.

A finding supported only by the agent's own claim is capped at **medium** severity, in code. A `failed` run is reported honestly — "nothing found" and "the run errored" are never conflated. Exports: **Markdown** download and **Print / PDF**.

---

## 8. Day-to-day developer commands

```bash
uv sync --extra dev
uv run pytest            # ~460 tests, no Docker or network needed
uv run ruff check .      # lint
uv run uvicorn safetywebbing.api:app --port 8001 --reload   # dev server w/ auto-reload
```

Interactive API docs (Swagger) are at `/docs`. The UI is a thin client over the HTTP API (`/api/scan`, `/api/history`, `/api/vulns`, `/api/overview`, `/api/benchmark`, etc.).

---

## 9. Known limitations (set expectations)

- Narrative text (explanations, remediation, goal templates) is **in Vietnamese**; the UI chrome switches to English.
- **Single user, no auth** — run it on your own machine; don't expose it to a network.
- **No database** — state lives in files under `runs/`; a restart marks running scans as *interrupted*.
- **`direct` mode is not isolated.**
- **Agent output varies** — treat a report as a lead to verify, not proof of safety.
- One bundled sample run (SQL-injection vs Juice Shop); other scan types have no bundled sample.

---

*Condensed from [`README.md`](README.md). For file-by-file detail see `CODEMAP.md`; for design rationale see `ARCHITECTURE.md` (both currently in Vietnamese).*
