# SafetyWebbing Benchmark

Measures how well a scan agent finds the **known** vulnerabilities of intentionally
vulnerable local targets. See [`../BENCHMARK.md`](../BENCHMARK.md) for the design.

> ⚠️ The target images contain real exploitable vulnerabilities on purpose. The compose
> file binds them to `127.0.0.1` only — never expose them to a network or run them in
> production.

## Layout

```
benchmark/
  docker-compose.benchmark.yml   # Juice Shop + DVWA + bWAPP, bound to 127.0.0.1
  ground_truth/<target>.json     # the vulnerabilities each target is known to have
  suites/default.json            # which targets x scan types to run, and how many times
  results/<timestamp>/           # output: records.jsonl, scores.json, report.md
```

The harness code is the `safetywebbing.benchmark` package (`run` / `score` subcommands).
It adds no dependency — it drives scans through the normal `POST /api/scan` API, so every
scan still passes the loopback whitelist and the fixed goal.

## Run it

```bash
# 1. Start the vulnerable targets (wait ~30s for Juice Shop to boot)
docker compose -f benchmark/docker-compose.benchmark.yml up -d

# For DVWA/bWAPP: open them once in a browser, log in, and set the security level
# to "low" (DVWA: Setup/Reset DB first). Ground truth assumes the low level.

# 2. Start the SafetyWebbing server (another terminal)
uv run uvicorn safetywebbing.api:app --port 8000

# 3. Run the benchmark suite (repeats each case 3x by default)
uv run python -m safetywebbing.benchmark run \
  --suite benchmark/suites/default.json \
  --model claude-sonnet-5-5

# 4. Tear the targets down
docker compose -f benchmark/docker-compose.benchmark.yml down
```

Useful `run` flags: `--agent`, `--model`, `--mode {docker,direct}`, `--timeout-s`,
`--repeat`, `--base-url`, `--max-wait-s`, `--out`.

## Re-score without re-running

Scoring reads saved `records.jsonl`, so you can re-score (e.g. after fixing a ground-truth
entry) without spending another scan:

```bash
uv run python -m safetywebbing.benchmark score benchmark/results/<timestamp>/records.jsonl
```

## Metrics (per target × scan type, averaged over repeats)

| Metric | Meaning |
|---|---|
| Recall (mean / best) | % of known vulns found (averaged over runs / ever found) |
| Precision | % of on-target findings that matched a known vuln (**lower bound** — the lists are focused, not exhaustive) |
| F1 | harmonic mean of recall and precision |
| CWE acc / OWASP acc | of the vulns found, % labeled with the right CWE / OWASP category |
| Sev Δ | mean severity-rank error on found vulns (0 = perfect) |
| Repro | 1 − (vulns found in some-but-not-all runs ÷ total); 100% = fully consistent |

Failed / timed-out scans are listed separately and **excluded** from scoring — a failed
scan is inconclusive, not "clean" (same rule as the app's overview page).

## Matching

A finding matches a known vuln when the CWE matches (or the vuln-class names overlap when
a CWE is missing) **and**, if both sides carry an endpoint, the endpoints agree. Origins and
endpoints are normalized with the same rules as `insights.py` (loopback → `localhost`,
numeric/hex id segments → `:id`), and assignment is one-to-one so repeat scans of the same
bug count once.

## Editing ground truth

Each entry needs `id`, `scan_type` (`sqli`/`xss`/`auth`/`general`), `vuln_class`, and ideally
`cwe`, `owasp`, `endpoint`, `severity`. Use `endpoint: "*"` when the vuln isn't tied to one
path. Keep the lists **focused and correct** rather than exhaustive — precision is reported as
a lower bound precisely because these aren't full inventories.
