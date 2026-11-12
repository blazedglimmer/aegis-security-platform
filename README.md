# 🛡️ Aegis — Authorized Multi-Agent Security Assessment Platform

Aegis points a team of specialized AI agents at a web target **you own or are
authorized to test**, drives **real security tools** (built-in evidence checks,
nuclei, OWASP ZAP, Playwright) to find vulnerabilities, **validates** them with
non-destructive proofs, scores them by **CVSS 3.1**, and produces a
reproducible report — all behind a safety core the scanner cannot bypass.

> ⚠️ **Authorized use only.** Active security testing of systems you do not own
> or have no written permission to test is illegal in most jurisdictions.
> Aegis enforces target ownership verification and scope confinement in code,
> but the legal responsibility for authorization is yours.

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the full design, agent/tool
permissions, LangGraph workflow, scanner threat model, and phased plan.

---

## What makes it *not* just "LLMs guessing vulnerabilities"

* Every finding is anchored to a real **HTTP exchange / scanner match / DOM
  state** captured by the guarded client. The LLM is **optional** — with no API
  key, Aegis still detects and validates issues from real evidence.
* Injection candidates are **confirmed** by non-destructive oracles: reflected
  XSS by unencoded-context reflection; SQLi by a read-only `1=1`/`1=2` boolean
  oracle. No data is read, modified, or deleted.
* CVSS scores are **computed by formula** from an auditable vector, not invented.
* A **hash-chained audit log** records every decision and request (tamper-evident).

## Safety core (enforced, not advisory)

Agents never touch a raw socket — they get a `GuardedHttpClient` that runs, on
every request **and every redirect hop**:

`kill-switch → scope allowlist → SSRF resolve-&-pin → rate-limit → budget → audit`

* **ScopeGuard** — deny-by-default registrable-domain/CIDR allowlist; lookalikes
  and suffix tricks rejected; ports & schemes are part of scope.
* **SSRFGuard** — resolves the host itself, rejects private/reserved/**cloud-
  metadata** addresses, and pins the connection to the vetted IP (defeats DNS
  rebinding). Private ranges allowed **only** if an authorized CIDR includes them.
* **RateLimiter / Budget** — per-host token bucket, concurrency cap, request/time
  budget, 429/503 backoff.
* **Payload blocklist** — the validation agent refuses any destructive/exfil
  payload (UNION dumps, writes, time-based, OOB callbacks, OS commands…).

## Agents

`recon` → ( `web_vuln` ∥ `authz` ∥ `api` ) → `exploit` (validate) → `analysis`
(dedup + CVSS) → `reporting`. Orchestrated by **LangGraph** (with a native
asyncio fallback), parallel assessment, shared findings, work-dedup ledger,
per-agent status/timing, and failure isolation (one agent degrades, scan
continues).

---

## Quick start

```bash
cd aegis
uv venv --python 3.13 .venv && . .venv/bin/activate
uv pip install -r requirements.txt
# optional: real browser crawling
python -m playwright install chromium
```

Run the server:

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8777
```

Open **http://127.0.0.1:8777/** and:

1. Enter your target URL → **Get verification token**.
2. Prove ownership via DNS TXT, a `/.well-known/aegis-authorization.txt` file,
   or an `X-Aegis-Authorization` header → **Verify ownership**.
3. Pick a profile (passive / safe / aggressive) and agents → **Start scan**.
4. Watch agents work live, review findings, download `report.{html,md,json}`.

### Configuration (env vars, prefix `AEGIS_`)

| Var | Default | Purpose |
|-----|---------|---------|
| `AEGIS_ANTHROPIC_API_KEY` | — | Enables LLM triage/report prose (optional) |
| `AEGIS_SIGNING_SECRET` | `change-me-in-production` | **Change this** — HMAC for authorization records |
| `AEGIS_NUCLEI_PATH` | `nuclei` | nuclei binary (auto-detected on PATH) |
| `AEGIS_ZAP_API_URL` / `AEGIS_ZAP_API_KEY` | — | OWASP ZAP daemon API |
| `AEGIS_DEFAULT_PER_HOST_RPS` | `4.0` | Throttle |
| `AEGIS_DEFAULT_REQUEST_BUDGET` | `5000` | Per-scan request cap |

External scanners are optional and auto-detected; with none installed Aegis runs
its built-in passive/active evidence checks.

## External tools (optional, recommended)

```bash
# nuclei (Go): https://github.com/projectdiscovery/nuclei
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# OWASP ZAP daemon:
zap.sh -daemon -port 8080 -config api.key=YOUR_KEY   # then set AEGIS_ZAP_API_URL/KEY
```

## Tests

```bash
. .venv/bin/activate && python -m pytest -q
```

The suite covers the safety core (scope/SSRF/rebinding/budget/audit), the CVSS
calculator against first.org reference vectors, authorization verification, and
a **full end-to-end scan** against a bundled deliberately-vulnerable app that
asserts real, validated findings — plus a backend API integration test.

## API

| Method | Path | |
|---|---|---|
| POST | `/api/authorizations` | issue verification token + instructions |
| POST | `/api/authorizations/verify` | run proof, persist signed authorization |
| POST | `/api/scans` | create a scan (requires authorization) |
| POST | `/api/scans/{id}/start\|pause\|resume\|stop` | control |
| GET | `/api/scans` · `/api/scans/{id}` · `/api/scans/{id}/findings` | status/results |
| GET | `/api/scans/{id}/report.{json,md,html}` | download report |
| WS | `/api/scans/{id}/events` | live event stream |

## Status & roadmap

Phases 0–5 are implemented and tested (safety core, authorization, orchestrator
+ all seven agents, tool integrations, backend, dashboard). **Phase 6**
(sandboxing external scanners in a network-restricted container, resource
limits, soak tests) is the remaining hardening work — see ARCHITECTURE §6.

Aegis is a defensive assessment platform for authorized targets. It intentionally
does **not** perform data exfiltration, persistence, destructive exploitation, or
testing of systems you have not proven you control.
