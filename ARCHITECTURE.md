# Aegis — Authorized Multi-Agent Security Assessment Platform

> **Authorized use only.** Aegis performs active security testing. It must only
> be pointed at systems you own or for which you hold **written authorization**.
> Running it against third-party systems without permission is illegal in most
> jurisdictions (e.g. the US CFAA, the UK Computer Misuse Act). Aegis enforces
> this in code — see [§2 Safety Core](#2-safety-core) — but the legal
> responsibility is the operator's.

Aegis coordinates specialized AI agents that drive **real, established security
tools** (nuclei, OWASP ZAP, httpx, Playwright) against an authorized target. The
LLM's job is orchestration, triage, correlation, and reporting **over real
evidence** — not to invent findings. Every finding is anchored to a concrete
artifact (an HTTP request/response pair, a scanner signature match, a rendered
DOM state) so it can be independently reproduced.

---

## 1. System Architecture

```
                         ┌──────────────────────────────────────────┐
                         │              React Dashboard               │
                         │  submit URL · authorize · monitor · report │
                         └───────────────┬────────────────────────────┘
                                         │ REST + WebSocket
                         ┌───────────────▼────────────────────────────┐
                         │                FastAPI                      │
                         │  /scans  /authorizations  /ws  /reports     │
                         └───────────────┬────────────────────────────┘
                                         │
             ┌───────────────────────────▼───────────────────────────┐
             │            Orchestrator (LangGraph state machine)       │
             │   authorize → recon → [parallel assessment] → analyze   │
             │                        → report                         │
             └───┬───────────────┬───────────────┬───────────────┬────┘
                 │               │               │               │
        ┌────────▼───┐   ┌───────▼─────┐  ┌──────▼──────┐ ┌──────▼──────┐
        │   Recon    │   │  Web Vuln   │  │  AuthN/AuthZ│ │ API Security│  ...agents
        │   Agent    │   │   Agent     │  │    Agent    │ │    Agent    │
        └────────┬───┘   └───────┬─────┘  └──────┬──────┘ └──────┬──────┘
                 │               │               │               │
        ┌────────▼───────────────▼───────────────▼───────────────▼──────┐
        │                      Tool Layer (sandboxed)                     │
        │   SSRF-safe HTTP client · nuclei · ZAP API · Playwright         │
        └────────┬────────────────────────────────────────────────────────┘
                 │  EVERY outbound request passes through ↓
        ┌────────▼────────────────────────────────────────────────────────┐
        │                        SAFETY CORE                               │
        │  ScopeGuard · SSRFGuard · RateLimiter · AuditLog · KillSwitch    │
        └──────────────────────────────────────────────────────────────────┘
```

**Key architectural decision:** the Safety Core is not a module that agents
*should* call — it is the **only** path to the network. Agents and tools receive
a pre-bound `GuardedHttpClient`; they have no access to a raw socket, raw
`httpx`, or `subprocess` with arbitrary args. A scope violation raises
`ScopeViolation` *before* a packet leaves the box. This makes "stay in scope" a
structural property, not a behavioral hope about an LLM.

---

## 2. Safety Core

The heart of the platform. Lives in `backend/safety/` and is exercised by
`tests/test_scope.py`. Nothing reaches the network without clearing all of it.

| Component     | Responsibility | Enforcement point |
|---------------|----------------|-------------------|
| `ScopeGuard`  | Decide whether a given URL/host/IP is in authorized scope. Allowlist of registrable domains + explicit subdomains + CIDR ranges. Deny by default. | Called on every request URL and on every redirect `Location`. |
| `SSRFGuard`   | Resolve the host, reject private/loopback/link-local/reserved/multicast IPs, reject DNS-rebinding (pins the resolved IP and connects to *that* IP). Reject non-http(s) schemes, credentials-in-URL, and odd ports unless allowlisted. | Wraps the transport; re-checks the *resolved* IP, not just the hostname. |
| `RateLimiter` | Token-bucket per-host RPS + global concurrency cap + per-scan request budget. Backs off on 429/503. | `await`ed before each request is released. |
| `AuditLog`    | Append-only, hash-chained JSONL of every authorization decision, request, tool invocation, and finding. Tamper-evident. | Written synchronously at each decision/request. |
| `KillSwitch`  | Per-scan + global stop flag. Checked in the request path and between agent steps; flips on budget exhaustion, operator "pause/stop", or repeated errors. | Request path + orchestrator node boundaries. |

### Authorization flow (must pass before any active scan)
1. Operator submits a target and attests ownership.
2. Aegis issues a **verification token** and requires **one** proof method:
   - **DNS TXT**: `aegis-site-verification=<token>` on the apex/host, **or**
   - **well-known file**: `GET /.well-known/aegis-authorization.txt` returning the token, **or**
   - **HTTP header**: `X-Aegis-Authorization: <token>` on the homepage.
3. Verification itself is a *single, unauthenticated, read-only* GET/DNS lookup,
   subject to SSRFGuard but exempt from the "must already be authorized" check
   (it's how you *become* authorized).
4. On success, a signed `Authorization` record (target scope, methods enabled,
   expiry, operator identity) is persisted. Scans reference it by id. Expired or
   missing authorization ⇒ the orchestrator refuses to leave the `authorize`
   node.

### Non-destructive guarantees
- Default **passive/safe** profile: scanners run with safe-checks only
  (`nuclei -etags intrusive,dos`, ZAP passive scan + safe active rules).
- Exploitation Validation agent is **PoC-only**: it confirms a vuln with a
  benign, idempotent marker (e.g. reflecting a unique nonce for XSS, a boolean
  timing/number-of-rows oracle for SQLi using a non-mutating `AND 1=1`/`AND 1=2`
  pair) and **never** runs `UNION SELECT` dumps, writes, deletes, uploads, or
  auth-bypass persistence.
- Hard blocklist of destructive payload classes, checked on every payload.
- `--profile aggressive` exists but requires an explicit extra attestation and
  still refuses the destructive blocklist.

---

## 3. Agents & Tool Permissions

Each agent is a LangGraph node with (a) a Claude reasoning loop, (b) a **narrow,
declared tool permission set**, and (c) a structured output contract. An agent
can only call tools in its grant; the grant is enforced by the tool registry,
not by prompt instruction.

| Agent | Reads | Tools granted | Emits |
|-------|-------|---------------|-------|
| **Recon** | target root | GuardedHttp, Playwright(read), nuclei(`-tags tech,exposure`), DNS | `tech[]`, `endpoints[]`, `surfaces[]` |
| **AuthN/AuthZ** | endpoints, surfaces | GuardedHttp, Playwright | `auth_findings[]` (session, IDOR candidates, privilege boundaries) |
| **Web Vuln** | endpoints | GuardedHttp, nuclei, ZAP(passive+safe-active) | `web_findings[]` (OWASP Top 10 candidates) |
| **API Security** | endpoints, discovered specs | GuardedHttp, nuclei(`-tags api`) | `api_findings[]` |
| **Exploitation Validation** | candidate findings | GuardedHttp (PoC payloads only, blocklist-checked) | `validated[]` with reproduction evidence |
| **Security Analysis** | all findings | *(no network)* Claude only | deduped, CVSS-scored `findings[]` |
| **Reporting** | scored findings | *(no network)* Claude + template | `report.md` / `report.html` / `report.json` |

Agents share state through the LangGraph `ScanState` (see §4), not by calling
each other directly. The analysis agent is the only writer of the canonical
finding list; assessment agents only append *candidates*.

---

## 4. LangGraph Orchestration

`ScanState` (a typed dict) is the shared blackboard:

```python
class ScanState(TypedDict):
    scan_id: str
    authorization_id: str
    scope: ScopeSpec            # frozen allowlist
    profile: Literal["passive","safe","aggressive"]
    budget: Budget              # remaining requests / time
    tech: list[Tech]
    endpoints: list[Endpoint]
    candidates: list[Finding]   # append-only, written by assessment agents
    validated: list[Finding]
    findings: list[Finding]     # canonical, written by analysis agent
    events: list[Event]         # streamed to the dashboard
    status: ScanStatus
```

Graph topology:

```
authorize ──▶ recon ──▶ fan_out ──┬─▶ web_vuln  ──┐
                                   ├─▶ authz      ──┤
                                   ├─▶ api        ──┤─▶ join ─▶ validate ─▶ analyze ─▶ report ─▶ END
                                   └─▶ (dynamic)  ──┘
```

- **Parallelism:** `fan_out` dispatches independent assessment agents
  concurrently (LangGraph parallel edges / `asyncio.gather`), each writing to its
  own slice of state to avoid write conflicts.
- **Sharing findings:** recon output is injected into every assessment agent's
  context. If one agent flags a *suspicious surface* (e.g. a login form, a
  GraphQL endpoint), it writes a `lead` that the orchestrator routes to the
  best-suited agent as **dynamic additional investigation** (a conditional edge
  that can re-enter `fan_out` with a focused sub-task).
- **Dedup / no duplicate work:** a `WorkLedger` keyed by `(agent, technique,
  endpoint)` prevents re-running the same check; the analysis node does
  semantic dedup across agents.
- **Status / timing:** every node wraps its body in a span that records start,
  end, request count, and errors into `events`; streamed over WebSocket.
- **Failure & retry:** node failures are caught; transient ones retry with
  backoff (bounded); persistent ones mark that agent `degraded` and the scan
  continues with partial results rather than aborting.
- **Checkpointing:** LangGraph checkpointer persists state so a scan can
  pause/resume and survive a worker restart (important in the ephemeral cloud
  container).

---

## 5. Security Risks In The Scanner Itself (threat model)

| Risk | Mitigation |
|------|------------|
| **SSRF via target redirects / rebinding** — a target 302s us to `169.254.169.254` or rebinds DNS to an internal IP. | SSRFGuard pins and re-validates the *resolved IP* on every hop; private ranges hard-blocked; redirects re-run ScopeGuard. |
| **Scope creep** — scanner wanders to third-party CDNs, OAuth providers, linked domains. | Deny-by-default allowlist; off-scope links recorded as *observations*, never fetched. |
| **Prompt injection from the target** — a page/API returns text telling the agent to scan another host or exfiltrate. | Target content is treated as untrusted data, never as instructions; the network path is gated by ScopeGuard regardless of what the LLM "decides"; tool args are schema-validated. |
| **Becoming a DoS** against the authorized target. | Per-host rate limit, concurrency cap, 429/503 backoff, request budget, `-etags dos`. |
| **Destructive payloads** (even accidental). | Payload blocklist, non-destructive profiles by default, PoC-only validation. |
| **Secret/evidence leakage** — reports contain live creds, tokens, PII. | Evidence redaction pass (strip cookies/authz headers/token-like strings) before storage; reports stored under the session workspace only. |
| **Command injection in tool wrappers** — target-derived strings reach a shell. | Tools invoked via `subprocess` arg-vectors (never `shell=True`); all target-derived values passed as positional args, never interpolated into a command string. |
| **Credential handling** — Claude API key, target creds. | From env/secret store; never logged; redacted in audit log. |
| **Audit tampering** | Hash-chained append-only audit log. |

---

## 6. Phased Implementation Plan

- **Phase 0 — Safety Core (first, non-negotiable).** ScopeGuard, SSRFGuard,
  RateLimiter, AuditLog, GuardedHttpClient + tests. *Nothing else is built until
  these pass.* ✅ built in this repo.
- **Phase 1 — Authorization & persistence.** Authorization verification (DNS/
  file/header), signed records, SQLite models, FastAPI skeleton.
- **Phase 2 — Orchestrator + Recon.** LangGraph graph, `ScanState`, recon agent
  driving the guarded client + Playwright, WebSocket event stream.
- **Phase 3 — Assessment agents.** Web Vuln (nuclei/ZAP), AuthN/AuthZ, API.
- **Phase 4 — Validation + Analysis + Reporting.** PoC validation, CVSS scoring/
  dedup, multi-format report.
- **Phase 5 — Dashboard.** React: submit, authorize, live agent view, findings,
  severity breakdown, report download.
- **Phase 6 — Hardening.** Sandboxing/containerization of scanner tools,
  resource limits, soak tests.

See `README.md` for how to run what exists today.
