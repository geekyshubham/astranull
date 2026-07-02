# Agent, Probe, and Detection Backend Blueprint

## Why no inbound firewall opening is needed

The AstraNull Agent does not need inbound management access because it initiates all control-plane communication outward.

```text
Agent -> AstraNull Control Plane: register, heartbeat, poll/stream jobs
AstraNull Probe Fleet -> Customer target: safe labeled probe traffic
Agent -> AstraNull Ingestion: observations, health, diagnostics
```

Important distinction:

- No inbound **management** port is required.
- The agent can only observe traffic that reaches its local host, local canary, configured logs, or mirrored interface.
- If installed on a random VM, it will not magically see traffic to another VM.
- For broad observation, the customer must deploy host agents at relevant origins, canary agents behind the same path, log observers, or packet-mirror collectors.

## Backend services and APIs

| Service | Critical APIs | Notes |
|---|---|---|
| Token Service | create/list/revoke bootstrap token | Token secret displayed once; hash stored |
| Agent Registry | register, heartbeat, revoke, capabilities | Issues per-agent identity |
| Control Plane | poll jobs, ack jobs, stream config | Outbound WebSocket or long-poll |
| Target Service | CRUD target groups/targets/bindings | Customer-declared only |
| Check Catalog | list checks, versions, prerequisites | Safety class and required agent mode |
| Test Planner | create run, expand jobs, enforce caps | Validates prerequisites |
| Probe Coordinator | dispatch external probes, collect results | Uses AstraNull-owned probe workers |
| Event Ingestion | receive probe/agent/SOC events | Idempotent event IDs |
| Correlation Engine | match nonce/time window/target/agent | Produces correlation confidence |
| Verdict Engine | pass/fail/inconclusive/misplaced | Uses truth tables |
| Finding Service | create/dedupe/update/retest | Links to remediation |
| SOC Service | high-scale approval state machine | Customer cannot bypass |

## Agent registration lifecycle

```text
token.created -> agent.installing -> agent.registering -> agent.identity_issued -> agent.online -> agent.bound -> agent.observing -> agent.updating/revoked/offline
```

| Stage | Backend record | Agent behavior | UI state |
|---|---|---|---|
| Token created | bootstrap_tokens | none | Install command ready |
| Registering | agent_registration_attempts | sends token, fingerprint, hostname, modes | Pending |
| Identity issued | agents + credentials | stores credential securely | Online soon |
| Heartbeating | agent_heartbeats | sends health/version/clock/capabilities | Online |
| Bound | agent_target_bindings | receives jobs for target group | Bound |
| Observing | agent_observations | acked job + metadata-only observation upload | Running |
| Revoked | revoked_at set | stops jobs/uploads fail | Revoked |

## Agent observation modes

| Mode | Sees | Best for | Required privilege | Evidence produced |
|---|---|---|---|---|
| Heartbeat only | agent health | base install proof | none | health events |
| Canary HTTP listener | labeled HTTP requests to canary | LB/WAF/CDN path proof | non-root if high port | request metadata + nonce |
| Packet metadata | packets to local host/interface | origin VM proof | capture capability may be needed | 5-tuple + flags + nonce marker when possible |
| Log tail | app/proxy logs containing nonce | app/serverless/container cases | read log permission | log line hash + timestamp |
| eBPF/flow observer | local flow metadata | Linux host visibility | kernel/capability dependent | flow metadata |
| Mirror collector | mirrored traffic from TAP/mirror | broad enterprise visibility | configured mirror target | packet metadata, no payload by default |
| Kubernetes DaemonSet | node-level agent | GKE/EKS/AKS/OpenShift nodes | cluster install | node health + selected observations |
| Kubernetes sidecar | same pod context | critical app pods | workload change | request/log metadata |

## Test run lifecycle

```text
CREATED -> PLANNED -> AGENTS_ARMED -> PROBES_DISPATCHED -> COLLECTING -> CORRELATED -> VERDICTED -> FINDINGS_CREATED -> REPORTED
```

Failure states:

| State | Meaning | User-facing message |
|---|---|---|
| BLOCKED_PREREQUISITE | Missing agent/target/check requirement | “This check needs an agent that can observe this target.” |
| AGENT_OFFLINE | Bound agent offline | “Agent is offline; fix or choose another agent.” |
| PROBE_FAILED | Probe infrastructure error | “AstraNull probe failed; no customer risk inferred.” |
| INCONCLUSIVE | Evidence insufficient | “We could not prove pass/fail. See why.” |
| MISPLACED_AGENT | Agent cannot observe expected path | “Agent placement does not prove this target.” |
| SAFETY_BLOCKED | Limits/approval missing | “This scenario needs SOC approval.” |

## Correlation truth table

| External result | Agent observation | Verdict | Explanation |
|---|---|---|---|
| Blocked/timeout | Not seen | Protected or likely protected | Expected block; no inside signal |
| Success/response | Seen | Bypassable/allowed | Traffic reached observed environment |
| Blocked/timeout | Seen | Penetrated but not responded | Edge/app may block response after traffic hit origin |
| Success/response | Not seen | Inconclusive or wrong placement | Probe reached something, but this agent did not observe it |
| Probe failed | Any | Inconclusive | AstraNull probe issue |
| Agent offline | Any | Inconclusive | No inside evidence |

## Detection confidence model

| Confidence | Requirements |
|---|---|
| High | Probe event and agent observation share nonce/test ID/target/time window |
| Medium | Probe event and indirect log/health signal match target/time window |
| Low | Only external response evidence, no internal observation |
| Inconclusive | Missing prerequisite, offline agent, ambiguous route, or clock skew |

## Detection event envelope

```json
{
  "event_id": "evt_...",
  "tenant_id": "org_...",
  "environment_id": "env_...",
  "target_group_id": "tg_...",
  "test_run_id": "run_...",
  "check_id": "origin.direct_ip.http",
  "source": "agent|probe|soc|system",
  "timestamp": "2026-06-30T00:00:00Z",
  "nonce_hash": "sha256:...",
  "signal_type": "probe_result|agent_observation|health|approval|verdict",
  "metadata": {},
  "signature": "..."
}
```

## API key generation UX and backend

| Step | UI | Backend |
|---|---|---|
| User clicks Generate token | Modal asks name, env, mode, TTL, max uses | RBAC checks `bootstrap_token:create` |
| Token is created | Secret shown once with copy command | Store token hash, scope, expiry, audit |
| User copies command | Show OS tabs and dry-run option | No extra backend call required |
| Agent registers | UI changes to Pending/Online | Token validated, identity issued, audit logged |
| Token expires/revoked | UI shows unusable | Register endpoint rejects token |

## Agent observation ingestion

- Agents poll jobs outbound, **ack** the assigned job, then upload `{ agent_job_id, test_run_id, target_id, nonce_hash, metadata? }`.
- Ingestion matches the job to agent identity, tenant, run, nonce, target, and check; only **acked** jobs accept the first observation (job moves to `observed` with `observed_at`).
- Rejections audit `observation.rejected` and do not create timeline events or verdict inputs.
- Body and `metadata` must not contain raw packet/log/header/body fields; values pass through `redactObject` before storage.

## Probe worker requirements

- Probe workers are AstraNull-owned and authenticated (HMAC request headers + per-job `job_signature` over canonical job fields).
- Reference worker CLI: `workers/probe-worker.mjs` — polls jobs, verifies signatures, runs metadata-only probes (no response bodies or raw packets), posts `safety_attestation`. Does not accept arbitrary targets on the command line.
- Control plane routes: `GET /internal/probe/jobs`, `POST /internal/probe/jobs/:id/result` when `ASTRANULL_PROBE_MODE=signed-worker`.
- Probe jobs are signed and scoped; `job.constraints` includes `max_requests`, `timeout_ms`, and existing duration/event/concurrency caps.
- Probe workers cannot choose arbitrary targets outside assigned job.
- Probe workers enforce per-check caps locally; control plane **rejects** results without `safety_attestation` (or `execution_summary`) or when `requests_sent` / `duration_ms` exceed signed caps (`missing_safety_attestation`, `invalid_safety_attestation`, `safety_attestation_exceeded`).
- Accepted probe events and evidence store a sanitized attestation summary (metadata-only optional fields such as `worker_version`, `region`, `completed_at`).
- Probe workers upload result metadata, not packet payloads by default.
- Probe fleet must support region selection, retries, jitter, and safe abort.

## High-scale execution adapter requirements

High-scale adapters are SOC-only. They must not expose raw traffic generation to customer APIs.

Required adapter inputs:

- SOC request ID,
- approved target scope,
- approved vector family,
- approved window,
- stop criteria,
- provider/partner approval artifact,
- SOC operator identity,
- dry-run/preflight confirmation.

Required adapter outputs:

- start timestamp,
- live status,
- metrics references,
- stop timestamp/reason,
- execution transcript,
- partner/provider evidence attachment.

## Completion criteria

This blueprint is complete when backend, agent, and probe teams can implement the full safe test lifecycle without granting cloud access, opening inbound management ports, or enabling customer-controlled high-scale traffic.
