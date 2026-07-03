# Correlation Engine

## Purpose

The correlation engine converts raw events into proof.

It answers:

> Did the traffic AstraNull sent reach the observation point where it should or should not have reached?

## Inputs

| Input | Source |
|---|---|
| Probe dispatched event | Probe coordinator. |
| Probe result event | External probe worker. |
| Agent observation event | Agent. |
| Agent no-observation event | Agent after window. |
| Expected behavior | Target group config. |
| Check definition | Check catalog. |
| Health events | Agent/backend/probe. |
| SOC approval events | SOC service for high-scale. |

## Correlation keys

| Key | Description |
|---|---|
| test_run_id | Parent run. |
| check_id/version | Check logic version. |
| target_id | Target under test. |
| nonce_hash | Unique validation marker. |
| agent_id | Expected observer. |
| time_window | Observation window with clock-skew allowance. |
| source_probe_id | Probe source. |

## Verdicts

| Verdict | Meaning |
|---|---|
| Protected | Expected block/no penetration proved. |
| Bypassable | Traffic reached protected zone when it should not. |
| Penetrated | Similar to bypassable, used for non-origin L3/L4/L7 paths. |
| Allowed as expected | Traffic reached target because that was expected. |
| Blocked as expected | Probe blocked and agent did not observe. |
| Inconclusive | Evidence insufficient. |
| Misplaced agent | Agent cannot prove this target path. |
| Control missing | Required setup/check dependency missing. |
| SOC approval required | Check cannot run without SOC approval. |

## Truth table

| External probe result | Agent observation | Expected behavior | Verdict |
|---|---|---|---|
| Blocked/timeout | Not observed | Must be blocked before origin | Protected |
| Connected/allowed | Observed | Must be blocked before origin | Bypassable |
| Blocked/timeout | Observed | Must be blocked before origin | Penetrated despite blocked response |
| Connected/allowed | Not observed | Must be blocked before origin | Inconclusive/misplaced/downstream block |
| Connected/allowed | Observed | Must reach canary | Allowed as expected |
| Blocked/timeout | Not observed | Must reach canary | Failing protected path or canary unreachable |
| Any | Agent unavailable | Any | Inconclusive |

## Confidence model

| Confidence | Criteria |
|---|---|
| High | Probe event, agent event, nonce match, time delta valid, agent placement verified. |
| Medium | Probe and partial internal evidence exist, but placement/health is imperfect. |
| Low | External result only or delayed/missing internal evidence. |

**Placement confidence (DET-014, separate field):** `finalizeVerdictIfReady` attaches `verdict.placement_confidence` from `computePlacementConfidence` (observation mode, bound/online agent state, and whether this run produced a correlated `agent_observation`). Correlation `confidence` remains unchanged for backward compatibility. UI and JSON report exports surface `placement_confidence.reason` so customers see evidence-based limits, not generic copy alone.

**Production blockers:** staging validation across host/sidecar/canary/mirror/log modes, live Postgres acceptance evidence for verdict/report export paths, and customer installation matrix proof.

## Misplaced agent logic

Mark as misplaced when:

- agent is online but cannot observe baseline known-good traffic,
- target IP is not local and no mirror/log/canary mode is configured,
- canary path cannot be reached through intended protected path,
- agent has never produced observations for bound group,
- clock skew or permissions make observations unreliable.

Run-level correlation emits `misplaced_agent` when an external probe connects but the bound online agent reports no matching observation (see truth table). That verdict is per check run, not a fleet-wide placement audit.

## Placement diagnostics (readiness)

`src/services/placement.mjs` computes tenant-scoped, metadata-only placement diagnostics per declared target group. These feed readiness scoring and summaries; they do not replace per-run correlation.

| Status | Meaning |
|---|---|
| `proven` | At least one bound online agent exists and a recent `agent_observation` event is tied to a test run for that target group. |
| `needs_baseline` | Bound online agent(s) exist but no recent `agent_observation` for that group (path not yet proven by observation). |
| `missing_agent` | No agent bound to the target group. |
| `misplaced_risk` | Bound agent(s) exist but none are online (observation path unavailable). |

| Warning code | Meaning |
|---|---|
| `no_bound_agent` | No agent registered with this target group id. |
| `no_online_bound_agent` | Bound agents are offline or not heartbeating. |
| `no_recent_observation` | No recent agent observation event for runs on this group. |
| `unbound_agent_only` | Online agents exist for the tenant but none are bound to this group (they cannot prove this group). |

Limitations:

- Diagnostics use declared target groups and store events only; no cloud inventory or automatic placement discovery.
- Unbound online agents are listed as tenant-level fallback metadata and never mark a group `proven`.
- `agent_no_observation` events count toward recent observation counts but do not alone satisfy `proven` (a positive `agent_observation` is required).

## Completion criteria

Correlation is complete when verdicts are explainable, reproducible, confidence-scored, and linked to evidence.
