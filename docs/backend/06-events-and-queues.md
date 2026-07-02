# Events and Queues

## Event principles

- Events are append-only.
- Events include tenant ID, environment ID, and trace ID.
- Sensitive payloads must be redacted.
- Correlation must tolerate out-of-order events.
- SOC/high-scale events require stronger retention.

## Core event topics

| Topic | Producers | Consumers |
|---|---|---|
| `agent.heartbeat` | Agents | Agent service, health monitor. |
| `agent.observation` | Agents | Correlation engine, evidence store. |
| `probe.dispatched` | Probe coordinator | Timeline, audit. |
| `probe.result` | Probe workers | Correlation engine, evidence store. |
| `test_run.state` | Orchestrator | UI, notifications, reports. |
| `detection.verdict` | Verdict engine | Findings, score engine, reports. |
| `finding.changed` | Findings service | Notifications, reports. |
| `soc.approval` | SOC service | Audit, reports. |
| `highscale.metric` | SOC/adapters/agents | SOC console, evidence store. |
| `audit.security` | All services | Immutable audit store. |

## Event envelope

```json
{
  "event_id": "evt_123",
  "event_type": "agent.observation",
  "tenant_id": "tenant_123",
  "environment_id": "env_prod",
  "trace_id": "trace_123",
  "occurred_at": "2026-06-30T10:00:00Z",
  "producer": "agent-service",
  "schema_version": "1.0",
  "payload": {}
}
```

## Correlation requirements

The correlation engine must handle:

- probe result before agent observation,
- agent observation before probe result,
- missing observation,
- duplicate events,
- clock skew,
- delayed agent upload,
- multiple probes with different nonces,
- multiple agents bound to same target.

## Completion criteria

Eventing is complete when every test run can be reconstructed from events.
