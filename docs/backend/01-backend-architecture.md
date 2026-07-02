# Backend Architecture

## Architecture goals

| Goal | Requirement |
|---|---|
| No-access-first | Backend must work without customer cloud credentials. |
| Multi-tenant | Strong tenant isolation across API, DB, queues, object storage, logs. |
| Evidence-grade | Every verdict has durable event/evidence records. |
| Safe execution | Backend enforces risk classes, rate caps, authorization gates. |
| Scalable | Probe, agent, ingestion, and correlation services scale independently. |
| Auditable | Security-sensitive actions are immutable and exportable. |

## High-level services

```text
Frontend Portal / SOC Console
        |
API Gateway + Auth/RBAC
        |
+----------------------+----------------------+----------------------+
| Tenant/Target Service | Agent Service        | Check Catalog        |
| Test Planner          | Probe Coordinator    | SOC Approval Service |
| Event Ingestion       | Correlation Engine   | Verdict/Finding      |
| Score Engine          | Report Generator     | Notification Service |
+----------------------+----------------------+----------------------+
        |
Database + Event Bus + Evidence Object Store + Audit Log
```

## Service responsibilities

| Service | Responsibilities |
|---|---|
| API Gateway | REST/GraphQL entry, auth enforcement, rate limiting, request logging. |
| Auth/RBAC | Users, roles, sessions, SSO, permissions. |
| Tenant Service | Organizations, environments, settings, retention. |
| Target Service | Target groups, targets, expected behavior, schedules. |
| Agent Service | Bootstrap tokens, registration, identities, heartbeats, capabilities. |
| Agent Control Channel | Outbound WebSocket/long-poll job delivery to agents. |
| Check Catalog | Versioned checks, risk class, requirements, safety constraints. |
| Test Planner | Creates test runs and bounded probe/agent jobs. |
| Probe Coordinator | Dispatches external probes and collects results. |
| Event Ingestion | Accepts probe events, agent observations, health metrics, SOC events. |
| Correlation Engine | Matches probe and agent data by test ID/nonce/window. |
| Verdict Engine | Produces protected/bypassable/inconclusive/misplaced verdicts. |
| Findings Service | Creates, deduplicates, assigns, closes findings. |
| Score Engine | Computes readiness scores and score trends. |
| SOC Approval Service | High-scale workflow state machine and authorization pack. |
| Report Generator | Generates evidence reports. |
| Notification Service | Email/Slack/Teams/webhooks/ticketing. |
| Audit Log Service | Immutable audit records for sensitive actions. |

## Storage components

| Storage | Data |
|---|---|
| Relational DB | Tenants, users, target groups, agents, checks, runs, findings, approvals. |
| Event stream | Probe events, agent observations, job state, correlation events. |
| Object store | Reports, authorization documents, evidence bundles. |
| Time-series store | Agent health, latency, availability, high-scale metrics. |
| Audit log store | Immutable security and SOC actions. |
| Secret store | Token hashes, signing keys, agent credentials. |

## Core backend invariants

- A test run cannot exist without a tenant and target group.
- A safe test cannot exceed check-level rate/concurrency caps.
- A high-scale test cannot start unless SOC state is `Go/No-Go Approved`.
- An agent observation must be tied to an agent identity and tenant.
- A verdict must be tied to evidence or explicitly marked inconclusive.
- Bootstrap token values are shown once and stored only as hashes.
- No high-scale execution adapter can be called directly by customer APIs.

## Suggested deployment architecture

| Component | Deployment suggestion |
|---|---|
| Frontend | CDN + web app hosting. |
| API Gateway | Stateless service behind load balancer. |
| Workers | Queue consumers for probes, correlation, reports. |
| Agent channel | Separate horizontally scalable service. |
| Database | Managed Postgres-compatible DB. |
| Event bus | Kafka/Pulsar/SQS/PubSub equivalent. |
| Object store | S3/GCS/Azure Blob equivalent. |
| Secrets | Managed secret/KMS service. |
| Observability | Metrics, logs, traces, alerting. |

## Completion criteria

Backend architecture is complete when every product flow can be represented as API calls, events, database records, audit logs, and evidence artifacts.
