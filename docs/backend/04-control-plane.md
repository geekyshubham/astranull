# Control Plane

## Purpose

The control plane coordinates agents, probes, checks, SOC approvals, and evidence.

## Agent control channel

The agent must initiate the connection. Supported options:

| Option | Pros | Cons | Recommended use |
|---|---|---|---|
| HTTPS polling | Simple, firewall-friendly | More latency, more requests | Fallback when streaming blocked. |
| Long polling | Simple and responsive | Connection management | Preferred when WebSocket blocked. |
| WebSocket over TLS | Near-real-time jobs/acks | Some enterprise proxies block it | Preferred for production. |
| mTLS gRPC stream | Strong identity, efficient | More complex | Later enterprise mode. |

## Job delivery model

1. Backend creates job.
2. Agent receives job through outbound channel.
3. Agent acknowledges job.
4. Agent prepares observation mode.
5. Probe job executes.
6. Agent uploads observation/no-observation after window.
7. Backend correlates and finalizes.

## Agent job states

| State | Meaning |
|---|---|
| queued | Job waiting for agent. |
| delivered | Agent received job. |
| acknowledged | Agent accepted job. |
| observing | Agent is watching for nonce. |
| observed | Agent saw matching signal. |
| not_observed | Observation window closed without signal. |
| failed | Agent could not observe due to error. |
| expired | Job timed out. |

## Probe worker control

Probe workers must:

- accept only signed jobs,
- validate rate/concurrency caps,
- use approved source regions,
- emit event before and after sending,
- never run SOC-gated jobs unless issued by SOC-approved workflow,
- support emergency stop signal.

## Completion criteria

Control plane is complete when agents and probes are coordinated without inbound customer access and every job has an auditable state transition.
