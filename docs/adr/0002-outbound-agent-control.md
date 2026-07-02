# ADR-0002: Outbound-Only Agent Control

## Status

Accepted.

## Context

Enterprises do not want to open inbound management firewall ports for a validation agent.

## Decision

The AstraNull Agent will initiate outbound communication to the AstraNull control plane. Jobs are delivered over outbound WebSocket/long-poll/HTTPS polling.

## Consequences

| Positive | Negative |
|---|---|
| Easier deployment through enterprise firewalls. | Job delivery depends on agent connectivity. |
| No inbound management attack surface. | Agent must maintain reliable outbound channel. |
| Works in private networks with egress. | Offline agents cannot receive jobs. |

## Detection note

Outbound-only control does not prevent detection. The agent detects probes locally at its placement point and reports observations outbound.
