# Agent Placement Guide

## The core rule

The agent must be placed where it can observe the traffic path being validated.

A random VM inside an internal network cannot see traffic to another VM unless:

- the agent is installed on that target host,
- the agent is a canary target behind the same path,
- logs from that target are made available,
- traffic is mirrored/TAPed to the agent,
- the agent is deployed as a sidecar or local observer.

## Placement matrix

| Enterprise setup | Recommended placement | What AstraNull can prove |
|---|---|---|
| Single VM origin | Host agent on origin VM | Exact traffic reached/did not reach origin. |
| Load balancer with VM backend | Agent on one/more backends or canary backend | Whether traffic reaches selected backend/canary. |
| CDN/WAF in front of origin | Agent on origin or canary behind origin path | Direct-origin bypass and protected path. |
| GCP Compute Engine | Host agent or canary VM; packet mirroring for broader view | Host/canary/mirrored traffic. |
| AWS EC2 | Host agent/canary EC2; Traffic Mirroring if configured | Host/canary/mirrored traffic. |
| Azure VM/VMSS | Host agent/canary VM; vTAP if configured | Host/canary/mirrored traffic. |
| Kubernetes | Helm canary, DaemonSet, sidecar | Cluster path or specific pod path. |
| ECS on EC2 | Host/container agent or sidecar | Host/container path. |
| Fargate/serverless containers | Sidecar if supported or app logs | L7/request-level evidence, not raw packet path. |
| Lambda/serverless functions | Extension/log integration only | Request/health evidence, not packet-level. |
| On-prem VMware | Host agent, canary VM, SPAN/TAP collector | Host/canary/mirrored traffic. |
| Bare metal | Host agent or network TAP | Host/mirrored traffic. |
| DNS infrastructure | Agent near authoritative service/log collector | DNS query and service health evidence. |

## GCP placement

| GCP service | Placement |
|---|---|
| Compute Engine | Install host agent on backend VM or canary VM in same path. |
| External HTTPS Load Balancer + Cloud Armor | Put canary backend behind same backend service/path. |
| GKE | Helm chart: canary Deployment for ingress path; DaemonSet for nodes; sidecar for critical pods. |
| Packet Mirroring | Deploy collector VM/appliance and configure mirroring to it. |
| Cloud Run | Sidecar/request-log style observation where supported; no raw packet visibility. |

## AWS placement

| AWS service | Placement |
|---|---|
| EC2 | Host agent or canary EC2. |
| ALB/NLB | Canary target in same target group/path or host agents on backends. |
| EKS | Helm chart. |
| ECS EC2 | Container/host agent or daemon task. |
| Fargate | Sidecar/container logs where possible. |
| Traffic Mirroring | Collector target receives mirrored traffic. |
| Lambda | Extension/logs only, not packet-level. |

## Azure placement

| Azure service | Placement |
|---|---|
| VM/VMSS | Host agent/canary VM. |
| Application Gateway/WAF | Canary backend pool member or backend host agent. |
| AKS | Helm chart. |
| App Service containers | Sidecar/request-log pattern where supported. |
| Virtual Network TAP | Collector appliance receives copied VM traffic. |

## Placement UX requirement

The UI must not simply say “agent online”. It must say:

- online,
- bound to target group,
- observation mode active,
- baseline observed,
- can prove this target or cannot prove this target,
- placement confidence for the current verdict.

## Agent confidence score

Every verdict, report, and test-run detail should show agent confidence so customers do not over-read weak placement evidence.

**Implemented (developer validation):** finalized verdicts store `placement_confidence` (`level`, `status`, `observation_mode`, `reason`, `agent_id`, `evidence_event_id`, `warnings`) from `computePlacementConfidence` in `src/services/placement.mjs`. This is separate from correlation verdict `confidence`. JSON report exports include the object; the Test Runs **"Why this verdict?"** panel prefers the backend `reason` and `level`.

**Remaining production blockers:** live validation across host/sidecar/canary/packet-mirror/log-tail customer installs, browser/accessibility matrix, guarded route-family Postgres migration plus staging/live DB evidence (DDL/repository parity via `0005_verdict_placement_confidence` landed), and installation-matrix signoff.

| Confidence | Placement | Meaning |
|---|---|---|
| High | Installed on the actual target host/app | Strong evidence for that target path. |
| High | Sidecar with target app | Strong L7 evidence. |
| Medium | Same backend pool or canary | Good path evidence, not exact app evidence. |
| Medium | Packet mirror collector | Broad evidence, depends on mirror scope. |
| Low | Same VPC/subnet only | Weak evidence; cannot prove exact target path. |
| Invalid | No traffic visibility path | Verdict cannot prove penetration/protection. |

## Placement diagnostics (implemented)

Readiness and reporting use `computePlacementDiagnostics(tenantId)` to classify each declared target group:

| Status | Customer-facing meaning |
|---|---|
| `proven` | A bound online agent has recently observed traffic on a validation run for this group. |
| `needs_baseline` | Agent is bound and online; run a safe check or baseline traffic so observation evidence can prove the path. |
| `missing_agent` | No agent is bound to this target group — install or bind an agent per the matrix above. |
| `misplaced_risk` | Agents are bound but offline — fix connectivity, credentials, or host health before trusting placement. |

Warnings (`no_bound_agent`, `no_online_bound_agent`, `no_recent_observation`, `unbound_agent_only`) are machine-readable hints for automation and SOC review.

Limitations:

- Placement is validated only for customer-declared target groups; unbound fleet agents do not prove a group.
- Packet mirror, log-tail, and canary modes still require customer configuration; diagnostics reflect observation events, not live network topology discovery.

## Completion criteria

Placement is complete when every supported deployment option has clear install instructions, capability limits, and placement diagnostics.
