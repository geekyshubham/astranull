# Agents Page

## Purpose

The Agents page makes installation, placement, health, and troubleshooting easy.

## Install tab

Show install options as copy-paste cards.

### Linux host

```bash
curl -fsSL https://download.astranull.example/install.sh | sudo bash -s -- \
  --token <BOOTSTRAP_TOKEN> \
  --env prod \
  --target-group "Retail Checkout"
```

### Docker canary

```bash
docker run -d --name astranull-agent \
  --restart unless-stopped \
  --network host \
  -e ASTRANULL_BOOTSTRAP_TOKEN=<BOOTSTRAP_TOKEN> \
  astranull/agent:stable
```

### Kubernetes Helm

```bash
helm repo add astranull https://charts.astranull.example
helm upgrade --install astranull-agent astranull/agent \
  --namespace astranull --create-namespace \
  --set bootstrapToken=<BOOTSTRAP_TOKEN> \
  --set mode=daemonset
```

## Install token options

| Option | Description |
|---|---|
| Environment | Prod/staging/lab. |
| Target group binding | Optional pre-bind. |
| Expiry | 15 min, 1 hour, 24 hours, custom. |
| Max agents | Prevent token reuse beyond expected count. |
| Allowed CIDRs | Optional egress-source restriction. |
| Observation modes | Packet metadata, canary listener, log tail, mirror collector. |
| Tags | Region, team, app, deployment method. |

## Fleet tab

Columns:

| Column | Description |
|---|---|
| Agent name | Human-friendly name. |
| Status | Online, degraded, offline, pending, revoked. |
| Environment | Prod/staging/lab. |
| Placement | Host, canary, DaemonSet, sidecar, mirror collector. |
| Target groups | Bound groups. |
| Version | Current agent version. |
| Last heartbeat | Timestamp and latency. |
| Capabilities | Observation modes available. |
| Actions | View, rebind, upgrade, revoke. |

## Placement tab

Show a traffic-path assistant:

```text
Where is this agent?
[ ] On the origin host
[ ] Canary behind same load balancer/WAF path
[ ] Kubernetes DaemonSet
[ ] Kubernetes sidecar
[ ] Packet mirror/TAP collector
[ ] DMZ/on-prem collector
```

For each placement, show what AstraNull can and cannot prove.

## Health tab

Metrics:

- heartbeat status,
- control-channel latency,
- clock skew,
- CPU/memory/disk,
- packet observation permission status,
- canary listener status,
- log-tail file status,
- mirror collector status,
- upload queue depth,
- last successful observation.

## Troubleshooting cards

| Problem | Likely cause | Fix |
|---|---|---|
| Agent online but no observations | Wrong placement or no baseline traffic | Run placement test or move/bind agent. |
| Packet mode unavailable | Missing permissions/capabilities | Reinstall with required mode or use canary/log mode. |
| Token rejected | Expired/revoked/wrong tenant | Generate a new bootstrap token. |
| Clock skew | Host time not synced | Enable NTP/chrony. |
| High latency | Proxy/firewall/egress issue | Check outbound HTTPS connectivity. |

## Completion criteria

Agents page is complete when a customer can install, verify, monitor, troubleshoot, upgrade, and revoke agents without support intervention.
