# Agent Detection Modes

## Detection mode overview

AstraNull needs multiple detection modes because enterprises deploy infrastructure differently.

| Mode | Best for | What it proves | Limitation |
|---|---|---|---|
| Packet metadata observer | Host VM/bare metal | Whether probe reached local interface/host. | Needs install on relevant host and privileges. |
| Canary listener | Canary VM/container/service | Whether probe reached a deliberately exposed canary path. | Proves canary path, not every app host. |
| Log-tail observer | NGINX/Envoy/app logs | Whether app/proxy handled request. | Needs log config and nonce visibility. |
| Packet mirror collector | AWS/GCP/Azure/on-prem TAP | Whether mirrored traffic reached selected sources. | Customer must configure mirroring/TAP. |
| Kubernetes DaemonSet | Node-level cluster coverage | Node-level observation and canary support. | May not see pod-level traffic without host networking/mirror/log mode. |
| Kubernetes sidecar | Specific pod/service | Same pod/request context. | More intrusive; app deployment change. |

## Evidence-based observation upload

The Linux agent (`agents/linux/astranull-agent.mjs`) is outbound-only. It polls `GET /v1/agents/{id}/jobs`, **acks** each job, and uploads `POST /v1/agents/{id}/observations` **only when a matching local signal exists** for that job's `nonce_hash`.

Signal precedence (strongest first):

1. Customer-approved canary listener (`--canary-listen`)
2. Log-tail observer (`--log-file`)
3. Packet mirror collector (`--mirror-metadata-file`)
4. Packet metadata observer (`--packet-metadata-file`)

If no signal matches, the agent logs a concise message and does **not** upload an observation.

## Packet metadata observer (implemented: JSONL file input)

The agent does not capture packets itself. Customers run host tooling that emits **JSON Lines** metadata to a file watched by the agent:

```bash
astranull-agent --packet-metadata-file /var/lib/astranull/packet-metadata.jsonl ...
```

Each line is a JSON object. Accepted safe fields:

- `nonce` (hashed locally to `nonce_hash`; raw nonce is never uploaded)
- `nonce_hash`
- `observed_at`, `interface`, `local_ip`, `local_port`, `remote_ip`, `remote_port`
- `protocol`, `tcp_flags`, `packet_count`, `flow_count`, `direction`

Records containing disallowed keys (`raw_packet`, `payload`, `body`, `headers`, `authorization`, `cookie`, `raw_log`, `log_line`, including nested values) are ignored.

## Canary listener

The canary listener is a small safe service the customer intentionally exposes behind the protected path.

Example protected path:

```text
External Probe -> CDN/WAF/LB -> Canary Listener on Agent
```

It records:

- HTTP path,
- test ID/nonce (stored as `nonce_hash` only),
- method and path metadata,
- timestamp.

## Log-tail observer

Reads configured logs via `--log-file`, for example:

- NGINX access logs,
- Envoy access logs,
- HAProxy logs,
- application logs that include canary nonce or `sha256:<nonce_hash>` fingerprint.

The agent stores a **line hash** keyed by `nonce_hash` and never uploads raw log lines.

## Packet mirror collector (implemented: JSONL file input)

Mirrored traffic is processed by customer-side collectors (GCP Packet Mirroring, AWS Traffic Mirroring, Azure vNET TAP, SPAN/TAP appliances). Those tools write **metadata-only** JSON Lines to a file watched by the agent:

```bash
astranull-agent --mirror-metadata-file /var/lib/astranull/mirror-metadata.jsonl ...
```

The same safe field contract and disallowed-field rules apply as packet metadata observer. Mode uploaded to the control plane is `packet_mirror_collector`.

## Observation upload contract

Agents post observations only after **acking** the assigned job from `GET /v1/agents/{id}/jobs`. Each upload must include `agent_job_id` matching that job plus `test_run_id`, `target_id`, and `nonce_hash`. The control plane rejects raw packet/log/header/body payload fields in the body or `metadata` (for example `raw_packet`, `payload`, `log_line`) and redacts secret-like keys before persistence.

Uploaded agent metadata is sanitized to mode, source, timestamps, counters, ports, and fingerprints—never raw packet, header, cookie, authorization, or log content.

## Misplaced agent detection

A random VM inside a VPC/VNet cannot see traffic to another VM by default. AstraNull must detect and warn about this.

Signals of misplaced agent:

- agent online but no baseline observations,
- agent not bound to target path,
- target IP/port differs from local interfaces,
- canary listener not reachable through protected path,
- log-tail source never sees test nonce,
- mirror collector has no mirrored packets.

## Production blockers (remaining)

| Area | Status |
|---|---|
| Signed agent packages / update channel | Generic tarball manifest signing, control-plane update APIs, and native deb/rpm builders exist in-repo; **release gates:** GPG-signed native packages, hosted artifact custody, tenant trust-key enforcement on hosts, and unattended update-daemon + fleet rollout evidence. |
| Distro-specific packaging validation (RPM/DEB) | Native package builder and unit tests ship; real distro matrix install/uninstall drills (Ubuntu/Debian, RHEL family, Amazon Linux, SUSE) not evidenced in staging. |
| Customer mirror/TAP setup | Requires customer network engineering; agent only ingests metadata files they provide. |
| Live pcap/libpcap capture in agent | Intentionally omitted; metadata file inputs only. |

## Completion criteria

Detection modes are complete when AstraNull can clearly state what each agent can prove and when it cannot prove a target's readiness. The Linux agent now implements evidence-gated upload for canary, log-tail, packet metadata file, and mirror metadata file modes; production packaging and customer mirror automation remain open.