# Agent Registration Flow

## Why no inbound firewall opening is needed

The agent does not wait for AstraNull to connect inbound. Instead:

1. Customer installs agent with a bootstrap token.
2. Agent initiates outbound HTTPS to AstraNull.
3. Agent registers and receives its own identity.
4. Agent keeps an outbound control channel open or polls periodically.
5. AstraNull sends jobs over that already-established outbound channel.
6. Agent observes local/mirrored/log/canary traffic and reports observations outbound.

The agent can detect probes without inbound management access because detection happens locally at the observation point. The only inbound traffic the agent may see is the customer-approved test traffic hitting the protected service/canary path, not management traffic from AstraNull.

## Registration sequence

```text
UI creates bootstrap token
  -> Customer runs install command
  -> Agent sends RegisterAgent(token, host_metadata, capabilities)
  -> Backend validates token
  -> Backend creates agent record
  -> Backend issues per-agent identity/certificate/JWT material
  -> Agent stores identity securely
  -> Agent starts heartbeat
  -> Agent waits for jobs over outbound channel
```

## Bootstrap token fields

| Field | Description |
|---|---|
| token_id | Internal ID, not the token secret. |
| tenant_id | Owning customer. |
| environment_id | Target environment. |
| target_group_id | Optional pre-binding. |
| expires_at | Short expiry. |
| max_registrations | Prevents reuse. |
| allowed_cidrs | Optional egress IP restrictions. |
| allowed_modes | Packet/log/canary/mirror. |
| created_by | User ID. |
| created_reason | Audit context. |
| revoked_at | Revocation status. |

## Agent registration request

Example shape, not final API contract:

```json
{
  "bootstrap_token": "displayed-once-token",
  "agent_name": "prod-origin-01",
  "hostname": "checkout-origin-01",
  "environment": "prod",
  "capabilities": ["packet_metadata", "canary_listener", "log_tail"],
  "platform": {
    "os": "linux",
    "distro": "ubuntu",
    "arch": "amd64",
    "kernel": "6.x"
  },
  "network": {
    "private_ips": ["10.10.4.12"],
    "public_egress_ip_seen_by_agent": "optional"
  }
}
```

## Agent identity after registration

The bootstrap token must not be used for ongoing runtime access. After registration, the backend issues:

- agent ID,
- short-lived access credential,
- refresh credential or mTLS certificate,
- tenant/environment binding,
- allowed capabilities,
- configuration version.

## Heartbeat payload

| Field | Description |
|---|---|
| agent_id | Unique agent ID. |
| version | Agent version. |
| status | online/degraded/offline/pending. |
| capabilities | Available observation modes. |
| placement | Host/canary/DaemonSet/sidecar/mirror. |
| health | CPU/memory/disk/queue/permissions. |
| clock_skew_ms | Time difference from platform. |
| last_observation_at | Last seen canary/packet/log event. |

## Failure cases

| Failure | Handling |
|---|---|
| Token expired | Reject, show regenerate-token guidance. |
| Token max registrations exceeded | Reject and audit. |
| Token revoked | Reject and audit. |
| Wrong tenant | Reject; never leak tenant details. |
| Agent duplicate name | Allow with suffix or ask user to rename. |
| Identity storage failed | Agent exits with actionable error. |

## Completion criteria

Agent registration is complete when bootstrap tokens are single-purpose, agent identities are unique/rotatable, heartbeats appear in UI, and all registration actions are audited.
