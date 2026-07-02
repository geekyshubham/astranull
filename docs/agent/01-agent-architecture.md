# Agent Architecture

## Agent purpose

The AstraNull Agent is installed by the customer inside the environment. Its purpose is to observe whether AstraNull validation probes reached a host, canary, log stream, or mirrored traffic point.

It is not a full EDR, scanner, or inventory discovery tool.

## Key design

| Design | Decision |
|---|---|
| Network access | Outbound-only to AstraNull control plane. |
| Runtime identity | Per-agent identity issued after bootstrap registration. |
| Observation | Packet metadata, canary listener, log tail, packet mirror collector. |
| Payload privacy | Store/report metadata and nonce match by default, not full packet payload. |
| Deployment | Linux host agent, Docker, Kubernetes Helm, virtual appliance later. |
| Permissions | Least privilege by mode; stronger permissions only when packet observation is enabled. |

## Agent modules

```text
Agent binary
  +-- Bootstrap/Register module
  +-- Identity/Credential store
  +-- Control channel client
  +-- Job runner
  +-- Observation modules
      +-- Packet metadata observer
      +-- Canary listener
      +-- Log-tail observer
      +-- Packet mirror collector
  +-- Health reporter
  +-- Evidence uploader
  +-- Auto-update module
  +-- Local config manager
```

## Why outbound-only still detects probes

AstraNull does not need to connect inbound to the agent. The agent detects traffic from its local vantage point:

| Observation mode | How detection happens |
|---|---|
| Host packet metadata | Agent watches local interface for probe nonce/flow metadata. |
| Canary listener | Agent exposes a customer-approved canary service/port that may be reached through protected path. |
| Log tail | Agent reads local app/proxy logs and finds the test nonce. |
| Packet mirror collector | Cloud/on-prem network copies selected traffic to the collector. |

The management/control channel remains outbound-only. Only the validation traffic itself may enter the customer environment, exactly like real external traffic would.

## Agent states

| State | Meaning |
|---|---|
| Pending | Token created but agent not registered. |
| Registered | Agent identity issued. |
| Online | Heartbeat healthy. |
| Degraded | Online but one or more capabilities failing. |
| Offline | No heartbeat within threshold. |
| Revoked | Identity invalidated. |
| Upgrade required | Version below minimum. |

## Agent config file

Example:

```yaml
agent:
  name: prod-origin-01
  environment: prod
  control_plane_url: https://api.astranull.example
  identity_path: /var/lib/astranull/identity.json
  bootstrap_token_path: /var/lib/astranull/bootstrap-token
  log_level: info

observation:
  modes:
    - packet_metadata
    - canary_listener
  interfaces:
    - eth0
  canary:
    enabled: true
    listen_address: 0.0.0.0
    listen_port: 18080
    path_prefix: /astranull-canary
  packet_metadata:
    capture_payload: false
    nonce_match_only: true

privacy:
  upload_payloads: false
  redact_headers: true
```

## Bootstrap and identity storage

| Artifact | Location | Permissions |
|---|---|---|
| One-time bootstrap token | `/var/lib/astranull/bootstrap-token` (or `ASTRANULL_BOOTSTRAP_TOKEN_FILE`) | `0600`, deleted after successful registration |
| Agent identity + credential | `/var/lib/astranull/identity.json` | `0600` file, `0700` directory where supported |

Management traffic is outbound-only over HTTPS. The optional canary listener is customer-approved observation traffic, not a management port.

## Production gateway mTLS identity (control channel)

In production, `ASTRANULL_AGENT_IDENTITY_MODE` defaults to `gateway-mtls`. Bearer-only mode is refused. The customer gateway or reverse proxy terminates mTLS from the agent, verifies the client certificate, and forwards a **metadata-only** SHA-256 fingerprint to the control plane on one of:

- `x-client-cert-fingerprint`
- `x-astranull-client-cert-fingerprint`
- `x-forwarded-client-cert-sha256`

The forwarded fingerprint must match the agent fingerprint stored at registration on heartbeat, job poll, observation upload, and update routes. Agents still present `agc_v1.…` bearer credentials; mTLS binding is an additional strong-identity gate in production.

Before attaching release evidence to `/v1/production-release-evidence`, operators capture **metadata-only** gateway/mTLS deployment proof with `scripts/agent-mtls-gateway-evidence.mjs` / `npm run agent:mtls:evidence`. The validator checks gateway/proxy references, client certificate issuance runbook references, fingerprint forwarding and header-spoofing controls, staging registration/heartbeat proof URIs, rotation/revocation drill references, and security signoff. It rejects PEM certificate bodies, private keys, tokens, passwords, database URLs, ciphertext, raw logs, and request headers/bodies. Passing local validation does not replace live PKI operations, gateway configuration review, or fleet-wide staging execution.

## Completion criteria

Agent architecture is complete when the agent can register, receive jobs outbound, observe selected traffic locally, upload evidence, report health, and be safely updated/revoked.
