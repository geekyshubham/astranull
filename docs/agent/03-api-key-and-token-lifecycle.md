# API Key and Token Lifecycle

## Credential types

| Credential | Used by | Purpose | Lifetime |
|---|---|---|---|
| Bootstrap token | Installer/agent first run | Register agent once. | Short-lived. |
| Agent identity | Agent runtime | Heartbeat, job channel, observations. | Rotated. |
| User API token | Customer automation | Manage target groups/runs. | Configurable. |
| SOC service credential | Internal services | High-scale adapters. | Strictly controlled. |
| Webhook secret | Outbound notifications | Sign webhook payloads. | Rotatable. |

## Bootstrap token rules

- Display raw token once.
- Store only salted hash.
- Short expiry by default.
- Optional source CIDR restriction.
- Optional max registrations.
- Optional target group pre-binding.
- Full audit trail.
- Revocable at any time.

## Token generation UI flow

1. Settings → API Keys → Create Bootstrap Token.
2. Select environment.
3. Optional target group binding.
4. Select observation modes.
5. Set expiry and max registrations.
6. Optionally restrict source CIDRs.
7. Create token.
8. UI shows install commands.
9. Token secret is never shown again.

## Agent identity rotation

Rotation triggers:

- scheduled rotation,
- suspected compromise,
- agent moved to new environment,
- user revokes agent,
- identity expires,
- platform key rotation.

## Revocation behavior

| Revoked item | System behavior |
|---|---|
| Bootstrap token | New registrations fail. Existing agents unaffected. |
| Agent identity | Agent job channel and uploads rejected. UI marks revoked. |
| User API token | API requests fail. Audit records action. |
| Webhook secret | New signatures use new secret; old secret optional grace period. |

## Completion criteria

Token lifecycle is complete when bootstrap tokens cannot be reused indefinitely, credentials are least-privilege, rotation works, and all actions are audited.
