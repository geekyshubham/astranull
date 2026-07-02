# Agent Lifecycle

## Lifecycle states

```text
Token Created
  -> Installed
  -> Registered
  -> Online
  -> Observing
  -> Upgrading
  -> Degraded/Offline
  -> Revoked/Uninstalled
```

## Upgrade strategy

| Feature | Requirement |
|---|---|
| Signed packages | Agent verifies authenticity. |
| Staged rollout | Roll out by tenant/environment/percentage. |
| Rollback | Revert to previous stable version. |
| Version pinning | Enterprise customers can pin. |
| Minimum supported version | UI warns or blocks old agents. |
| Audit | Upgrades recorded. |

## Health checks

Agent reports:

- version,
- uptime,
- CPU/memory/disk,
- observation modules active/inactive,
- permissions status,
- network connectivity,
- queue depth,
- last successful job,
- last observation,
- clock skew.

## Revocation

Revoking an agent:

1. uses `POST /v1/agents/:id/revoke` (`agent:revoke`, owner/admin),
2. marks the tenant-scoped agent `revoked`,
3. invalidates the runtime credential by rejecting future bearer-authenticated calls,
4. rejects heartbeats, job polling, observations, and update poll/status calls,
5. retains evidence history,
6. records audit event.

Revoked credential attempts return `401` and audit `agent.auth_denied` with reason `revoked` without storing bearer material. The route and credential rejection path are wired in developer JSON and Postgres service modes. Remaining production gates are operational: staging revoke drills across generic, deb/rpm, container, and Kubernetes installs; customer uninstall runbooks; and evidence that revoked agents stop receiving jobs before host removal.

## Uninstall (host agent)

On Linux generic installs, `agents/linux/uninstall.sh` removes the outbound agent service artifacts in a bounded way:

| Step | Default uninstall | With `--purge-data` |
|---|---|---|
| Stop/disable systemd | Yes on production `/` when `systemctl` exists | Same |
| Remove `astranull-agent.service` | Yes | Yes |
| Remove `/usr/local/bin/astranull-agent.mjs` | Yes | Yes |
| Remove `/etc/astranull/agent.env` | Yes | Yes |
| Remove `/var/lib/astranull` | No (preserved) | Yes |

The script never echoes bootstrap tokens or reads secrets for logging. Re-running uninstall is idempotent. Revoke the agent in the UI before or after uninstall so the platform stops accepting observations from that identity.

Native `.deb`/`.rpm` packages ship `prerm` hooks that stop `astranull-agent.service` before `apt remove` / `yum remove`. Operators on generic tarball installs should still use `uninstall.sh`. **Remaining release gates:** signed apt/yum repository publishing, GPG/package signing, and distro matrix install/uninstall validation — not absence of native package uninstall scripts.

## Current implementation status (developer validation)

| Capability | Status |
|---|---|
| Release creation | `POST /v1/agent-updates` (`agent_update:write`) accepts version, channel (`stable`/`beta`/`canary`), signed manifest + detached Ed25519 signature, required `distribution: { manifest_url, signature_url, artifact_url }` (absolute HTTPS; URL credentials rejected; decoded `artifact_url` basename must match `manifest.artifact.name`; query strings allowed), rollout (`percentage`, optional `environment_ids` / `target_group_ids` / `agent_ids`), optional embedded rollback with its own `distribution`. Control plane verifies package `astranull-agent`, version match, artifact SHA-256/size, safe `.tar.gz` basename, `signing.signed === true`, and signature over canonical manifest payload. Audits `agent_update.release_created` (audit metadata excludes distribution URLs). |
| Release listing | `GET /v1/agent-updates` (`agent_update:read`) returns tenant-scoped releases. |
| Staged rollout selection | `isAgentInRollout` applies filters then deterministic percentage bucket from `tenant_id|agent_id|version` SHA-256. |
| Rollback request | `POST /v1/agent-updates/:id/rollback` (`agent_update:rollback`) sets `rollback_requested` when rollback metadata exists; audits `agent_update.rollback_requested`. |
| Agent poll | `GET /v1/agents/:id/update` (agent bearer) returns `{ update: null }` or upgrade/rollback metadata (`release_id`, `action`, `version`, `manifest`, `signature`, `download: { manifest_url, signature_url, artifact_url }`). Rollback poll targets agents that reported `applied` on the release. |
| Status acknowledgment | `POST /v1/agents/:id/update-status` records `downloaded`, `verified`, `applied`, `failed`, or `rolled_back`; optional `installed_version`, `action`, `error_code`. `applied` / `rolled_back` with `installed_version` updates agent `version`. Audits `agent_update.status_recorded`. |
| Agent verifier / preflight | `agents/linux/astranull-agent.mjs` exports manifest helpers; CLI: `--verify-update-manifest <manifest.json> --signature <manifest.json.sig> --trusted-public-key <base64-der-spki>` with optional `--artifact <tarball>` and `--expected-version <version>`. Rejects unsigned/tampered manifests and key mismatch. |
| Host apply primitive | CLI: `--apply-update-manifest <manifest.json> --signature <sig> --trusted-public-key <base64-der-spki> --artifact <tarball> --install-root <absolute path>` with optional `--expected-version <version>`. Verifies signed manifest, artifact SHA-256/size, safe paths, tar listing, file checksums/sizes; rejects symlinks and non-files. Installs to `<installRoot>/releases/<version>/` and writes `<installRoot>/current.json`. |
| Hosted download + apply | CLI: `--download-and-apply-update --manifest-url <url> --signature-url <url> --artifact-url <url> --trusted-public-key <base64-der-spki> --install-root <absolute path>` (optional `--expected-version`). Downloads manifest, signature, and artifact, then runs the same verification and apply path as `--apply-update-manifest`. Download policy defaults to **HTTPS only**; local HTTP is allowed only with `--allow-insecure-localhost-downloads` (test-only). Rejects URL credentials; enforces response size caps and bounded timeout; **does not follow HTTP redirects**. Does not restart the agent daemon or wire control-plane poll URLs — operators invoke explicitly or from their own orchestration. |
| Tenant trust keys | `POST /v1/agent-update-trust-keys` (`agent_update:write`) registers DER SPKI Ed25519 public keys (`fingerprint_sha256`, rejects duplicate active keys); `GET /v1/agent-update-trust-keys` (`agent_update:read`) lists metadata (`id`, name, fingerprint, status, timestamps); `POST /v1/agent-update-trust-keys/:id/revoke` revokes active keys. Release and rollback creation require manifest signing key matching an active tenant trust key (`untrusted_signing_key` otherwise). Audits `agent_update.trust_key_added` / `agent_update.trust_key_revoked`. Ledger: `agentUpdateTrustKeys` in developer validation, `agent_update_trust_keys` through `runtime.services.agentUpdates` in Postgres mode. |
| Agent revoke | `POST /v1/agents/:id/revoke` (`agent:revoke`) marks the agent `revoked`, audits `agent.revoked`, and causes the prior credential to fail heartbeat, jobs, observations, and update routes with `401`; revoked attempts audit `agent.auth_denied` reason `revoked` without credential material. Developer JSON and Postgres service modes are wired. |

Outside Postgres mode, update persistence uses the developer JSON ledgers (`agentUpdateReleases`, `agentUpdateStatuses`, `agentUpdateTrustKeys`). With `ASTRANULL_PERSISTENCE_MODE=postgres`, the same route family uses tenant-scoped `agent_update_releases`, `agent_update_statuses`, and `agent_update_trust_keys` tables through `agentUpdateRepository` + `runtime.services.agentUpdates`. Control-plane release `distribution` metadata and poll `download` payloads are wired in both modes; host `--apply-update-manifest` and `--download-and-apply-update` exist. **Production blockers:** hosted artifact storage custody/CDN/mirror operational runbooks and staging evidence, unattended daemon loop (poll → download → apply → **service restart**), and fleet rollout drills.

## Install/uninstall matrix release gate

Before production agent packaging promotion, operators should record **metadata-only** install/uninstall matrix evidence across `generic`, `deb`, `rpm`, `container`, and `kubernetes` paths. Each row must cover outbound lifecycle checks: `install`, `heartbeat`, `job_poll`, `upgrade_rollback`, `revoke`, `uninstall`, and `no_inbound_port` (inbound listener count `0` when passed). The agent remains **outbound-only** — matrix evidence must not require inbound management ports.

Use the repository utility:

```bash
node scripts/agent-install-matrix-evidence.mjs \
  --input evidence/agent-install-matrix.json \
  --matrix-id staging_2026_07 \
  --out output/agent-install-matrix-evidence.json
```

`--validate-only` validates input without writing output. The summary artifact reports `overall_status`, per-format pass/fail rows, and `coverage_gaps` (missing formats or failed checks). Evidence payloads must not include raw logs, secrets, or bearer/bootstrap tokens — only redacted agent IDs, counts, timestamps, and pass/fail status. CI covers the contract in `tests/unit/agent-install-matrix-evidence.test.mjs`.

| Gate | Expectation |
|---|---|
| Format coverage | All five install formats represented with passing rows. |
| Revoke/uninstall | Failed revoke or uninstall on any format fails the matrix. |
| No inbound ports | `no_inbound_port` passed rows document `inbound_listener_count: 0`. |
| Secret safety | Forbidden token/log fields rejected; output is metadata-only. |

## Trust-key ceremony / rotation / revocation release gate

Before production agent update promotion, operators should record **metadata-only** evidence for the tenant trust-key lifecycle: signing-key generation or import references (not private key material), active trust-key registration (`fingerprint_sha256`, trust-key id), staged release binding to an active signing fingerprint, rotation from a previous to a new active key, revocation of a superseded key, and rollback trust behavior (`untrusted_signing_key` rejection after revoke). Include operator and security signoff references plus custody URIs for controlled artifacts.

```bash
node scripts/agent-trust-key-ceremony-evidence.mjs \
  --input evidence/agent-trust-key-ceremony.json \
  --out output/agent-trust-key-ceremony-evidence.json
```

`--validate-only` validates input without writing output. The summary artifact reports `ceremony_summary`, `custody_uris`, and validation status. Evidence must not include DER/PEM keys, tokens, passwords, database URLs, raw logs, HTTP bodies/headers, URL credentials, or ciphertext/auth tags — only fingerprints, ids, references, timestamps, and signoff metadata. Attach accepted manifests through `/v1/production-release-evidence` kind `agent_trust_key_ceremony`. CI covers the contract in `tests/unit/agent-trust-key-ceremony-evidence.test.mjs`.

| Gate | Expectation |
|---|---|
| Signing-key ceremony | `generate` or `import` method with `signing_key_reference` and `custody_uri`. |
| Active registration | Trust-key id, name, and valid `fingerprint_sha256` registered in control plane. |
| Staged release | Release id bound to active signing fingerprint; `binding_verified: true`. |
| Rotation / revocation | Previous and new key ids/fingerprints documented; revoked key id recorded. |
| Rollback trust | Post-revoke release attempt observes `untrusted_signing_key_observed: true`. |
| Signoff / custody | Operator and security signoff references; non-empty `custody_uris`. |

## Remaining production blockers

- Hosted artifact storage custody, CDN or customer mirror operational runbooks, and staging evidence that published URLs match signed manifests (control-plane metadata alone is not sufficient).
- Agent daemon orchestration: unattended loop from poll → download → apply → **service restart** (host CLI primitives exist; staging rollout evidence does not).
- Live execution of the trust-key ceremony/rotation/revocation drill in staging (validator: `scripts/agent-trust-key-ceremony-evidence.mjs` / `npm run agent:trust-key:evidence`) and installer/update-daemon enforcement of pinned keys on generic, deb/rpm, and container paths.
- Staging validation: distro matrix, Kubernetes rollout, and rollback drill with fleet evidence.
- Enterprise IdP/MFA and audit policy for human release administrators.

## Completion criteria

Lifecycle is complete when agents are installable, observable, upgradable, revocable, and supportable at enterprise scale.
