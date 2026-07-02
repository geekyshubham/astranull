# High-Scale Execution Adapter

## Purpose

The execution adapter abstracts how SOC starts/stops/monitors approved high-scale simulations without exposing raw execution controls to customers.

## Adapter types

| Adapter | Description |
|---|---|
| Partner adapter | Integrates with approved third-party DDoS testing provider. |
| Provider fire-drill adapter | Coordinates supported provider-side simulation/fire drill flow. |
| Internal simulator adapter | Internal controlled simulator for legally approved cases only. |
| Manual adapter | SOC records externally coordinated test phases and imports metrics. |

## Provider-Specific Approval Paths

SOC-010 models provider paths as metadata before execution. Each high-scale request can carry normalized provider checklist items with `provider_key`, `approval_path`, accepted high-level test paths, required evidence, approved limits, stop controls, customer action summary, and SOC review summary.

| Provider key | Path | Examples |
|---|---|---|
| `aws`, `azure`, `gcp` | `provider_fire_drill` | Cloud/provider-approved simulation or protection drill metadata. |
| `cloudflare`, `akamai`, `cdn_other` | `provider_fire_drill` or `manual_coordination` | CDN/WAF edge readiness approval metadata. |
| `isp_carrier` | `manual_coordination` | Carrier/NOC-approved network drill metadata. |
| `on_prem_lab` | `internal_lab` | Isolated customer lab authorization. |
| `partner_lab` | `partner_adapter` | Approved third-party lab or partner adapter path. |

These paths are governance constraints only. Missing approval metadata, expired windows, or incomplete stop paths block SOC approval; no provider API call or traffic generator is introduced.

## Adapter interface

`src/contracts/governedExecutionAdapter.mjs` is the canonical production-readiness contract for partner, provider fire-drill, internal lab, and manual-coordination adapters. It validates metadata-only adapter registrations before production use and rejects secrets, raw commands, payloads, headers, and traffic-generator details.

Mandatory capabilities:

- `validate_scope_hash`
- `dry_run`
- `start_with_soc_token`
- `stop_or_abort`
- `status`
- `metrics_metadata`
- `evidence_export`
- `audit_events`
- `kill_switch_stop_path`

Conceptual operations:

| Operation | Purpose |
|---|---|
| validate_scope | Ensure adapter can only target approved scope. |
| dry_run | Validate configuration without sending traffic. |
| start | Start approved scenario. SOC-only. |
| pause | Pause if adapter supports it. |
| stop | Stop immediately. SOC-only. |
| status | Return running/stopping/stopped/failed. |
| metrics | Return scenario metrics. |
| evidence_export | Export provider/adapter evidence. |

## Mandatory enforcement

- Adapter cannot run without approved high-scale request ID.
- Adapter must verify scope hash before start.
- Adapter must receive signed short-lived execution token from SOC service.
- Adapter must support stop or documented emergency stop path.
- Adapter must emit audit events.
- Adapter must never be callable from customer APIs.
- Adapter start must be preceded by accepted provider-path metadata when the request declares a provider requirement.
- Adapter registration evidence must pass `validateGovernedAdapterRegistration()` before a release can claim a production-connected adapter.

## Completion criteria

Execution adapter is complete when SOC can operate approved scenarios safely while customers can only request and observe authorized results. The local contract is necessary but not sufficient; production still requires a connected partner/internal adapter, staging start/stop/kill-switch proof, telemetry/evidence export proof, and security/SOC signoff.

Kill-switch drills use `src/contracts/killSwitchValidation.mjs` as the evidence baseline. A production drill must prove tenant activation, new safe-run blocking, active safe-run cancellation, probe-fleet lease stop, adapter stop invocation, audit timeline capture, and guarded resume with metadata-only evidence.

## Governed adapters versus attack tooling

AstraNull **governed integration adapters** are SOC-controlled coordination boundaries. They validate scope hashes, bind short-lived SOC execution tokens, invoke provider-approved stop paths, export metadata summaries, and emit audit events. They do **not** ship reusable attack scripts, amplification recipes, unmanaged traffic generators, raw command lines, packet payloads, target IP inventories, or credential material in evidence bundles.

| Category | Governed adapter | Attack tooling (forbidden in-repo) |
|---|---|---|
| Purpose | Prove readiness and coordinate approved provider/manual paths | Generate unmanaged attack traffic |
| Inputs | Authorization pack id, schedule window, scope hash, SOC approvers, provider approval reference | Target lists, payloads, shell commands, secrets |
| Execution | SOC-only start/stop with kill-switch hook and dry-run proof first | Customer-triggered or ungated high-scale send |
| Evidence | Metadata manifests via `scripts/governed-adapter-evidence.mjs` | Raw logs, packets, commands, credentials |

Operator workflow for release evidence:

```bash
node scripts/governed-adapter-evidence.mjs --input path/to/adapter-readiness.json --out output/governed-adapter-evidence.json
```

The CLI validates metadata-only adapter readiness: `adapter_id`, `adapter_type`, `authorization_pack_id`, `scheduled_window`, `soc_approvers`, `provider_approval_reference`, `kill_switch_hook`, `telemetry_metadata`, `dry_run_status` (`mode=dry_run`, `traffic_generated=false`), and `stop_close_evidence`. It rejects forbidden attack-command fields, inventories, secrets, and unapproved live-traffic execution markers, then writes a **redacted manifest** suitable for production release evidence submission. Use `--validate-only` to check input without writing output.
