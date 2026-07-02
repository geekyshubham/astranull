# High-Scale Authorization Pack Template

This template pack is an operational starting point, not legal advice. Customer counsel, provider policy owners, and AstraNull SOC/legal reviewers must approve production use before any governed high-scale validation.

Use this pack to create metadata-backed artifacts for `POST /v1/high-scale-requests/:id/artifacts`. Production use still requires durable document custody, retention/legal-hold review, export signoff, and staging walkthrough evidence.

## Required Artifact Map

| Artifact type | Purpose | Required metadata |
|---|---|---|
| `customer_authorization_letter` | Customer authorizes AstraNull SOC to coordinate bounded validation. | `approval_reference`, `approver`, `valid_window`, `approved_targets`, `approved_scenario_families` |
| `target_ownership_confirmation` | Customer confirms declared targets are owned, controlled, or explicitly authorized. | `approval_reference`, `approver`, `approved_targets` |
| `emergency_contacts` | Customer, SOC, and provider stop/escalation contacts. | `emergency_contacts` |
| `stop_criteria` | Pause/stop thresholds and authority. | `abort_criteria` |
| `test_plan` | Scenario families, observations, monitoring, and completion criteria. | `approved_scenario_families`, `valid_window`, `approved_targets` |
| `business_approval` | Business owner accepts risk, timing, and communications. | `approval_reference`, `approver` |
| `legal_approval` | Legal/security owner approves scope under customer and provider rules. | `approval_reference`, `approver` |
| `scope_and_rate_plan` | Locks scope, rate labels, duration caps, and change-control boundaries. | `max_rate`, `max_duration_minutes`, `approved_scenario_families`, `valid_window`, `approved_targets` |
| `abort_criteria` | Immediate abort conditions and recovery sequence. | `abort_criteria` |
| `provider_approval` | Provider, CDN, carrier, partner, or lab approval metadata. | `provider_name`, `approval_reference`, `valid_window`, `approved_targets`, `approved_scenario_families`, `approved_limits`, `contact_path`, `emergency_stop_path`, `provider_specific_evidence` |

## Customer Authorization Letter

| Field | Value |
|---|---|
| Customer legal entity | `<customer legal name>` |
| AstraNull tenant/org ID | `<tenant id>` |
| Authorization reference | `<ticket/case/document id>` |
| Authorized approver | `<name, title, contact>` |
| Valid window | `<start/end/timezone>` |
| Declared target groups | `<target group ids/names>` |
| Approved scenario families | `<families>` |

Required text:

- Customer authorizes AstraNull SOC to coordinate only the declared validation scope.
- Customer can request immediate stop through the emergency path.
- AstraNull SOC can stop the validation at any time.
- Provider approvals are required where applicable.

## Target Ownership Confirmation

| Field | Value |
|---|---|
| Ownership basis | `<owned/controlled/contractually authorized>` |
| Declared targets | `<fqdn/ip/url labels from target group>` |
| Exclusions | `<targets/subsystems out of scope>` |
| Approver | `<name, role, reference>` |

Attach a reference to the internal inventory, CMDB, contract, change request, or customer statement proving scope authority.

## Emergency Contacts

| Role | Name | Contact path | Availability |
|---|---|---|---|
| Customer incident commander | `<name>` | `<phone/email/bridge>` | `<window>` |
| Customer technical owner | `<name>` | `<phone/email/bridge>` | `<window>` |
| AstraNull SOC lead | `<name>` | `<bridge/pager>` | `<window>` |
| Provider/carrier contact | `<name>` | `<case/bridge>` | `<window>` |

## Stop Criteria

| Criterion | Threshold | Stop authority | Evidence source |
|---|---|---|---|
| Customer request | Any explicit stop request | Customer or SOC | SOC note/call log |
| Provider request | Any provider stop instruction | Provider or SOC | Provider case/bridge |
| Availability degradation | `<threshold>` | SOC | External probe/service health |
| Error budget breach | `<threshold>` | SOC/customer | Customer telemetry |
| Agent health blind spot | `<threshold>` | SOC | Agent heartbeat/observation |

## Test Plan

| Field | Value |
|---|---|
| Objective | `<readiness question>` |
| Scenario families | `<L3/L4/L7/DNS/protocol/operations>` |
| Expected controls | `<CDN/WAF/scrubber/rate limits/runbooks>` |
| Evidence required | `<probe, agent, provider, SOC notes, health signals>` |
| Completion criteria | `<verdict/report criteria>` |

The plan must not include reusable traffic-generation commands, amplification instructions, spoofing steps, or unmanaged attack recipes.

## Business Approval

| Field | Value |
|---|---|
| Business owner | `<name/title>` |
| Business reason | `<reason>` |
| Customer communications | `<planned comms or N/A>` |
| Maintenance/change link | `<change id>` |
| Approval reference | `<ticket/document id>` |

## Legal Approval

| Field | Value |
|---|---|
| Legal/security reviewer | `<name/title>` |
| Policy references | `<customer/provider/legal references>` |
| Approved scope | `<target groups/scenario families/window>` |
| Retention instructions | `<retention/legal hold/export requirements>` |
| Approval reference | `<ticket/document id>` |

This section must be reviewed by authorized customer/legal personnel before production use.

## Scope and Rate Plan

| Field | Value |
|---|---|
| Approved targets | `<target group/target ids>` |
| Approved scenario families | `<families>` |
| Max rate label | `<metadata label, not generator command>` |
| Max duration minutes | `<number>` |
| Valid window | `<start/end/timezone>` |
| Change-control reference | `<ticket>` |

## Abort Criteria

| Trigger | Required action | Owner | Evidence |
|---|---|---|---|
| Customer stop | Stop immediately | SOC | SOC note |
| Provider stop | Stop immediately | SOC/provider | Provider case |
| Health threshold breach | Stop or pause | SOC | Health metric |
| Scope mismatch | Stop and investigate | SOC | Audit/event evidence |

## Provider Approval

| Field | Value |
|---|---|
| Provider name | `<AWS/Azure/GCP/CDN/carrier/on-prem/partner>` |
| Provider approval path | `<provider drill/partner adapter/manual coordination/lab>` |
| Approval reference | `<case/ticket/email>` |
| Valid window | `<start/end/timezone>` |
| Approved targets | `<scope>` |
| Approved scenario families | `<families>` |
| Approved limits | `<provider-approved labels>` |
| Contact path | `<bridge/case/escalation>` |
| Emergency stop path | `<provider stop instruction/bridge>` |
| Provider-specific evidence | `<metadata fields required by provider path>` |

Do not store provider credentials in this artifact. Store metadata references only until durable document custody is integrated.
