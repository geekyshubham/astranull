# AstraNull Documentation Index

## Product

| Doc | Purpose |
|---|---|
| [Platform Overview](product/01-platform-overview.md) | What AstraNull is and what it validates. |
| [Scope and Principles](product/02-scope-and-principles.md) | No-access, no-inventory, SOC-gated rules. |
| [Personas and Roles](product/03-personas-and-roles.md) | Customer and internal roles. |
| [Target Groups](product/04-target-groups.md) | Core customer-declared scope model. |
| [Roadmap](product/05-platform-roadmap.md) | Build phases. |
| [Release Plan](product/06-release-plan.md) | Production release milestones and verification. |
| [Enterprise Production Gap Backlog](product/08-enterprise-production-gap-backlog.md) | Explicit backlog of remaining enterprise production gaps from the latest gap review. |
| [WAF Posture Management](product/09-waf-posture-management.md) | Optional WAF posture, coverage, effectiveness, drift, CVE mitigation, and remediation scope. |
| [Enhanced External Discovery](product/10-enhanced-external-discovery.md) | Optional entity mapping and approval-gated candidate discovery. |
| [Active Protection and Digital Supply Chain](product/11-active-protection-and-digital-supply-chain.md) | Optional dangling asset, DNS hijack, and dependency protection design. |

## UX

| Doc | Purpose |
|---|---|
| [UX Principles](ux/00-ux-principles.md) | Friendly product behavior and microcopy. |
| [Pages and Tabs](ux/01-pages-and-tabs.md) | Full page map and tab details. |
| [Dashboard](ux/02-dashboard.md) | Dashboard layout and data. |
| [Target Groups Page](ux/03-target-groups-page.md) | Target group UX. |
| [Agents Page](ux/04-agents-page.md) | Agent install, fleet, placement, health. |
| [Checks Library](ux/05-checks-library-page.md) | Check catalog UX. |
| [Test Runs](ux/06-test-runs-page.md) | Timeline/evidence UX. |
| [Findings](ux/07-findings-page.md) | Triage/remediation UX. |
| [Reports](ux/08-reports-page.md) | Reports and evidence packs. |
| [SOC Console](ux/09-soc-console.md) | SOC high-scale console. |
| [Settings](ux/10-settings-page.md) | API keys, users, integrations, audit. |
| [Visualizations](ux/11-visualization-methods.md) | Best representation methods. |
| [WAF Posture UX](ux/13-waf-posture-ux.md) | Optional WAF dashboard, asset, drift, validation, CVE, discovery, and integration pages. |

## Flows

| Doc | Purpose |
|---|---|
| [Customer Onboarding](flows/01-customer-onboarding.md) | End-to-end customer setup. |
| [Agent Registration](flows/02-agent-registration.md) | Bootstrap token and outbound control. |
| [Safe Check Execution](flows/03-safe-check-execution.md) | Safe validation lifecycle. |
| [High-Scale Request and Approval](flows/04-high-scale-request-and-approval.md) | Customer request and SOC gating. |
| [SOC Operations](flows/05-soc-operations.md) | SOC run operation. |
| [Reporting and Remediation](flows/06-reporting-and-remediation.md) | Findings and retesting. |
| [WAF Posture Workflows](flows/07-waf-posture-workflows.md) | End-to-end WAF onboarding, drift, CVE, discovery, and remediation flows. |

## Backend

| Doc | Purpose |
|---|---|
| [Backend Architecture](backend/01-backend-architecture.md) | Services, storage, invariants. |
| [Test Orchestration](backend/02-test-orchestration.md) | Planner, jobs, lifecycle. |
| [API Design](backend/03-api-design.md) | API endpoints and token flow. |
| [Control Plane](backend/04-control-plane.md) | Agent/probe job control. |
| [Test Strategy](backend/05-test-strategy.md) | QA and CI strategy. |
| [Events and Queues](backend/06-events-and-queues.md) | Event topics and envelope. |
| [Notifications](backend/07-notifications.md) | Email/Slack/Teams/webhooks. |
| [Observability](backend/08-observability.md) | Metrics and SLOs. |
| [Database Schema](backend/09-database-schema.md) | Tables and relationships. |
| [WAF Backend Architecture](backend/11-waf-posture-architecture.md) | Optional WAF posture services, jobs, queues, state machines. |
| [WAF Data Model](backend/12-waf-posture-data-model.md) | Optional WAF posture tables, indexes, migrations, retention. |
| [WAF API Contract](backend/13-waf-posture-api-contract.md) | Optional WAF posture endpoint and RBAC contract. |

## Agent

| Doc | Purpose |
|---|---|
| [Agent Architecture](agent/01-agent-architecture.md) | Modules and runtime design. |
| [Installation and Packaging](agent/02-installation-and-packaging.md) | Linux/Docker/Helm packaging. |
| [API Key and Token Lifecycle](agent/03-api-key-and-token-lifecycle.md) | Bootstrap and identity lifecycle. |
| [Detection Modes](agent/04-detection-modes.md) | Packet, canary, log, mirror modes. |
| [Kubernetes Agent](agent/05-kubernetes-agent.md) | Helm, DaemonSet, canary, sidecar. |
| [Placement Guide](agent/06-placement-guide.md) | AWS/GCP/Azure/on-prem placement. |
| [Agent Lifecycle](agent/07-agent-lifecycle.md) | Upgrade, revoke, health. |
| [WAF Agent/Probe Updates](agent/08-waf-agent-probe-updates.md) | Optional probe and agent changes for WAF validation. |

## Detection

| Doc | Purpose |
|---|---|
| [Vector Catalog](detection/01-vector-catalog.md) | DDoS vector families. |
| [Check Library](detection/02-check-library.md) | Checks and safety classes. |
| [Correlation Engine](detection/03-correlation-engine.md) | Verdict logic. |
| [Evidence and Scoring](detection/04-evidence-and-scoring.md) | Evidence model and readiness score. |
| [Origin Bypass](detection/05-origin-bypass.md) | Primary production use case (direct-origin bypass). |
| [L3/L4 Vectors](detection/06-l3-l4-vectors.md) | Network/transport vectors. |
| [DNS Vectors](detection/07-dns-vectors.md) | DNS checks and SOC scenarios. |
| [L7/API Vectors](detection/08-l7-api-vectors.md) | HTTP/API/WAF/rate checks. |
| [TLS/Connection Vectors](detection/09-tls-connection-vectors.md) | TLS, slow, timeout checks. |
| [Protocol Vectors](detection/10-protocol-vectors.md) | HTTP/2, HTTP/3, QUIC, WebSocket. |
| [High-Scale DDoS Detection](detection/11-high-scale-ddos-detection.md) | SOC-gated high-scale evidence. |
| [WAF Fingerprinting and Coverage](detection/13-waf-fingerprinting-coverage.md) | Optional WAF/CDN detection and coverage classification. |
| [WAF Effectiveness and Drift](detection/14-waf-effectiveness-drift.md) | Optional safe WAF validation, monitor-only inference, and baseline drift. |
| [Live Exposure Defense CVE Pipeline](detection/15-live-exposure-defense-cve-pipeline.md) | Optional CVE ingestion, asset matching, and WAF mitigation recommendations. |

## SOC and Security

| Doc | Purpose |
|---|---|
| [High-Scale Workflow](soc/01-high-scale-ddos-workflow.md) | SOC-gated process. |
| [Authorization Pack](soc/02-authorization-pack.md) | Required approvals. |
| [Execution Adapter](soc/03-execution-adapter.md) | Governed adapters. |
| [SOC Reporting](soc/04-soc-reporting.md) | Post-test report. |
| [Security Model](security/01-security-model.md) | Tenant isolation and controls. |
| [Safe Testing Policy](security/02-safe-testing-policy.md) | What is prohibited and gated. |
| [Privacy and Data Retention](security/03-privacy-and-data-retention.md) | Data minimization. |
| [Compliance and References](security/04-compliance-and-references.md) | Research and provider references. |
| [Safe WAF Validation Policy](security/05-waf-safe-validation-policy.md) | Optional WAF validation safety boundaries and prohibited behavior. |

## Optional Integrations

| Doc | Purpose |
|---|---|
| [WAF/CDN/Cloud Connectors](integrations/01-waf-cdn-cloud-connectors.md) | Optional read-only connector pull matrix and normalized snapshots. |
| [Remediation/SIEM/SOAR Connectors](integrations/02-remediation-siem-soar-connectors.md) | Optional Jira, ServiceNow, Splunk, Sentinel, XSOAR, Slack, and webhook workflows. |

## WAF Posture Add-on

| Doc | Purpose |
|---|---|
| [WAF Add-on Master Summary](waf-posture-addon-master.md) | High-level optional add-on summary and architecture decisions. |
| [WAF Add-on Feed Order](agent-prompts/00-waf-agent-feed-order.md) | Agent feed order, feature flags, and non-negotiables for WAF posture work. |
| [WAF Build Backlog](progress-waf-posture-backlog.md) | Agent-ready WAF posture milestones and release blockers. |
| [WAF Add-on Index Section](index-waf-addon-section.md) | Standalone index snippet from the imported add-on package. |
| [Exposure Management Research Map](sources/exposure-management-research-map.md) | Public source mapping for capability inspiration. |

## Deep implementation specs

| Doc | Purpose |
|---|---|
| [End-to-End Platform Spec](product/07-end-to-end-platform-spec.md) | Consolidated product, pages, flows, state machines, UX rules. |
| [Enterprise Production Gap Backlog](product/08-enterprise-production-gap-backlog.md) | Production gap backlog covering auth proof, placement confidence, vector expansion, high-scale lifecycle, notifications, ops, and compliance. |
| [Full Wireframes and Interactions](ux/12-full-wireframes-and-interactions.md) | Concrete page-level wireframes and interaction requirements. |
| [Agent/Probe/Detection Blueprint](backend/10-agent-probe-detection-blueprint.md) | Backend, agent, probe, identity, and detection mechanics. |
| [Vector Test Matrix](detection/12-vector-test-matrix.md) | Vector coverage, safe/high-scale mapping, evidence and done criteria. |
| [Detailed Build Tracker](progress-detailed.md) | Minor task-level build tracker with doc links. |
