# Platform Overview

## What AstraNull is

**AstraNull** is a DDoS readiness validation platform for enterprises that do not want to give cloud, CDN, WAF, or firewall credentials to a third party.

The product validates customer-declared target groups through:

1. **External probes** launched from AstraNull-controlled probe locations.
2. **Internal agents/canaries** installed by the customer inside the protected environment.
3. **Correlation** between what AstraNull sent and what the agent observed.
4. **Evidence-backed verdicts** that say whether traffic was blocked, penetrated, bypassed, or inconclusive.
5. **SOC-gated high-scale workflows** for approved large simulations.

## Core platform modules

| Module | What it does |
|---|---|
| Public Landing | Unauthenticated entry point with product positioning, sign-up, and login redirects. |
| Customer Portal | UI for onboarding, target groups, agents, checks, findings, reports, and settings. |
| Internal Management Console | AstraNull staff-only UI for tenant lifecycle, sign-up review, subscriptions, entitlements, support operations, and internal approvals. |
| SOC Console | Internal operator UI for high-scale requests, approval, scheduling, execution, monitoring, and closure. |
| Agent Service | Registers agents, issues identities, receives heartbeats and observations. |
| Probe Network | Sends safe external validation traffic and collects external observations. |
| Test Orchestration Engine | Turns target group + check selection into a bounded test plan. |
| Detection & Correlation Engine | Matches probe events with agent observations and produces verdicts. |
| Evidence Store | Stores immutable records of requests, observations, logs, approvals, and reports. |
| Readiness Score Engine | Converts checks and findings into target-group and enterprise-level scores. |
| Reporting Engine | Produces executive, technical, SOC, audit, and customer-facing reports. |
| API & Integrations | Supports automation, webhooks, ticketing, SIEM/SOAR, and optional future cloud connectors. |

The customer portal and internal management console are separate trust surfaces. Customers can request sign-up, safe validation, and high-scale assessments, but AstraNull staff-only management handles tenant provisioning, subscription controls, internal approvals, and SOC-governed high-scale decisions. See [Public Landing and Internal Management](13-public-landing-and-internal-management.md).

## What AstraNull validates

| Validation family | Example question AstraNull answers |
|---|---|
| Direct-origin bypass | Can traffic reach the origin without going through CDN/WAF/scrubbing? |
| Protected-path validation | Does the expected protected route block/challenge/allow the right canary requests? |
| L3/L4 policy behavior | Do TCP/UDP/ICMP/protocol probes reach the protected zone when they should not? |
| DNS readiness | Are declared DNS services protected against exposure and obvious misuse patterns? |
| L7/WAF/rate-limit readiness | Do safe request patterns trigger intended controls? |
| API/resource exhaustion readiness | Are declared expensive endpoints protected by limits? |
| Agent placement correctness | Is the agent placed where it can actually observe traffic for the target? |
| High-scale DDoS readiness | Under SOC-approved simulation, do protections, health checks, alerts, and runbooks work? |

## What AstraNull does not do by default

| Not in core scope | Reason |
|---|---|
| Automatic IP inventory discovery | User explicitly wants this removed. It also requires trust/access and can become noisy. |
| Cloud config audit | Requires customer API credentials. Optional later as enhanced mode. |
| Uncontrolled attack generation | Unsafe and legally risky. High-scale tests must be SOC-gated and authorized. |
| Replacement for DDoS protection providers | AstraNull validates readiness; it does not replace Cloudflare, Akamai, AWS Shield, Azure DDoS, Google Cloud Armor, Arbor, Radware, etc. |

## Product positioning

**AstraNull proves DDoS readiness for customer-declared targets without requiring cloud credentials or automatic IP inventory discovery.**

This is a **no-access-first** platform: customers declare scope, install outbound-only agents, and AstraNull correlates safe external probes with internal observations.

## Enterprise value

| Buyer concern | AstraNull value |
|---|---|
| “We cannot give you cloud access.” | No-access mode works with agents and declared targets. |
| “We bought DDoS protection, but is it working?” | Inside/outside validation proves behavior. |
| “Our SOC needs control over dangerous tests.” | High-scale tests are request-only and SOC-authorized. |
| “We need audit evidence.” | Every verdict includes test IDs, timestamps, observations, and approval artifacts. |
| “We use hybrid/multi-cloud/on-prem.” | Agent/canary model works across environments. |
