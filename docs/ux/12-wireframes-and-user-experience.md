# UX Wireframes and Experience Blueprint

## Experience goal

AstraNull should feel like a guided readiness cockpit, not a raw security tool. The best UX is:

- wizard-first for new users,
- evidence-first for engineers,
- score-first for executives,
- approval-first for SOC,
- action-first for findings.

## Home dashboard wireframe

```text
+--------------------------------------------------------------------------------+
| AstraNull                         [Target Group Filter] [Run Safe Test] [Report] |
+--------------------------------------------------------------------------------+
| Readiness Score 78     Critical Findings 3     Agents 18/20     SOC Requests 2  |
+--------------------------------------------------------------------------------+
| Priority Actions                                                               |
| 1. Retail Checkout: direct-origin bypass confirmed       [View Evidence]       |
| 2. API Gateway: agent placement inconclusive             [Fix Placement]       |
| 3. High-scale request missing provider approval          [Upload Approval]     |
+--------------------------------------------------------------------------------+
| Service Readiness Heatmap                                                      |
| Target Group          Origin   L3/L4   DNS   L7/API   Protocols   High-Scale   |
| Retail Checkout       FAIL     PASS    N/A   WARN     PASS        PENDING      |
| Public API Gateway    PASS     PASS    N/A   PASS     WARN        NONE         |
+--------------------------------------------------------------------------------+
| Recent Evidence Feed                                                           |
| 10:20 Direct-origin probe reached agent-prod-01 -> Critical finding created     |
| 09:45 Canary protected-path check passed for Public API Gateway                 |
+--------------------------------------------------------------------------------+
```

## Onboarding wizard wireframe

```text
Step 1       Step 2       Step 3        Step 4        Step 5        Step 6
Environment > Targets  > Agent Install > Placement  > Safe Check > Evidence

[Create target group]
Name: Retail Checkout
Environment: Production
Criticality: Critical
Owner: Platform Security

Primary CTA: Continue
Secondary CTA: Import CSV
```

## Agent install page wireframe

```text
Agents > Install

Choose install method:
[Linux Host] [Docker] [Kubernetes Helm] [Packet Mirror Collector] [Cloud Startup Script]

Bootstrap token settings:
Environment: Production
Target group: Retail Checkout
Expires: 1 hour
Max registrations: 1
Observation modes: packet metadata, canary listener

Generated command:
+------------------------------------------------------------------------------+
| curl -fsSL https://download.astranull.example/install.sh | sudo bash -s -- ...|
+------------------------------------------------------------------------------+
[Copy command]

After installation:
[Waiting for heartbeat...]  [Troubleshooting]
```

## Test run evidence wireframe

```text
Test Run run_123: Direct-Origin Bypass
Status: Completed       Verdict: Bypassable       Confidence: High

Traffic Path:
[External Probe] ---> [Direct Origin IP] ---> [Agent prod-origin-01]
       sent                  connected                  observed nonce

Evidence Timeline:
10:00:01 Agent prepared observation window
10:00:04 Probe sent to 203.0.113.10:443
10:00:04 Probe connected
10:00:05 Agent observed nonce on eth0
10:00:06 Correlation verdict: Bypassable

Recommended fix:
Restrict origin ingress to CDN/scrubber/LB path and retest.
```

## SOC high-scale console wireframe

```text
SOC Console > High-Scale Request hs_456

State: Go/No-Go Review
Customer: ExampleBank
Target Group: Public API Gateway
Window: 2026-07-02 02:00-03:00 IST

Authorization Checklist:
[x] Customer authorization letter
[x] Provider approval reference
[x] Emergency contacts
[x] Scope locked
[x] Agent health verified
[ ] SOC lead final approval

Live controls after approval:
[Start Approved Run] [Pause] [STOP ALL / Kill Switch]

Live Metrics:
External availability | Agent heartbeat | Service health | Adapter status | SOC notes
```

## Best representation methods by user type

| User | Best representation | Why |
|---|---|---|
| CISO | Score trend, heatmap, executive report | Fast risk understanding. |
| Security architect | Vector matrix, findings, remediation | Shows exact gaps. |
| Network engineer | Traffic path diagram, probe/agent truth table | Explains packet/path behavior. |
| App owner | L7/API cards, endpoint controls, latency/error impact | Maps to application behavior. |
| SOC analyst | Approval swimlane, live telemetry, kill switch | Operational safety. |
| Auditor | Evidence timeline, immutable report, authorization pack | Proof and traceability. |

## Completion criteria

The UX is complete when users can finish the first validation without reading documentation, engineers can trust evidence, and SOC cannot accidentally bypass high-scale approvals.
