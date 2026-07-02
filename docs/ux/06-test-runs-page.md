# Test Runs Page

## Purpose

The Test Runs page is the proof center. It should answer:

- What did AstraNull send?
- What did the outside probe observe?
- What did the inside agent observe?
- How did AstraNull decide the verdict?
- What evidence can we export?

## Summary layout

```text
Test Run: run_01J...
Target Group: Retail Checkout - Prod
Status: Completed
Verdict: Bypassable
Score Impact: -18

Top Evidence:
- Probe from us-east reached 203.0.113.10:443
- Agent prod-origin-01 observed nonce abc123 on eth0
- Expected behavior was "must be blocked before origin"
```

## Timeline event types

| Event | Description |
|---|---|
| Test planned | Planner selected checks and constraints. |
| Agent prepared | Agent acknowledged job over outbound channel. |
| Probe sent | External worker sent safe validation traffic. |
| Probe observed response | External worker recorded response/timeout/reset. |
| Agent observed nonce | Agent saw matching test ID/nonce. |
| Correlation completed | Engine matched events. |
| Verdict emitted | Pass/fail/inconclusive created. |
| Finding created/updated | Failed verdict mapped to finding. |
| Notification sent | Alert/report/ticket emitted. |

## Verdict truth table display

| External result | Agent observation | Verdict |
|---|---|---|
| Blocked/timeout | Not seen | Protected |
| Allowed/connected | Seen | Bypassable / Penetrated |
| Blocked/timeout | Seen | Edge response blocked, traffic still penetrated |
| Allowed/connected | Not seen | Inconclusive / wrong placement / downstream block |
| Probe failed | Agent silent | Inconclusive |

## Evidence detail panel

Show:

- test ID,
- nonce hash/fingerprint,
- target,
- check version,
- probe region/source ID,
- external result,
- agent ID,
- observation mode,
- timestamp delta,
- confidence,
- raw event IDs,
- retention period,
- export button.

## Completion criteria

Test Runs page is complete when a skeptical engineer can understand and verify the verdict without needing backend logs.
