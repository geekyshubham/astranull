# SOC Operations Flow

## SOC responsibilities

| Responsibility | Details |
|---|---|
| Validate authorization | Confirm customer, provider, and internal approvals. |
| Validate scope | Ensure only declared targets are included. |
| Validate monitoring | Agent, external availability, health checks, and contacts are ready. |
| Run go/no-go | Confirm timing, contacts, kill switch, escalation path. |
| Execute/coordinate | Use approved adapter/provider only. |
| Monitor | Watch real-time health and signals. |
| Stop | Stop immediately if safety rules trigger. |
| Close | Record outcome, evidence, and report. |

## SOC live monitoring checklist

- [ ] Correct tenant and target group.
- [ ] Approved window active.
- [ ] Customer contact online.
- [ ] Provider contact path available if applicable.
- [ ] Agent heartbeats healthy.
- [ ] External baseline probes healthy.
- [ ] Kill switch tested before run.
- [ ] Scenario constraints loaded.
- [ ] Notes channel open.
- [ ] Stop criteria visible.

## Stop criteria

A SOC analyst or lead must stop a test if:

- target impact exceeds approved threshold,
- customer emergency contact requests stop,
- provider requests stop,
- traffic deviates from approved scope,
- telemetry is lost,
- agent health is lost and the test depends on it,
- unexpected third-party impact is suspected,
- internal safety system triggers.

## Completion criteria

SOC operations are complete when every high-scale run has documented pre-checks, live notes, stop criteria, and closure evidence.
