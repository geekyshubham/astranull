# SOC Runbook Template

## Test summary

| Field | Value |
|---|---|
| Request ID | `<id>` |
| Customer | `<customer>` |
| Target group | `<target group>` |
| Window | `<start-end>` |
| Scenario | `<scenario>` |
| SOC owner | `<name>` |

## Pre-run checklist

- [ ] Authorization pack accepted.
- [ ] Provider approval accepted.
- [ ] Target scope locked.
- [ ] Emergency contacts online.
- [ ] Agent health verified.
- [ ] External baseline verified.
- [ ] Stop criteria reviewed.
- [ ] Kill switch verified.
- [ ] SOC lead go/no-go approved.

## Live notes

| Time | Note | Owner |
|---|---|---|
| `<time>` | `<note>` | `<owner>` |

## Stop criteria

| Criterion | Threshold | Triggered? |
|---|---|---|
| Availability degradation | `<threshold>` | No |
| Error rate | `<threshold>` | No |
| Customer request | Any request | No |
| Provider request | Any request | No |

## Closure

- [ ] Test stopped.
- [ ] Service health confirmed.
- [ ] Evidence bundle saved.
- [ ] Findings created.
- [ ] Report generated.
- [ ] Customer notified.
