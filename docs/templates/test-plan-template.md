# DDoS Readiness Test Plan Template

## Scope

| Field | Value |
|---|---|
| Target group | `<target group>` |
| Targets | `<targets>` |
| Environment | `<prod/staging/lab>` |
| Objective | `<objective>` |
| Risk class | Safe / Controlled / SOC-gated |

## Checks

| Check | Risk class | Expected behavior | Evidence required |
|---|---|---|---|
| `<check>` | `<risk>` | `<expected>` | `<evidence>` |

## Monitoring

| Signal | Source | Owner |
|---|---|---|
| External availability | AstraNull probes | AstraNull |
| Agent health | AstraNull agent | AstraNull/customer |
| Service health | Customer endpoint | Customer/AstraNull |

## Completion criteria

The test is complete when all selected checks have verdicts or documented inconclusive reasons.
