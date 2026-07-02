# Customer Onboarding Flow

## Goal

A new customer should reach the first evidence-backed validation run with minimum confusion.

## Flow summary

```text
Sign up / invited
  -> Create organization
  -> Create environment
  -> Create target group
  -> Add declared targets
  -> Generate bootstrap token
  -> Install agent
  -> Verify agent heartbeat
  -> Run placement test
  -> Run first safe validation
  -> Review findings/report
```

## Detailed steps

| Step | User action | Platform action | Success condition |
|---|---|---|---|
| 1 | Accept invite / sign in | Create user session and tenant context | User lands on onboarding wizard. |
| 2 | Create environment | Store environment metadata | Environment exists. |
| 3 | Create target group | Store business service scope | Target group created. |
| 4 | Add target | Validate format only, not ownership discovery | At least one target exists. |
| 5 | Pick expected behavior | Configure expected outcome | Expected behavior saved. |
| 6 | Generate token | Create one-time bootstrap token | Install command generated. |
| 7 | Install agent | Agent registers outbound | Agent appears online. |
| 8 | Run placement test | Platform sends safe baseline/canary | Placement is verified or warning shown. |
| 9 | Run first checks | Planner executes safe checks | Run completed. |
| 10 | Review result | Findings/report generated | User sees action plan. |

## Onboarding UX requirements

- Show progress bar.
- Explain why each step matters.
- Allow skipping high-scale setup.
- Warn if no agent placement can prove the selected target.
- Provide install commands for Linux, Docker, Kubernetes.
- Show copy button and “command copied” confirmation.
- Provide troubleshooting link if agent does not connect.

## Completion criteria

Onboarding is complete when a new user can independently install an agent and complete the first validation run.
