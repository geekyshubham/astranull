# Safe Check Execution Flow

## Goal

Run low-risk checks that validate readiness without disrupting customer services.

## Flow

```text
User selects target group + checks
  -> Backend validates permissions and schedule
  -> Planner builds bounded test plan
  -> Agent receives prep job over outbound channel
  -> External probe sends labeled safe traffic
  -> Agent observes or does not observe nonce
  -> Correlation engine compares signals
  -> Verdict engine emits result
  -> Findings/report updated
```

## Safety controls

| Control | Purpose |
|---|---|
| Check risk class | Safe vs controlled vs SOC-gated. |
| Rate cap | Prevent accidental load. |
| Concurrency cap | Prevent overlapping tests. |
| Time window | Respect customer-defined safe windows. |
| Target allowlist | Only declared targets can be tested. |
| Nonce labeling | Every probe must be attributable. |
| Kill switch | Stop running jobs. |
| Audit log | Record who started what and when. |

## Test plan fields

| Field | Description |
|---|---|
| test_run_id | Unique run ID. |
| target_group_id | Scope. |
| selected_checks | Versioned checks. |
| targets | Explicit targets. |
| agents | Agents expected to observe. |
| constraints | Rate/concurrency/time limits. |
| expected_behaviors | Target-specific expectations. |
| nonces | Per-probe identifiers. |
| timeout_windows | Correlation windows. |

## Completion criteria

Safe execution is complete when customer-started tests are bounded, audited, correlated, and cannot turn into high-scale traffic.
