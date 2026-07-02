# Reporting and Remediation Flow

## Flow

```text
Verdict generated
  -> Finding created/updated
  -> Owner assigned
  -> Notification sent
  -> User reviews evidence
  -> User fixes environment
  -> User reruns check
  -> Finding closes automatically or manually
  -> Report captures before/after evidence
```

## Remediation guidance format

Every finding should include:

1. what failed,
2. why it matters,
3. exact evidence,
4. likely cause,
5. recommended fix options,
6. retest button,
7. report export.

## Auto-close logic

A finding can auto-close when:

- same check passes on same target group,
- agent placement confidence is high,
- evidence is fresh,
- no contradictory observation exists.

## Completion criteria

Reporting/remediation is complete when issues move from detection to action and retest proof without manual spreadsheet tracking.
