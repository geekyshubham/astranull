# UX Principles

AstraNull users are usually under pressure: security teams, network engineers, SOC operators, and executives care about clarity more than decoration. The UX should feel powerful but calm.

## UX goals

| Goal | UX behavior |
|---|---|
| Make complex testing safe | Default to safe checks; explain risk level before execution. |
| Show proof, not jargon | Every verdict links to evidence: probe event, agent observation, health signal, approval artifact. |
| Reduce setup friction | Onboarding wizard gives copy-paste install commands and verifies agent placement. |
| Prevent false confidence | Warn clearly when the agent is misplaced or cannot observe the target path. |
| Make SOC control obvious | High-scale actions are request-only for customers and action-gated for SOC. |
| Help users act | Findings must include “why it matters”, “evidence”, and “recommended fix”. |

## Voice and microcopy

| Situation | Copy style |
|---|---|
| Empty target group | “Add the first target you want AstraNull to validate.” |
| Agent not installed | “Install an agent where it can observe this target’s traffic.” |
| Misplaced agent | “This agent is online, but it did not observe baseline traffic for this target.” |
| High-scale request | “This request will be reviewed by AstraNull SOC before anything is executed.” |
| Failed check | “Traffic reached a protected zone when it was expected to be blocked.” |
| Inconclusive check | “AstraNull could not prove the outcome. Check agent placement or expected behavior.” |

## Friendly defaults

- First-run onboarding should guide the user through **one target group + one agent + one safe run**.
- Do not show all advanced vectors at once; group them by risk and layer.
- Make “what to do next” visible on every page.
- Use compact score cards at top, details below.
- Use plain labels: **Blocked**, **Reached Agent**, **Bypassable**, **Needs Placement Fix**, **SOC Approval Needed**.

## Error states

| Error | User-facing message | Action |
|---|---|---|
| Bootstrap token expired | “This install token has expired.” | Generate new token. |
| Agent clock skew | “Agent time differs from platform time.” | Show NTP guidance. |
| Wrong target/agent binding | “This agent did not observe baseline traffic for this target.” | Rebind or move agent. |
| Unsafe schedule | “This test is outside the allowed window.” | Pick approved window. |
| High-scale missing approval | “Provider/customer authorization is required before SOC can approve this.” | Upload required documents. |

## UX completion criteria

The UX is complete when a non-expert user can:

1. understand what AstraNull does,
2. create a target group,
3. install an agent,
4. run a safe check,
5. understand a pass/fail/inconclusive result,
6. request high-scale validation without being able to self-launch it,
7. export a meaningful report.
