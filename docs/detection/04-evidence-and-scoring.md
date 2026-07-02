# Evidence and Scoring

## Evidence model

Every verdict should have an evidence bundle.

| Evidence item | Required for |
|---|---|
| Test run ID | All verdicts. |
| Check ID/version | All verdicts. |
| Target and expected behavior | All verdicts. |
| Probe event | Most checks. |
| Probe result | Most checks. |
| Agent observation/no-observation | Inside/outside proof checks. |
| Agent health | Agent-based checks. |
| Correlation decision | All verdicts. |
| Approval documents | High-scale checks. |
| SOC notes | High-scale checks. |
| Health metrics | High-scale and availability checks. |

## Readiness score dimensions

The live readiness service (`src/services/readiness.mjs`) computes an **evidence-backed** score from in-memory tenant records. Points are not awarded from absence of data (for example, an empty high-scale queue does not imply SOC readiness).

| Dimension | Weight | Meaning |
|---|---:|---|
| Validation coverage | 40 | Distinct declared target groups with a **recent** (≤30 days) completed/verdicted run that has a linked verdict, event, or evidence vault record. |
| Agent placement & health | 25 | Active non-revoked agents and online health; detail distinguishes registration vs observation evidence. |
| Open findings impact | 25 | Penalty for open findings; verdict counts separate recent vs stale evidence. |
| Evidence freshness | 15 | Awarded only when recent evidence-backed validations exist; **stale evidence (>30 days) earns no freshness credit**. |
| SOC governance posture | 10 | Explicit artifacts: dual SOC approval with accepted authorization pack, governed high-scale lifecycle audit trail, or tenant kill-switch evidence—not pending requests alone. |

Longer-term product dimensions (origin bypass, L3/L4, DNS, L7/API) remain roadmap items; they must also be evidence-backed when implemented.

## Score bands

| Score | Label | Meaning |
|---:|---|---|
| 90-100 | Strong | Readiness is well-evidenced. |
| 75-89 | Good | Minor gaps or stale evidence. |
| 50-74 | Needs attention | Important gaps exist. |
| 25-49 | Weak | Multiple critical gaps. |
| 0-24 | Unknown/critical | Missing evidence or confirmed high-risk exposure. |

## Finding creation logic

Create finding when:

- verdict is bypassable/penetrated,
- required control is missing,
- high-scale test failed or caused unacceptable degradation,
- agent placement invalidates readiness evidence,
- evidence is stale for critical target group.

Do not create noisy findings for expected/accepted behaviors unless policy requires it.

## Completion criteria

Scoring is complete when executives can trust the score and engineers can drill from score to evidence to remediation.
