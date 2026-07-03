# Frontend UX Agent Prompt - WAF Posture

Read:

1. `docs/ux/13-waf-posture-ux.md`
2. `docs/backend/13-waf-posture-api-contract.md`
3. `docs/backend/14-waf-risk-coverage-analytics.md`
4. `docs/product/09-waf-posture-management.md`
5. `docs/product/12-waf-compliance-audit-evidence.md`

Your task:

- Build WAF Posture navigation and pages.
- Add Overview, Assets, Drift, Validation Runs, CVE Pipeline, Discovery Inbox, Integrations, Reports.
- Clearly explain detected vs validated vs underprotected vs unknown.
- Add action buttons for retest, create ticket, approve baseline, approve/reject candidates.

Constraints:

- Do not expose raw payloads/secrets/full response bodies.
- Discovery inbox cannot run tests directly.
- Show confidence and evidence for every verdict.

Output:

- Page components.
- Empty/loading/error states.
- Filters/tables/detail drawers.
- UI tests.
