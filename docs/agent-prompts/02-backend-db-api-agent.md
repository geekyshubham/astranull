# Backend DB/API Agent Prompt - WAF Posture

Read:

1. `docs/backend/11-waf-posture-architecture.md`
2. `docs/backend/12-waf-posture-data-model.md`
3. `docs/backend/13-waf-posture-api-contract.md`
4. Existing `docs/backend/09-database-schema.md`
5. Existing `docs/api.md`

Your task:

- Implement WAF tables with tenant RLS.
- Add feature flags.
- Add repository/service layer for WAF assets, snapshots, baselines, drift, connectors, CVE pipeline, recommendations.
- Add API endpoints and RBAC.
- Integrate with existing test runs, evidence, findings, reports, notifications, audit, secret vault.

Constraints:

- No raw payloads, packet captures, secrets, or full policy bodies.
- Discovery candidates cannot be tested until approved.
- Connector failure must not break no-access validation.

Output:

- Migration files.
- Repository/service code.
- Route handlers.
- Unit/integration tests.
- Updated API docs/OpenAPI.
