# Security and QA Agent Prompt - WAF Posture

Read:

1. `docs/security/05-waf-safe-validation-policy.md`
2. `docs/backend/12-waf-posture-data-model.md`
3. `docs/backend/13-waf-posture-api-contract.md`
4. `docs/backend/16-waf-analytics-schema-extensions.md`
5. `docs/detection/14-waf-effectiveness-drift.md`
6. `docs/detection/16-waf-scenario-cadence.md`
7. `docs/product/12-waf-compliance-audit-evidence.md`

Your task:

- Threat-model WAF posture features.
- Add tests for tenant isolation, unsafe field rejection, connector secret safety, safe probe enforcement, unapproved candidate blocking, and audit coverage.
- Verify feature flags default off.
- Verify reports/tickets are redacted.

Must test:

- Cross-tenant reads/writes fail.
- Raw payload/body/header/packet fields rejected.
- Probe request counts cannot be raised by client.
- Connector plaintext secrets never returned.
- Auto-deploy is impossible unless future feature flag and approval workflow exist.
- Findings close only through retest/exception/baseline approval.

Output:

- Security test plan.
- Automated tests.
- Release gate checklist.
- Findings with severity and fixes.
