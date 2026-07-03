# Detection/Probe Agent Prompt - WAF Posture

Read:

1. `docs/detection/13-waf-fingerprinting-coverage.md`
2. `docs/detection/14-waf-effectiveness-drift.md`
3. `docs/detection/16-waf-scenario-cadence.md`
4. `docs/detection/17-multi-vendor-cve-mitigation-playbook.md`
5. `docs/backend/15-waf-product-catalog-pipeline.md`
6. `docs/security/05-waf-safe-validation-policy.md`
7. `docs/agent/08-waf-agent-probe-updates.md`
8. Existing `docs/detection/05-origin-bypass.md`
9. Existing `docs/detection/08-l7-api-vectors.md`

Your task:

- Add safe WAF fingerprint probe profiles.
- Add customer marker rule validation.
- Add WAF correlation logic.
- Add monitor-only and drift behavior detection.
- Reuse origin-bypass logic for WAF/CDN bypass.

Constraints:

- Do not add live exploit payloads.
- Do not exceed safe probe limits.
- Store metadata-only evidence.
- Strong verdicts require agent/canary or connector support where needed.

Output:

- Check catalog entries.
- Probe worker profiles.
- Correlation functions.
- Test fixtures for protected/underprotected/unprotected/unknown.
- Safety tests for forbidden fields.
