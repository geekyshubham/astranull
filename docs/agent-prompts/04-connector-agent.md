# Connector Agent Prompt - WAF/CDN/Cloud/CNAPP/Workflow

Read:

1. `docs/integrations/01-waf-cdn-cloud-connectors.md`
2. `docs/integrations/02-remediation-siem-soar-connectors.md`
3. `docs/backend/12-waf-posture-data-model.md`
4. `docs/backend/16-waf-analytics-schema-extensions.md`
5. `docs/detection/17-multi-vendor-cve-mitigation-playbook.md`
6. Existing `docs/api.md` secrets section.

Your task:

- Implement generic connector framework first.
- Implement MVP Cloudflare and AWS WAF connectors.
- Normalize snapshots into metadata summaries and config hashes.
- Implement Jira/ServiceNow ticket creation and Splunk/Sentinel event streaming if in scope.

Constraints:

- Verify exact provider API endpoints and least-privilege scopes before coding.
- Store credentials only in secret vault.
- Never return plaintext secrets.
- Do not store full WAF config bodies unless redacted and approved.

Output:

- Connector models/services.
- Provider adapters.
- Snapshot normalization.
- Health/permission reporting.
- Tests with mocked provider responses.
