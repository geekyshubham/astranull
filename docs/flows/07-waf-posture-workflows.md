# WAF Posture Workflows

## 1. No-access WAF posture onboarding

| Step | Actor | Action |
|---|---|---|
| 1 | Customer admin | Enables WAF posture feature for tenant/environment. |
| 2 | Customer engineer | Selects existing target group or creates web target group. |
| 3 | Customer engineer | Adds URL/FQDN/API target and expected WAF requirement. |
| 4 | Customer engineer | Optionally installs/positions agent or canary. |
| 5 | Customer WAF owner | Creates harmless marker rule in WAF console. |
| 6 | AstraNull | Runs fingerprint + marker + origin-bypass safe checks. |
| 7 | AstraNull | Produces posture snapshot and findings if needed. |
| 8 | Customer | Reviews evidence, remediates, retests. |

Acceptance criteria:

- Works with zero cloud/WAF credentials.
- Max requests enforced by safe catalog.
- Strong verdict requires agent/canary when proving before-origin block.

## 2. Connector-enriched onboarding

| Step | Actor | Action |
|---|---|---|
| 1 | Customer admin | Creates read-only connector secret. |
| 2 | AstraNull | Validates connector permissions. |
| 3 | AstraNull | Pulls normalized snapshots. |
| 4 | AstraNull | Reconciles connector resources to approved WAF assets. |
| 5 | Customer | Approves proposed baseline. |
| 6 | AstraNull | Schedules drift comparison. |

Acceptance criteria:

- No plaintext secret returned.
- Permission gaps shown clearly.
- Connector data enhances posture but does not override failed external validation without explanation.

## 3. WAF drift detection

| Step | Actor | Action |
|---|---|---|
| 1 | AstraNull | Loads active baseline. |
| 2 | AstraNull | Runs scheduled safe validation and/or connector poll. |
| 3 | AstraNull | Compares latest result against baseline. |
| 4 | AstraNull | Creates drift event if behavior/config weakened. |
| 5 | AstraNull | Opens/updates finding and sends notification/ticket. |
| 6 | Customer | Fixes WAF policy or approves new baseline/exception. |
| 7 | AstraNull | Retests and closes only on proof. |

## 4. Origin-bypass escalation

| Step | Actor | Action |
|---|---|---|
| 1 | AstraNull | Detects direct-origin path reaches agent/canary. |
| 2 | AstraNull | Creates critical finding for protected asset. |
| 3 | AstraNull | Recommends origin restriction: CDN/WAF egress ACL, authenticated origin pull, mTLS, private origin, Host/SNI validation. |
| 4 | Customer | Applies fix in cloud/load balancer/origin/WAF. |
| 5 | AstraNull | Retests direct path and protected path. |
| 6 | AstraNull | Closes when direct path no longer reaches origin and protected path still works. |

## 5. CVE-to-WAF mitigation

| Step | Actor | Action |
|---|---|---|
| 1 | AstraNull | Ingests CVE/advisory. |
| 2 | AstraNull | Triage filters by tenant tech footprint. |
| 3 | AstraNull | Matches affected approved WAF assets. |
| 4 | AstraNull | Runs safe validation where available. |
| 5 | AstraNull | Drafts vendor-specific WAF recommendation. |
| 6 | Human reviewer | Approves recommendation for ticketing/deployment. |
| 7 | AstraNull | Creates ticket/action item with evidence. |
| 8 | Customer | Deploys mitigation in WAF console. |
| 9 | AstraNull | Retests and updates ticket/finding. |

## 6. Optional discovery candidate workflow

| Step | Actor | Action |
|---|---|---|
| 1 | Tenant admin | Enables external discovery and defines allowed entity scope. |
| 2 | AstraNull | Builds entity/candidate map from approved sources. |
| 3 | AstraNull | Shows candidates in discovery inbox; no findings yet. |
| 4 | Customer | Approves/rejects candidates. |
| 5 | AstraNull | Approved candidates become targets/WAF assets. |
| 6 | AstraNull | Runs safe posture validation. |

## 7. Remediation workflow

| Step | Actor | Action |
|---|---|---|
| 1 | AstraNull | Groups related WAF findings into action item. |
| 2 | AstraNull | Routes to owner based on target group/entity/connector tags. |
| 3 | AstraNull | Creates Jira/ServiceNow ticket or SIEM/SOAR event. |
| 4 | Customer | Fixes, marks deployed, or accepts risk. |
| 5 | AstraNull | Retests. |
| 6 | AstraNull | Closes finding or reopens with updated evidence. |

## Done criteria for workflow suite

- Every workflow has audit events.
- Every unsafe or unapproved path is blocked by API/service layer.
- Every finding can be retested.
- Every external ticket has a link back to evidence and retest.
- User can disable WAF posture or discovery per tenant/environment.
