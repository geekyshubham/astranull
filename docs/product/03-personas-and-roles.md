# Personas and Roles

## External customer personas

| Persona | Needs | Product experience |
|---|---|---|
| CISO / VP Security | Enterprise risk, board evidence, trend, audit readiness | Dashboard, score trend, executive reports, risk acceptance. |
| Security Architect | Validation coverage, protection design gaps | Target groups, check library, findings, remediation guidance. |
| Network Engineer | Ports, protocols, origin exposure, packet path | L3/L4 checks, agent placement, packet observation evidence. |
| App/API Owner | L7 readiness, rate limits, endpoint risk | API/L7 checks, endpoint limits, safe recommendations. |
| SRE / Platform Engineer | Availability, health, runbooks, alerts | Test runs, timelines, health data, retest scheduling. |
| Compliance/Auditor | Evidence and approvals | Reports, immutable audit log, authorization artifacts. |
| Read-only Executive | Minimal high-level status | Business-service score cards and reports. |

## Internal AstraNull personas

| Persona | Responsibilities | Product area |
|---|---|---|
| SOC Analyst | Review high-scale requests, validate permissions, monitor runs | SOC Console |
| SOC Lead | Approve risky tests, enforce rules, stop tests | SOC Console, Authorization Pack |
| Customer Success Engineer | Help customers onboard and place agents correctly | Onboarding, Agents, Target Groups |
| Detection Engineer | Add/maintain vector checks and verdict logic | Check Library, Detection Engine |
| Platform Admin | Tenant support, operational health, incident response | Admin and Observability |

## RBAC matrix

| Permission | Owner | Admin | Engineer | SOC Analyst | Auditor | Viewer |
|---|---:|---:|---:|---:|---:|---:|
| View dashboard | Yes | Yes | Yes | Yes | Yes | Yes |
| Manage target groups | Yes | Yes | Yes | No | No | No |
| Generate bootstrap token | Yes | Yes | Yes | No | No | No |
| Install agent | External action | External action | External action | No | No | No |
| Start safe test | Yes | Yes | Yes | No | No | No |
| Request high-scale test | Yes | Yes | Yes | No | No | No |
| Approve high-scale test | No | No | No | Yes | No | No |
| Execute high-scale test | No | No | No | Yes | No | No |
| Stop high-scale test | No | No | No | Yes | No | No |
| View reports | Yes | Yes | Yes | Yes | Yes | Yes |
| Accept risk | Yes | Yes | No | No | No | No |
| Manage users | Yes | Yes | No | No | No | No |
| View audit logs | Yes | Yes | No | Yes | Yes | No |
