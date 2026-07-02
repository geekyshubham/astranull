# Backend and Platform Test Strategy

## Test categories

| Category | What to test |
|---|---|
| Unit tests | Token validation, RBAC, planning, correlation, scoring. |
| Integration tests | Agent registration, probe event ingestion, verdict creation. |
| E2E tests | Onboarding -> install simulated agent -> run check -> view finding. |
| Security tests | Tenant isolation, token leakage, replay, permission bypass, API rate-limit 429 behavior. |
| Load tests | Event ingestion, heartbeats, dashboards, reports. |
| Chaos tests | Agent disconnects, queue delay, probe timeout, partial evidence. |
| SOC workflow tests | Approval gates, kill switch, rejected authorization, stop states. |

## Minimum CI scenarios

1. Create tenant/user.
2. Create target group.
3. Generate bootstrap token.
4. Register simulated agent.
5. Send heartbeat.
6. Start safe run.
7. Emit probe event.
8. Emit agent observed event.
9. Correlate as bypassable.
10. Create finding.
11. Generate report.
12. Verify audit logs.
13. Exceed service-layer API rate limit and assert `429` + `Retry-After`; confirm `/health` remains reachable.

## Service-layer rate limits

Unit tests cover fixed-window reset, per-client key separation, and production fail-closed when `ASTRANULL_RATE_LIMIT_DISABLED=1`. Integration tests use a low `ASTRANULL_RATE_LIMIT_MAX_REQUESTS` on a dedicated server instance so the default operability server is unaffected. Gateway/WAF limits are documented as required production defense-in-depth but are not simulated in CI.

## Agent install matrix

| Platform | Test requirement |
|---|---|
| Ubuntu LTS | deb package + one-line installer. |
| Debian | deb package. |
| RHEL/Rocky/Alma | rpm package. |
| Amazon Linux | rpm package. |
| SUSE | rpm or tarball fallback. |
| Generic Linux | static tarball. |
| Docker | container mode. |
| Kubernetes | Helm DaemonSet and canary Deployment. |

## Completion criteria

Testing is complete when CI proves the entire validation loop and blocks unsafe regressions.
