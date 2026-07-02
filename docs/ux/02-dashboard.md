# Dashboard UX

## Purpose

The Dashboard gives a fast answer to:

> Are we DDoS-ready right now, and where are the biggest gaps?

## Top layout

```text
+---------------------------------------------------------------+
| AstraNull Readiness Dashboard                                 |
| Score: 78 / 100   Status: Needs Attention   Last Run: 2h ago  |
+----------------+----------------+----------------+-----------+
| Critical gaps  | Agents online  | Groups covered | SOC reqs  |
| 3              | 18/20          | 12/14          | 2 pending |
+----------------+----------------+----------------+-----------+
| Priority Actions                                                |
| 1. Fix direct-origin bypass on Retail Checkout                  |
| 2. Move/rebind agent for API Gateway                            |
| 3. Complete provider approval for high-scale test               |
+---------------------------------------------------------------+
```

## Dashboard cards

| Card | Fields |
|---|---|
| Readiness Score | Score, trend, score band, last calculated time. |
| Critical Findings | Count, top 3, affected target groups. |
| Agent Health | Online/offline/degraded, stale heartbeat, version drift. |
| Target Group Coverage | Declared groups, groups with agents, groups with recent runs. |
| Recent Test Runs | Status, verdict, duration, check count, link to evidence. |
| High-Scale Requests | Pending SOC review, scheduled, running, blocked. |
| Evidence Freshness | Last successful run per critical target group. |

## Priority action logic

Sort actions by:

1. criticality of target group,
2. severity of finding,
3. confidence of evidence,
4. age of finding,
5. whether it affects high-scale readiness.

## Dashboard visualizations

| Visualization | Why it works |
|---|---|
| Readiness score gauge | Executive-friendly overview. |
| Target group heatmap | Shows which services are weak. |
| Score trend line | Shows improvement/regression. |
| Vector coverage matrix | Shows gaps by L3/L4/DNS/L7/API/high-scale. |
| Agent health strip | Quickly reveals blind spots. |
| Evidence feed | Builds trust that tests are actually running. |

## Empty state

When no target groups exist:

> “Start by creating a target group for one internet-facing service. AstraNull will help you install an agent and run the first safe validation.”

Primary CTA: **Create Target Group**

Secondary CTA: **View 5-minute Setup Guide**

## Completion criteria

Dashboard is complete when:

- data loads per tenant,
- no-target empty state exists,
- score and risk cards are accurate,
- every card links to details,
- stale data is clearly labeled,
- SOC items are visible but customer cannot execute them.
