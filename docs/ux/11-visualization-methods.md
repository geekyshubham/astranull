# Visualization Methods

AstraNull should use visual evidence to make complex DDoS readiness understandable.

## Recommended visualizations

| Visualization | Best page | Purpose |
|---|---|---|
| Readiness score gauge | Dashboard | Executive snapshot. |
| Layered defense stack | Target group overview | Show L3/L4/DNS/L7/origin/agent coverage. |
| Traffic path diagram | Test run, findings | Show external probe -> edge -> origin/agent. |
| Truth table | Test run correlation | Explain verdict logic. |
| Timeline | Test run/SOC console | Show events in order. |
| Heatmap | Dashboard/target groups | Show target group vs vector readiness. |
| Radar/spider chart | Reports | Compare readiness dimensions. |
| Score trend line | Dashboard/reports | Show improvement/regression. |
| Agent health map | Agents | Show agent placement and health by environment/region. |
| Evidence feed | Dashboard/reports | Show recent proof events. |
| SOC swimlane | SOC console | Show request approval lifecycle. |
| Risk burn-down | Findings/reports | Show remediation over time. |

## Traffic path diagram states

```text
[External Probe] -> [CDN/WAF/Scrubber] -> [Load Balancer] -> [Origin/Canary Agent]
       sent              blocked?              forwarded?            observed?
```

Use colors/states:

| State | Meaning |
|---|---|
| Green | Expected behavior verified. |
| Red | Traffic penetrated or protection failed. |
| Amber | Partial or inconclusive. |
| Gray | Not configured / not observed. |

## Vector matrix

Rows: target groups. Columns: vector families.

| Target Group | Origin | L3/L4 | DNS | L7/API | TLS/Protocol | High-Scale | Agent Placement |
|---|---|---|---|---|---|---|---|
| Retail Checkout | Fail | Pass | N/A | Warning | Pass | Pending | Pass |
| API Gateway | Pass | Pass | N/A | Pass | Warning | Not requested | Warning |

## Developer-validation implementation (UX-011)

| Visualization | `apps/web` status | Notes |
|---|---|---|
| Readiness score gauge | Implemented | `renderReadinessGauge` on Dashboard readiness snapshot. |
| Radar/spider dimensions | Implemented | `renderReadinessRadar` from readiness factors (fallback dims when empty). |
| Vector/target heatmap | Implemented | `renderVectorHeatmap` — target groups × vector families + `high_scale` column from request state. |
| Score trend | Implemented | `renderScoreTrend` sparkline from test-run history and current score. |
| Traffic path diagram | Implemented | `renderTrafficPath` on Test Runs (latest run). |
| Truth table | Implemented | `renderTruthTable` correlates protected/bypassable/penetrated/misplaced outcomes; backend `misplaced_agent` normalizes to the misplaced row via `normalizeVerdictKey`. |
| Verdict explanation ("Why this verdict?") | Implemented (Test Runs) | `renderVerdictExplanation` — external probe, internal agent, observation mode, placement confidence (`verdict.placement_confidence` when present), conclusion, remediation; reads `external_result` from event or `metadata.external_result`. **Production blockers:** browser/accessibility matrix and staging mode-matrix signoff. |
| Timeline | Implemented | `renderRunTimeline` visual rail plus existing list on Test Runs. |
| SOC swimlane | Implemented | `renderSocSwimlane` on SOC Console (SOC/Owner role). |
| Layered defense stack | Not in slice | Target group overview — production UX follow-up. |
| Agent health map | Not in slice | Agents page — production UX follow-up. |
| Evidence feed | Partial | Evidence Vault table; dedicated feed widget deferred. |
| Risk burn-down | Not in slice | Findings/reports — production UX follow-up. |

Implementation constraints: inline SVG and CSS only (no chart libraries or external assets). Heatmap and trend use metadata from existing `/v1/*` APIs; high-scale cells reflect request state, not customer-triggered execution.

## Production validation still needed

- Cross-browser layout checks for heatmap horizontal scroll and swimlane wrapping on narrow viewports.
- Live data fidelity: heatmap cells should prefer stored verdict evidence over inferred pending states when backend exposes per-cell summaries.
- Accessibility: screen-reader labels on gauges and path diagrams; keyboard focus for drill-down links.
- Reports export should embed the same visual components as the Dashboard where parity is required.

## Browser and accessibility matrix evidence (production blockers)

The **browser/accessibility matrix** called out in UX-011, UX-013, SOC-009, and release checklist items is closed only with **metadata-only** evidence validated by `scripts/ui-accessibility-matrix-evidence.mjs` (unit tests: `tests/unit/ui-accessibility-matrix-evidence.test.mjs`). Do not attach screenshots, DOM/HTML dumps, log blobs, or secrets to the bundle.

### Required page coverage

Each production-blocking surface must appear in the matrix with at least **desktop** and **mobile** viewport runs:

| Page key | Product surface |
|---|---|
| `dashboard` | Readiness gauge, radar, heatmap, score trend, evidence-oriented overview |
| `test_runs` | Traffic path, truth table, verdict explanation, run timeline |
| `soc_console` | SOC swimlane, queue, execution controls (SOC role) |
| `high_scale_request` | Customer high-scale intake and authorization context |
| `reports_export_custody_preview` | Report/export custody preview parity with dashboard visuals |
| `findings` | Findings triage, severity, and remediation drill-down |

### Required run metadata (per page × viewport)

| Field | Meaning |
|---|---|
| `browser` | Browser engine/name used for the run (e.g. `chromium`, `firefox`, `webkit`) |
| `viewport` | `desktop` or `mobile` |
| `axe_status` | Automated axe (or equivalent) result: `pass`, `fail`, `skip`, or `not_applicable` |
| `keyboard_status` | Keyboard traversal / focus order check |
| `screen_reader_status` | Screen-reader labels and announcements check |
| `issues.critical` / `serious` / `moderate` / `minor` | Non-negative issue counts by severity |

Validation **fails** if any required page lacks desktop or mobile coverage, if run metadata is missing, if **critical** issue counts are greater than zero (unresolved production blockers), or if forbidden artifact keys appear (`screenshot`, `raw_html`, `log_blob`, `token`, other `raw_*` fields, etc.).

### How to record evidence

```bash
node scripts/ui-accessibility-matrix-evidence.mjs --input path/to/matrix-input.json --out output/ui-accessibility-matrix-evidence.json
node scripts/ui-accessibility-matrix-evidence.mjs --input path/to/matrix-input.json --validate-only
```

Input may use a top-level `runs[]` array or `pages.{page_key}.runs[]`. The validator writes (or validate-only checks) a safe `ui_accessibility_matrix_evidence` artifact with redacted summaries suitable for release bundles and operator review.

### What this evidence does **not** replace

- Staging/live data fidelity checks for heatmaps and verdict panels.
- Findings detail parity and placement-confidence mode-matrix signoff.
- SOC legal/offline authorization custody for high-scale execution.

Those remain separate production gates; the matrix evidence specifically closes **cross-browser layout** and **accessibility** blockers tied to the visualization surfaces above.

## Completion criteria

Visualization is complete when every major verdict can be understood visually and then drilled into exact evidence.
