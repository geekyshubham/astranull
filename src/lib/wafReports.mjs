import {
  assertNoRawWafEvidence,
  normalizeWafEvidenceSummary,
  WAF_SCENARIO_FAMILIES,
  WAF_VALIDATION_MODES,
} from '../contracts/wafPosture.mjs';
import { buildCriticalityRollup } from '../services/wafCoverageService.mjs';
import { buildCustodyManifest } from './custody.mjs';
import { normalizeEvidenceKey, redactObject } from './redact.mjs';

export const WAF_REPORT_VALIDATION_LIMIT = 200;
export const WAF_REPORT_DRIFT_LIMIT = 200;

export const WAF_REPORT_KINDS = new Set([
  'executive_coverage',
  'technical_evidence',
  'drift_audit',
  'connector_health',
  'compliance_audit',
  'board_roadmap_brief',
]);

export const WAF_BOARD_ROADMAP_DISCLAIMER =
  'Executive investment narrative derived from declared asset metadata and safe validation evidence; not a procurement commitment or vendor recommendation.';

const TIER_ROLLOUT_WINDOWS = Object.freeze({
  tier_1: '0-14 days',
  tier_2: '15-60 days',
  tier_3: '61-180 days',
  tier_4: 'quarterly review',
});

const TIER_EXAMPLE_CRITICALITY = new Set([
  'auth',
  'payment',
  'checkout',
  'pii',
  'login',
  'admin',
  'internal_admin',
]);

export const WAF_COMPLIANCE_AUDIT_DISCLAIMER =
  'Maps observed WAF posture evidence to common framework questions; does not certify compliance. Requires auditor review.';

const WAF_COMPLIANCE_FRAMEWORK_MAPPINGS = Object.freeze([
  {
    framework: 'PCI DSS',
    control_themes: 'Protect cardholder data environments; monitor security controls',
    evidence_summary: 'WAF coverage on payment-tagged assets; blocking validation results; drift audit',
    compliance_tag: 'pci',
  },
  {
    framework: 'HIPAA',
    control_themes: 'Access control and transmission protection for ePHI systems',
    evidence_summary: 'WAF coverage on PHI-tagged assets; origin-bypass findings',
    compliance_tag: 'hipaa',
  },
  {
    framework: 'GDPR',
    control_themes: 'Appropriate technical measures for processing risk',
    evidence_summary: 'Coverage and remediation records for in-scope web assets',
    compliance_tag: 'gdpr',
  },
  {
    framework: 'ISO 27001',
    control_themes: 'Annex A network security and monitoring',
    evidence_summary: 'Validation history, drift events, ticket linkage',
    compliance_tag: null,
  },
  {
    framework: 'SOC 2',
    control_themes: 'Logical access and system operations',
    evidence_summary: 'Connector read-only posture, change drift, retest closure',
    compliance_tag: null,
  },
  {
    framework: 'NIST CSF',
    control_themes: 'Protect (PR.DS, PR.IP) and Detect (DE.CM)',
    evidence_summary: 'Posture snapshots, scenario pass rates, SIEM event exports',
    compliance_tag: null,
  },
]);

const CVE_OPEN_STATUSES = new Set([
  'ingested',
  'triaged',
  'matched',
  'validation_pending',
  'exposed',
  'mitigation_recommended',
]);

export function normalizeWafReportKind(kind) {
  return String(kind ?? '').trim().toLowerCase();
}

function redactAssetForReport(asset, snapshot = null) {
  const out = {
    id: asset.id,
    canonical_url: asset.canonical_url ?? asset.hostname ?? null,
    target_group_id: asset.target_group_id,
    ...(asset.owner_hint ? { owner_hint: asset.owner_hint } : {}),
    ...(asset.business_criticality ? { business_criticality: asset.business_criticality } : {}),
    status: asset.status ?? null,
  };
  if (snapshot) {
    out.posture_status = snapshot.status ?? out.status ?? 'unknown';
    out.reason_codes = snapshot.reason_codes ?? [];
    if (snapshot.detected_vendor) out.detected_vendor = snapshot.detected_vendor;
    if (snapshot.detected_product) out.detected_product = snapshot.detected_product;
    if (snapshot.risk_score != null) out.risk_score = snapshot.risk_score;
  }
  return out;
}

function redactValidationForReport(run, scenarioResults = []) {
  return {
    id: run.id,
    waf_asset_id: run.waf_asset_id,
    mode: run.mode,
    status: run.status,
    created_at: run.created_at,
    finalized_at: run.finalized_at ?? null,
    summary: run.summary_json ?? {},
    scenario_results: scenarioResults.map((scenario) => ({
      scenario_family: scenario.scenario_family,
      expected_action: scenario.expected_action,
      observed_action: scenario.observed_action,
      passed: scenario.passed,
      confidence: scenario.confidence,
      evidence_summary: safeEvidenceSummaryForReport(
        scenario.evidence_summary_json ?? scenario.evidence_summary ?? {},
      ),
    })),
  };
}

const WAF_REPORT_CONNECTOR_CONFIG_KEYS = new Set([
  'account_ref_hash',
  'zone_ref_hash',
  'resource_ref_hash',
  'default_snapshot_kind',
  'read_only',
  'owner_hint',
  'tag_summary',
  'polling_interval_minutes',
  'region_summary',
  'notes_hash',
]);

function safeEvidenceSummaryForReport(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {};
  const out = {};
  for (const [key, value] of Object.entries(input)) {
    try {
      Object.assign(out, normalizeWafEvidenceSummary({ [key]: value }));
    } catch {
      /* Drop disallowed report fields instead of leaking them. */
    }
  }
  return out;
}

function safeConnectorConfigForReport(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {};
  const out = {};
  for (const [key, value] of Object.entries(input)) {
    const normalizedKey = normalizeEvidenceKey(key);
    if (WAF_REPORT_CONNECTOR_CONFIG_KEYS.has(normalizedKey)) {
      out[normalizedKey] = value;
    }
  }
  return out;
}

function redactConnectorForReport(connector) {
  return {
    id: connector.id,
    provider: connector.provider,
    name: connector.name,
    status: connector.status,
    ...(connector.last_success_at ? { last_success_at: connector.last_success_at } : {}),
    config: safeConnectorConfigForReport(connector.config ?? connector.config_json ?? {}),
  };
}

function computeCoverageRatio(coverage = {}) {
  const total = coverage.total_assets ?? 0;
  const excluded = coverage.excluded ?? 0;
  const protectedCount = coverage.protected ?? 0;
  const denominator = total - excluded;
  if (denominator <= 0) return 0;
  return Math.round((protectedCount / denominator) * 10000) / 100;
}

function enrichCoverage(coverage = {}) {
  return {
    ...coverage,
    coverage_ratio: computeCoverageRatio(coverage),
  };
}

function redactExceptionForReport(exception) {
  return {
    waf_asset_id: exception.waf_asset_id,
    owner: exception.owner,
    reason: exception.reason,
    expires_at: exception.expires_at,
    scope_hash: exception.scope_hash ?? null,
    ...(exception.approved_at ? { approved_at: exception.approved_at } : {}),
    ...(exception.id ? { id: exception.id } : {}),
  };
}

function buildExceptionRegister(exceptions = []) {
  return exceptions.map((entry) => redactExceptionForReport(entry));
}

function buildValidationPassRates(validations = [], scenarioResultsByRunId = new Map()) {
  const finalized = validations.filter((run) => run.status === 'finalized');
  let passed = 0;
  for (const run of finalized) {
    const scenarios = scenarioResultsByRunId.get(run.id) ?? [];
    if (scenarios.length > 0 && scenarios.every((scenario) => scenario.passed === true)) {
      passed += 1;
    } else if (run.summary_json?.validation_passed === true) {
      passed += 1;
    }
  }
  const total_finalized = finalized.length;
  return {
    total_finalized,
    passed,
    pass_rate: total_finalized === 0 ? 0 : Math.round((passed / total_finalized) * 10000) / 100,
  };
}

function buildAssetSample(assets = [], snapshotsByAssetId = new Map(), limit = 10) {
  const ranked = assets
    .map((asset) => {
      const snapshot = snapshotsByAssetId.get(asset.id) ?? null;
      const riskScore = snapshot?.risk_score ?? postureRiskWeight(snapshot?.status);
      return { asset, snapshot, riskScore };
    })
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, limit);

  return ranked.map(({ asset, snapshot }) => {
    const redacted = redactAssetForReport(asset, snapshot);
    const latestValidationAt = snapshot?.observed_at ?? snapshot?.updated_at ?? null;
    return {
      ...redacted,
      ...(latestValidationAt ? { latest_validation_at: latestValidationAt } : {}),
    };
  });
}

function postureRiskWeight(status) {
  switch (status) {
    case 'unprotected':
      return 100;
    case 'underprotected':
      return 80;
    case 'unknown':
      return 50;
    case 'protected':
      return 10;
    case 'excluded':
      return 0;
    default:
      return 40;
  }
}

function buildEntityRollup(assets = [], snapshotsByAssetId = new Map()) {
  const buckets = new Map();
  for (const asset of assets) {
    const key = asset.entity_id ?? asset.target_group_id ?? 'unassigned';
    const label = asset.entity_id ?? asset.target_group_id ?? 'unassigned';
    if (!buckets.has(key)) {
      buckets.set(key, {
        entity_id: asset.entity_id ?? null,
        target_group_id: asset.target_group_id ?? null,
        name: label,
        asset_count: 0,
        protected: 0,
        underprotected: 0,
        unprotected: 0,
        unknown: 0,
        excluded: 0,
      });
    }
    const bucket = buckets.get(key);
    bucket.asset_count += 1;
    const status = snapshotsByAssetId.get(asset.id)?.status ?? 'unknown';
    if (Object.prototype.hasOwnProperty.call(bucket, status)) {
      bucket[status] += 1;
    } else {
      bucket.unknown += 1;
    }
  }
  return [...buckets.values()].map((bucket) => ({
    ...bucket,
    coverage_ratio: computeCoverageRatio({
      total_assets: bucket.asset_count,
      protected: bucket.protected,
      excluded: bucket.excluded,
    }),
  }));
}

function buildGeographyRollup(assets = [], snapshotsByAssetId = new Map()) {
  const buckets = new Map();
  for (const asset of assets) {
    const region = asset.region_code ?? asset.geography_label ?? 'undeclared';
    if (!buckets.has(region)) {
      buckets.set(region, {
        region_code: asset.region_code ?? null,
        region_label: asset.geography_label ?? region,
        asset_count: 0,
        protected: 0,
        underprotected: 0,
        unprotected: 0,
        unknown: 0,
        excluded: 0,
        unprotected_critical_count: 0,
      });
    }
    const bucket = buckets.get(region);
    bucket.asset_count += 1;
    const status = snapshotsByAssetId.get(asset.id)?.status ?? 'unknown';
    if (Object.prototype.hasOwnProperty.call(bucket, status)) {
      bucket[status] += 1;
    } else {
      bucket.unknown += 1;
    }
    if (
      status === 'unprotected'
      && ['critical', 'high'].includes(asset.business_criticality)
    ) {
      bucket.unprotected_critical_count += 1;
    }
  }
  return [...buckets.values()].map((bucket) => ({
    ...bucket,
    coverage_ratio: computeCoverageRatio({
      total_assets: bucket.asset_count,
      protected: bucket.protected,
      excluded: bucket.excluded,
    }),
  }));
}

function buildConnectorAttestation(connectors = []) {
  return connectors.map((connector) => {
    const redacted = redactConnectorForReport(connector);
    const config = redacted.config ?? {};
    return {
      ...redacted,
      read_only: config.read_only ?? null,
      permission_gaps: connector.last_snapshot_summary?.permission_gaps
        ?? connector.summary_json?.permission_gaps
        ?? [],
      last_poll_at: connector.last_success_at ?? connector.last_poll_at ?? null,
    };
  });
}

function buildCveExposureSummary(cveItems = [], cveMatches = [], assetIds = new Set()) {
  const matchedItemIds = new Set();
  for (const match of cveMatches) {
    if (assetIds.has(match.waf_asset_id)) {
      matchedItemIds.add(match.cve_pipeline_item_id ?? match.cve_item_id);
    }
  }
  const items = cveItems
    .filter((item) => CVE_OPEN_STATUSES.has(item.status))
    .filter((item) => matchedItemIds.size === 0 || matchedItemIds.has(item.id))
    .map((item) => ({
      id: item.id,
      cve_id: item.cve_id,
      status: item.status,
      severity: item.severity ?? null,
      triage_score: item.triage_score ?? null,
    }));
  return {
    open_item_count: items.length,
    items,
  };
}

function collectComplianceArtifactRefs(sources = {}) {
  const validationRunIds = (sources.validations ?? []).map((run) => run.id).filter(Boolean);
  const driftEvents = sources.driftEvents ?? [];
  const driftEventIds = driftEvents.map((event) => event.id).filter(Boolean);
  const findingIds = driftEvents.map((event) => event.finding_id).filter(Boolean);
  const wafAssetIds = (sources.assets ?? []).map((asset) => asset.id).filter(Boolean);
  return {
    validation_run_ids: validationRunIds,
    drift_event_ids: driftEventIds,
    finding_ids: findingIds,
    waf_asset_ids: wafAssetIds,
  };
}

function assetMatchesComplianceTag(asset, tag) {
  if (!tag) return true;
  const tags = Array.isArray(asset.compliance_tags) ? asset.compliance_tags : [];
  return tags.map((entry) => String(entry).trim().toLowerCase()).includes(tag);
}

function buildWafComplianceControlMappingAppendix(sources = {}) {
  const artifactRefs = collectComplianceArtifactRefs(sources);
  const coverage = enrichCoverage(sources.coverage ?? {});
  const passRates = buildValidationPassRates(
    sources.validations ?? [],
    sources.scenarioResultsByRunId ?? new Map(),
  );
  const driftEvents = sources.driftEvents ?? [];

  const entries = WAF_COMPLIANCE_FRAMEWORK_MAPPINGS.map((mapping) => {
    const taggedAssets = (sources.assets ?? []).filter((asset) =>
      assetMatchesComplianceTag(asset, mapping.compliance_tag),
    );
    const taggedAssetIds = new Set(taggedAssets.map((asset) => asset.id));
    const taggedDrift = driftEvents.filter((event) => taggedAssetIds.has(event.waf_asset_id));

    return {
      framework: mapping.framework,
      control_themes: mapping.control_themes,
      astranull_evidence: mapping.evidence_summary,
      status: 'requires auditor review',
      artifact_ids: {
        validation_run_ids: artifactRefs.validation_run_ids.slice(0, 25),
        drift_event_ids: taggedDrift.map((event) => event.id).slice(0, 25),
        finding_ids: taggedDrift.map((event) => event.finding_id).filter(Boolean).slice(0, 25),
        waf_asset_ids: taggedAssets.map((asset) => asset.id).slice(0, 25),
      },
      live_metrics: {
        in_scope_asset_count: taggedAssets.length || (sources.assets ?? []).length,
        coverage_ratio: coverage.coverage_ratio,
        protected_count: coverage.protected ?? 0,
        underprotected_count: coverage.underprotected ?? 0,
        unprotected_count: coverage.unprotected ?? 0,
        open_drift_count: driftEvents.filter((event) => event.status === 'open').length,
        validation_pass_rate: passRates.pass_rate,
      },
    };
  });

  return {
    disclaimer: WAF_COMPLIANCE_AUDIT_DISCLAIMER,
    entries,
  };
}

function redactRoadmapItemForBrief(item) {
  return {
    waf_asset_id: item.waf_asset_id,
    hostname: item.hostname ?? null,
    owner_hint: item.owner_hint ?? null,
    detected_vendor: item.detected_vendor ?? null,
    risk_score: item.risk_score ?? null,
    priority_band: item.priority_band ?? null,
    primary_reason_codes: item.primary_reason_codes ?? [],
    recommended_action: item.recommended_action ?? null,
    posture_status: item.posture_status ?? null,
    ...(item.business_criticality ? { business_criticality: item.business_criticality } : {}),
    ...(item.asset_kind ? { asset_kind: item.asset_kind } : {}),
  };
}

function buildTierSummary(roadmap = {}) {
  const tiers = roadmap.tiers ?? {};
  const tier1 = tiers.tier_1 ?? [];
  const tier2 = tiers.tier_2 ?? [];
  return {
    tier_1_count: tier1.length,
    tier_2_count: tier2.length,
    tier_1_highlights: tier1.slice(0, 5).map((item) => redactRoadmapItemForBrief(item)),
    tier_2_highlights: tier2.slice(0, 5).map((item) => redactRoadmapItemForBrief(item)),
  };
}

function buildInvestmentPhases(roadmap = {}) {
  const tiers = roadmap.tiers ?? {};
  return ['tier_1', 'tier_2', 'tier_3', 'tier_4'].map((tier) => ({
    tier,
    rollout_window: TIER_ROLLOUT_WINDOWS[tier],
    item_count: (tiers[tier] ?? []).length,
    focus:
      tier === 'tier_1'
        ? 'Immediate protection for highest-risk auth, payment, and PII surfaces.'
        : tier === 'tier_2'
          ? 'Near-term remediation for underprotected high-traffic and compliance-tagged assets.'
          : tier === 'tier_3'
            ? 'Planned rollout for medium-priority legacy and marketing assets.'
            : 'Quarterly monitor for excluded or low-impact exceptions.',
  }));
}

function buildTierOneExamples(assets = [], snapshotsByAssetId = new Map(), roadmap = {}) {
  const tierItems = roadmap.tiers?.tier_1 ?? [];
  const examples = [];
  for (const item of tierItems) {
    const asset = assets.find((row) => row.id === item.waf_asset_id);
    if (!asset) continue;
    const criticality = String(asset.business_criticality ?? '').trim().toLowerCase();
    const assetKind = String(asset.asset_kind ?? '').trim().toLowerCase();
    if (!TIER_EXAMPLE_CRITICALITY.has(criticality) && !TIER_EXAMPLE_CRITICALITY.has(assetKind)) {
      continue;
    }
    const snapshot = snapshotsByAssetId.get(asset.id) ?? null;
    examples.push({
      waf_asset_id: asset.id,
      canonical_url: asset.canonical_url ?? asset.hostname ?? null,
      business_criticality: asset.business_criticality ?? null,
      asset_kind: asset.asset_kind ?? null,
      posture_status: snapshot?.status ?? asset.status ?? 'unknown',
      risk_score: snapshot?.risk_score ?? item.risk_score ?? null,
    });
    if (examples.length >= 5) break;
  }
  return examples;
}

function buildProcurementJustificationNarrative({
  coverage = {},
  tierSummary = {},
  geographyHighlights = [],
  vendorMix = {},
}) {
  const coverageRatio = coverage.coverage_ratio ?? computeCoverageRatio(coverage);
  const unprotected = coverage.unprotected ?? 0;
  const underprotected = coverage.underprotected ?? 0;
  const tier1 = tierSummary.tier_1_count ?? 0;
  const tier2 = tierSummary.tier_2_count ?? 0;
  const criticalGeo = geographyHighlights
    .filter((row) => (row.unprotected_critical_count ?? 0) > 0)
    .slice(0, 3)
    .map((row) => row.region_label ?? row.region_code ?? 'undeclared');
  const leadingVendor = (vendorMix.vendor_mix ?? vendorMix.items ?? [])[0]?.vendor ?? 'undeclared';

  const parts = [
    `Current WAF coverage ratio is ${coverageRatio}% across declared in-scope assets.`,
    `${unprotected} assets remain unprotected and ${underprotected} are underprotected based on safe validation evidence.`,
    `The deployment roadmap prioritizes ${tier1} Tier 1 (0-14 day) and ${tier2} Tier 2 (15-60 day) remediation items.`,
  ];
  if (criticalGeo.length > 0) {
    parts.push(
      `Geography highlights with unprotected critical assets: ${criticalGeo.join(', ')}.`,
    );
  }
  parts.push(
    `Vendor mix is led by ${leadingVendor}; investment should align blocking validation and connector read-only attestation before expansion.`,
  );
  parts.push(
    'Recommended procurement phases: fund immediate Tier 1 blocking deployments, then near-term Tier 2 rule hardening and origin-bypass closure.',
  );
  return parts.join(' ');
}

function buildBoardRoadmapBriefPayload(sources = {}, generated_at, tenant_id) {
  const coverage = enrichCoverage(sources.coverage ?? {});
  const roadmap = sources.riskRoadmap ?? { tiers: {}, generated_at, method: 'waf_risk_v1' };
  const vendorBreakdown = sources.vendorBreakdown ?? { items: [], vendor_mix: [] };
  const geography = sources.geographyRollup ?? { items: [] };
  const geographyHighlights = [...(geography.items ?? [])]
    .sort(
      (a, b) =>
        (b.unprotected_critical_count ?? 0) - (a.unprotected_critical_count ?? 0)
        || (b.asset_count ?? 0) - (a.asset_count ?? 0),
    )
    .slice(0, 5);
  const tierSummary = buildTierSummary(roadmap);
  const tierOneExamples = buildTierOneExamples(
    sources.assets ?? [],
    sources.snapshotsByAssetId ?? new Map(),
    roadmap,
  );

  return {
    report_kind: 'board_roadmap_brief',
    generated_at,
    tenant_id,
    disclaimer: WAF_BOARD_ROADMAP_DISCLAIMER,
    executive_summary: {
      coverage,
      coverage_trend: sources.coverageTrend ?? coverage.trend ?? [],
      tier_summary: tierSummary,
    },
    vendor_mix: {
      items: vendorBreakdown.items ?? [],
      vendor_mix: vendorBreakdown.vendor_mix ?? [],
    },
    geography_highlights: geographyHighlights,
    roadmap_reference: {
      api_path: '/v1/waf/coverage/risk-roadmap',
      method: roadmap.method ?? 'waf_risk_v1',
      generated_at: roadmap.generated_at ?? generated_at,
    },
    investment_phases: buildInvestmentPhases(roadmap),
    procurement_justification: {
      narrative: buildProcurementJustificationNarrative({
        coverage,
        tierSummary,
        geographyHighlights,
        vendorMix: vendorBreakdown,
      }),
      tier_1_examples: tierOneExamples,
      risk_signals: {
        coverage_ratio: coverage.coverage_ratio ?? 0,
        unprotected_count: coverage.unprotected ?? 0,
        underprotected_count: coverage.underprotected ?? 0,
        tier_1_gap_count: tierSummary.tier_1_count,
        tier_2_gap_count: tierSummary.tier_2_count,
        unprotected_critical_regions: geographyHighlights
          .filter((row) => (row.unprotected_critical_count ?? 0) > 0)
          .map((row) => row.region_code ?? row.region_label ?? 'undeclared'),
      },
    },
  };
}

function buildComplianceAuditPayload(sources = {}, generated_at, tenant_id) {
  const assets = sources.assets ?? [];
  const snapshotsByAssetId = sources.snapshotsByAssetId ?? new Map();
  const driftEvents = sources.driftEvents ?? [];
  const coverage = enrichCoverage(sources.coverage ?? {});
  const exceptionRegister = buildExceptionRegister(sources.exceptions ?? []);
  const assetIds = new Set(assets.map((asset) => asset.id));

  const validations = sources.validations ?? [];
  const modesUsed = [...new Set(validations.map((run) => run.mode).filter(Boolean))];

  return {
    report_kind: 'compliance_audit',
    generated_at,
    tenant_id,
    executive_coverage_summary: {
      coverage,
      trend: sources.coverageTrend ?? [],
    },
    scope_declaration: {
      target_group_ids: [...new Set(assets.map((asset) => asset.target_group_id).filter(Boolean))],
      waf_required_policy: 'declared_assets',
      assessment_window: {
        end: generated_at,
        ...(sources.assessmentWindowStart ? { start: sources.assessmentWindowStart } : {}),
      },
    },
    asset_sample: buildAssetSample(assets, snapshotsByAssetId),
    validation_methodology: {
      scenario_families: [...WAF_SCENARIO_FAMILIES],
      modes: modesUsed.length > 0 ? modesUsed : [...WAF_VALIDATION_MODES],
    },
    drift_and_exceptions: {
      open_drift_count: driftEvents.filter((event) => event.status === 'open').length,
      resolved_drift_count: driftEvents.filter((event) => event.status === 'resolved').length,
      accepted_risk_count: driftEvents.filter((event) => event.status === 'accepted_risk').length,
      drift_events_summary: driftEvents.map((event) => ({
        id: event.id,
        waf_asset_id: event.waf_asset_id,
        drift_type: event.drift_type,
        severity: event.severity,
        status: event.status,
        created_at: event.created_at,
        ...(event.resolved_at ? { resolved_at: event.resolved_at } : {}),
        ...(event.finding_id ? { finding_id: event.finding_id } : {}),
      })),
    },
    connector_attestation: buildConnectorAttestation(sources.connectors ?? []),
    cve_exposure_summary: buildCveExposureSummary(
      sources.cveItems ?? [],
      sources.cveMatches ?? [],
      assetIds,
    ),
    validation_pass_rates: buildValidationPassRates(
      validations,
      sources.scenarioResultsByRunId ?? new Map(),
    ),
    entity_rollup: buildEntityRollup(assets, snapshotsByAssetId),
    geography_rollup: buildGeographyRollup(assets, snapshotsByAssetId),
    criticality_rollup: buildCriticalityRollup({
      assets,
      currentSnapshotsByAsset: snapshotsByAssetId,
    }).items,
    exception_register: exceptionRegister,
    control_mapping_appendix: buildWafComplianceControlMappingAppendix(sources),
  };
}

/**
 * Build a metadata-only WAF report payload from pre-fetched tenant sources.
 * @param {string} kind
 * @param {{
 *   coverage?: object,
 *   assets?: object[],
 *   snapshotsByAssetId?: Map<string, object>,
 *   validations?: object[],
 *   scenarioResultsByRunId?: Map<string, object[]>,
 *   driftEvents?: object[],
 *   driftEventsTruncation?: { truncated: boolean, limit: number, total_available: number, included_count: number } | null,
 *   connectors?: object[],
 *   exceptions?: object[],
 *   cveItems?: object[],
 *   cveMatches?: object[],
 *   coverageTrend?: object[],
 *   assessmentWindowStart?: string,
 *   tenantId?: string,
 * }} sources
 */
export function buildWafReportPayload(kind, sources = {}) {
  const generated_at = new Date().toISOString();
  const tenant_id = sources.tenantId ?? null;

  if (kind === 'executive_coverage') {
    const assets = (sources.assets ?? []).map((asset) => {
      const snapshot = sources.snapshotsByAssetId?.get(asset.id) ?? null;
      return redactAssetForReport(asset, snapshot);
    });
    const driftEvents = sources.driftEvents ?? [];
    const snapshotsByAssetId = sources.snapshotsByAssetId ?? new Map();
    return {
      report_kind: kind,
      generated_at,
      tenant_id,
      coverage: sources.coverage ?? {},
      asset_summary: assets,
      criticality_rollup: buildCriticalityRollup({
        assets: sources.assets ?? [],
        currentSnapshotsByAsset: snapshotsByAssetId,
      }).items,
      open_drift_count: driftEvents.filter((e) => e.status === 'open').length,
    };
  }

  if (kind === 'technical_evidence') {
    const validations = (sources.validations ?? []).map((run) => {
      const scenarioResults = sources.scenarioResultsByRunId?.get(run.id) ?? [];
      return redactValidationForReport(run, scenarioResults);
    });
    const truncation = sources.validationRunsTruncation ?? null;
    return {
      report_kind: kind,
      generated_at,
      tenant_id,
      validation_runs: validations,
      ...(truncation
        ? {
            validation_runs_truncation: {
              truncated: Boolean(truncation.truncated),
              limit: truncation.limit,
              total_available: truncation.total_available,
              included_count: truncation.included_count,
            },
          }
        : {}),
    };
  }

  if (kind === 'drift_audit') {
    const truncation = sources.driftEventsTruncation ?? null;
    return {
      report_kind: kind,
      generated_at,
      tenant_id,
      drift_events: sources.driftEvents ?? [],
      ...(truncation
        ? {
            drift_events_truncation: {
              truncated: Boolean(truncation.truncated),
              limit: truncation.limit,
              total_available: truncation.total_available,
              included_count: truncation.included_count,
            },
          }
        : {}),
    };
  }

  if (kind === 'connector_health') {
    const connectors = (sources.connectors ?? []).map((connector) => redactConnectorForReport(connector));
    return {
      report_kind: kind,
      generated_at,
      tenant_id,
      connectors,
      counts: {
        active: connectors.filter((c) => c.status === 'active').length,
        degraded: connectors.filter((c) => c.status === 'degraded').length,
        error: connectors.filter((c) => c.status === 'error').length,
        disabled: connectors.filter((c) => c.status === 'disabled').length,
      },
    };
  }

  if (kind === 'compliance_audit') {
    return buildComplianceAuditPayload(sources, generated_at, tenant_id);
  }

  if (kind === 'board_roadmap_brief') {
    return buildBoardRoadmapBriefPayload(sources, generated_at, tenant_id);
  }

  return null;
}

function collectWafReportSubjectIds(payload) {
  const ids = new Set();
  if (payload.tenant_id) ids.add(payload.tenant_id);
  for (const asset of payload.asset_summary ?? payload.asset_sample ?? []) {
    if (asset.id) ids.add(asset.id);
    if (asset.waf_asset_id) ids.add(asset.waf_asset_id);
  }
  for (const run of payload.validation_runs ?? []) {
    if (run.id) ids.add(run.id);
    if (run.waf_asset_id) ids.add(run.waf_asset_id);
  }
  for (const drift of payload.drift_events ?? payload.drift_and_exceptions?.drift_events_summary ?? []) {
    if (drift.id) ids.add(drift.id);
    if (drift.waf_asset_id) ids.add(drift.waf_asset_id);
    if (drift.finding_id) ids.add(drift.finding_id);
  }
  for (const connector of payload.connectors ?? payload.connector_attestation ?? []) {
    if (connector.id) ids.add(connector.id);
  }
  for (const exception of payload.exception_register ?? []) {
    if (exception.id) ids.add(exception.id);
    if (exception.waf_asset_id) ids.add(exception.waf_asset_id);
  }
  for (const item of payload.cve_exposure_summary?.items ?? []) {
    if (item.id) ids.add(item.id);
  }
  for (const highlight of payload.executive_summary?.tier_summary?.tier_1_highlights ?? []) {
    if (highlight.waf_asset_id) ids.add(highlight.waf_asset_id);
  }
  for (const highlight of payload.executive_summary?.tier_summary?.tier_2_highlights ?? []) {
    if (highlight.waf_asset_id) ids.add(highlight.waf_asset_id);
  }
  for (const example of payload.procurement_justification?.tier_1_examples ?? []) {
    if (example.waf_asset_id) ids.add(example.waf_asset_id);
  }
  return [...ids];
}

export function custodyAuditMetadata(custody) {
  return {
    format: custody.format,
    content_sha256: custody.content_sha256,
    custody_schema_version: custody.schema_version,
    report_kind: custody.artifact_id,
  };
}

function buildWafReportMarkdown(payload, custody) {
  const lines = [
    `# WAF ${payload.report_kind} report`,
    '',
    `Generated at: ${payload.generated_at}`,
    `Tenant: ${payload.tenant_id ?? 'unknown'}`,
    '',
  ];

  if (payload.report_kind === 'executive_coverage') {
    lines.push('## Coverage summary');
    for (const [key, value] of Object.entries(payload.coverage ?? {})) {
      lines.push(`- ${key}: ${value}`);
    }
    lines.push('', `Open drift events: ${payload.open_drift_count ?? 0}`, '', '## Asset summary');
    for (const asset of payload.asset_summary ?? []) {
      lines.push(
        `- ${asset.canonical_url ?? asset.id}: ${asset.posture_status ?? asset.status ?? 'unknown'}`,
      );
    }
  } else if (payload.report_kind === 'technical_evidence') {
    lines.push('## Validation runs');
    for (const run of payload.validation_runs ?? []) {
      lines.push(`- ${run.id}: ${run.status} (${run.mode})`);
    }
  } else if (payload.report_kind === 'drift_audit') {
    lines.push('## Drift events');
    for (const drift of payload.drift_events ?? []) {
      lines.push(`- ${drift.id}: ${drift.drift_type} (${drift.severity}) -> ${drift.status}`);
    }
  } else if (payload.report_kind === 'connector_health') {
    lines.push('## Connector health');
    for (const [key, value] of Object.entries(payload.counts ?? {})) {
      lines.push(`- ${key}: ${value}`);
    }
    for (const connector of payload.connectors ?? []) {
      lines.push(`- ${connector.name}: ${connector.provider} (${connector.status})`);
    }
  } else if (payload.report_kind === 'compliance_audit') {
    lines.push('## Executive coverage summary');
    const coverage = payload.executive_coverage_summary?.coverage ?? {};
    lines.push(`- coverage_ratio: ${coverage.coverage_ratio ?? 0}`);
    for (const [key, value] of Object.entries(coverage)) {
      if (key === 'coverage_ratio') continue;
      lines.push(`- ${key}: ${value}`);
    }
    lines.push('', '## Exception register');
    for (const exception of payload.exception_register ?? []) {
      lines.push(
        `- ${exception.waf_asset_id}: owner=${exception.owner}, expires=${exception.expires_at}`,
      );
    }
    lines.push('', '## Control mapping appendix');
    lines.push(`_${payload.control_mapping_appendix?.disclaimer ?? WAF_COMPLIANCE_AUDIT_DISCLAIMER}_`);
    for (const entry of payload.control_mapping_appendix?.entries ?? []) {
      lines.push(
        `- ${entry.framework}: ${entry.control_themes} (${entry.status})`,
      );
    }
  } else if (payload.report_kind === 'board_roadmap_brief') {
    lines.push(`_${payload.disclaimer ?? WAF_BOARD_ROADMAP_DISCLAIMER}_`);
    lines.push('', '## Executive summary');
    const coverage = payload.executive_summary?.coverage ?? {};
    lines.push(`- coverage_ratio: ${coverage.coverage_ratio ?? 0}`);
    const tierSummary = payload.executive_summary?.tier_summary ?? {};
    lines.push(`- tier_1_count: ${tierSummary.tier_1_count ?? 0}`);
    lines.push(`- tier_2_count: ${tierSummary.tier_2_count ?? 0}`);
    lines.push('', '## Investment phases');
    for (const phase of payload.investment_phases ?? []) {
      lines.push(
        `- ${phase.tier}: ${phase.rollout_window} (${phase.item_count} items) — ${phase.focus}`,
      );
    }
    lines.push('', '## Procurement justification');
    lines.push(payload.procurement_justification?.narrative ?? '');
    lines.push('', '## Tier 1 examples');
    for (const example of payload.procurement_justification?.tier_1_examples ?? []) {
      lines.push(
        `- ${example.canonical_url ?? example.waf_asset_id}: ${example.business_criticality ?? example.asset_kind ?? 'in_scope'}`,
      );
    }
    lines.push('', '## Roadmap reference');
    lines.push(`- api_path: ${payload.roadmap_reference?.api_path ?? '/v1/waf/coverage/risk-roadmap'}`);
    lines.push(`- method: ${payload.roadmap_reference?.method ?? 'waf_risk_v1'}`);
  }

  lines.push(
    '',
    '## Custody',
    `- artifact_id: ${custody.artifact_id}`,
    `- content_sha256: ${custody.content_sha256}`,
    `- canonicalization: ${custody.content_canonicalization}`,
    `- created_at: ${custody.created_at}`,
    `- previous_audit_hash: ${custody.previous_audit_hash ?? 'none'}`,
    `- previous_tenant_audit_hash: ${custody.previous_tenant_audit_hash ?? 'none'}`,
    '',
    '_Metadata-only export; credentials and raw traffic omitted._',
  );
  return lines.join('\n');
}

export function prepareWafReportExport(ctx, kind, format, payload, options = {}) {
  const exportFormat = format === 'markdown' ? 'markdown' : 'json';
  const redactedPayload = redactObject(payload);
  try {
    assertNoRawWafEvidence(redactedPayload);
  } catch (err) {
    return {
      error: err.code ?? 'invalid_request',
      status: err.status ?? 400,
      message: err.message,
    };
  }

  const custody = buildCustodyManifest({
    tenant_id: ctx.tenantId,
    artifact_type: 'waf_report_export',
    artifact_id: kind,
    format: exportFormat,
    created_by: ctx.userId,
    content: redactedPayload,
    subject_ids: collectWafReportSubjectIds(redactedPayload),
    previous_audit_hash: options.previousAuditHash ?? null,
    previous_tenant_audit_hash: options.previousTenantAuditHash ?? null,
  });

  if (exportFormat === 'markdown') {
    return {
      format: 'markdown',
      content: buildWafReportMarkdown(redactedPayload, custody),
      payload: redactedPayload,
      custody,
    };
  }
  return { format: 'json', payload: redactedPayload, custody };
}