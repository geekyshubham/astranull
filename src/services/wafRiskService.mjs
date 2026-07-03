export const WAF_RISK_METHOD = 'waf_risk_v1';

export const DEPLOYMENT_TIERS = Object.freeze(['tier_1', 'tier_2', 'tier_3', 'tier_4']);

const CRITICAL_BUSINESS_VALUES = new Set([
  'critical',
  'payment',
  'checkout',
  'pii',
  'auth',
  'admin',
  'internal_admin',
  'api',
  'high',
]);

const HIGH_TRAFFIC_VALUES = new Set(['high', 'very_high', 'critical']);

const REGULATORY_TAGS = new Set([
  'pci',
  'pci-dss',
  'hipaa',
  'gdpr',
  'soc2',
  'soc_2',
  'iso27001',
  'iso_27001',
  'nist',
]);

const OWASP_EXPOSURE_BY_KIND = Object.freeze({
  auth_portal: { class: 'authentication_surface', weight: 10 },
  login: { class: 'authentication_surface', weight: 10 },
  payment: { class: 'payment_pii_surface', weight: 10 },
  checkout: { class: 'payment_pii_surface', weight: 10 },
  admin: { class: 'administrative_surface', weight: 9 },
  internal_admin: { class: 'administrative_surface', weight: 9 },
  api: { class: 'machine_api_surface', weight: 8 },
  graphql: { class: 'machine_api_surface', weight: 8 },
  upload: { class: 'file_upload_surface', weight: 7 },
  file_exchange: { class: 'file_upload_surface', weight: 7 },
  search: { class: 'input_heavy_public_surface', weight: 6 },
  public_form: { class: 'input_heavy_public_surface', weight: 6 },
});

const PROTECTION_STATE_WEIGHTS = Object.freeze({
  unprotected: 28,
  underprotected: 18,
  unknown: 12,
  protected: 2,
  excluded: 0,
});

function clampScore(value) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function normalizeString(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function pushFactor(factors, factor, value, contribution) {
  if (!contribution) return;
  factors.push({
    factor,
    value: value == null ? null : String(value),
    contribution: Math.round(contribution),
  });
}

function protectionStateContribution(status) {
  return PROTECTION_STATE_WEIGHTS[status] ?? PROTECTION_STATE_WEIGHTS.unknown;
}

function validationContribution(summary = {}) {
  if (summary.origin_bypass_confirmed === true) return 0;
  if (summary.validation_failed === true) return 15;
  if (summary.validation_passed === true) return 0;
  if (summary.validation_passed === false) return 12;
  return 8;
}

function businessCriticalityContribution(value) {
  const normalized = normalizeString(value);
  if (['payment', 'checkout', 'pii', 'auth', 'admin', 'internal_admin'].includes(normalized)) {
    return 18;
  }
  if (['api', 'graphql', 'critical', 'high'].includes(normalized)) return 12;
  if (['medium'].includes(normalized)) return 6;
  if (['low', 'marketing', 'legacy'].includes(normalized)) return 2;
  return 6;
}

function trafficTierContribution(value) {
  const normalized = normalizeString(value);
  if (HIGH_TRAFFIC_VALUES.has(normalized)) return 12;
  if (normalized === 'medium') return 6;
  if (normalized === 'low') return 2;
  return 4;
}

function owaspExposureContribution(asset = {}) {
  const kind = normalizeString(asset.asset_kind);
  const mapped = OWASP_EXPOSURE_BY_KIND[kind];
  if (mapped) return mapped.weight;
  const tags = Array.isArray(asset.compliance_tags) ? asset.compliance_tags : [];
  for (const tag of tags) {
    const normalized = normalizeString(tag);
    if (normalized.includes('owasp') || normalized.includes('api') || normalized.includes('admin')) {
      return 5;
    }
  }
  return 0;
}

function regulatoryContribution(tags = []) {
  let contribution = 0;
  for (const tag of tags) {
    const normalized = normalizeString(tag).replace(/\s+/g, '_');
    if (REGULATORY_TAGS.has(normalized) || REGULATORY_TAGS.has(normalized.replace(/-/g, '_'))) {
      contribution = Math.max(contribution, 8);
    }
  }
  return contribution;
}

function hostingEnvironmentContribution(targetGroup = null) {
  if (!targetGroup) return 0;
  const settings = targetGroup.settings_json ?? {};
  const hosting = normalizeString(settings.hosting_environment ?? settings.hosting ?? '');
  if (['unknown', 'vendor_managed', 'subsidiary'].includes(hosting)) return 5;
  return 0;
}

function vulnerabilityContribution(matches = []) {
  if (!Array.isArray(matches) || matches.length === 0) return 0;
  let contribution = 0;
  for (const match of matches) {
    const status = normalizeString(match.validation_status ?? match.status);
    if (['resolved', 'not_relevant', 'not_exploitable'].includes(status)) continue;
    const score = Number(match.risk_score ?? 0);
    if (match.known_exploited === true || status === 'exposed') {
      contribution = Math.max(contribution, 15);
    } else if (score >= 70) {
      contribution = Math.max(contribution, 12);
    } else {
      contribution = Math.max(contribution, 8);
    }
  }
  return contribution;
}

function originBypassContribution(snapshot = {}, summary = {}) {
  const reasonCodes = new Set(snapshot.reason_codes ?? []);
  if (summary.origin_bypass_confirmed === true || reasonCodes.has('origin_bypass_confirmed')) {
    return 25;
  }
  return 0;
}

function deriveConfidence({ snapshot = {}, asset = {}, factors = [] }) {
  const sourceMix = snapshot.source_mix_json ?? snapshot.source_mix ?? {};
  let confidence = Number(snapshot.confidence ?? 0);
  if (!confidence) {
    const signals = [
      sourceMix.external,
      sourceMix.agent,
      sourceMix.connector,
      sourceMix.validation,
      sourceMix.cve,
    ].filter(Boolean).length;
    confidence = 0.45 + signals * 0.12;
  }
  if (factors.some((f) => f.factor === 'confidence_review')) {
    confidence = Math.min(confidence, 0.69);
  }
  return Math.max(0, Math.min(1, Math.round(confidence * 100) / 100));
}

export function deriveRecommendedAction({ factors = [], snapshot = {}, priorityBand = 'tier_3' } = {}) {
  const reasonCodes = new Set(snapshot.reason_codes ?? []);
  const factorNames = new Set(factors.map((f) => f.factor));
  if (factorNames.has('origin_bypass') || reasonCodes.has('origin_bypass_confirmed')) {
    return 'close_origin_bypass';
  }
  if (reasonCodes.has('policy_exception_active')) return 'approve_exception';
  if (snapshot.status === 'excluded') return 'approve_exception';
  if (snapshot.status === 'unprotected') return 'deploy_waf_blocking';
  if (
    reasonCodes.has('marker_rule_not_blocking')
    || reasonCodes.has('monitor_only_behavior')
    || reasonCodes.has('rule_mode_changed')
  ) {
    return 'fix_blocking_mode';
  }
  if (reasonCodes.has('rule_update_stale') || reasonCodes.has('rule_count_decreased')) {
    return 'refresh_rules';
  }
  if (priorityBand === 'tier_4') return 'approve_exception';
  if (snapshot.status === 'underprotected') return 'fix_blocking_mode';
  return 'deploy_waf';
}

export function assignPriorityBand({
  riskScore = 0,
  asset = {},
  snapshot = {},
  factors = [],
} = {}) {
  const status = snapshot.status ?? 'unknown';
  const criticality = normalizeString(asset.business_criticality);
  const traffic = normalizeString(asset.traffic_tier);
  const complianceTags = Array.isArray(asset.compliance_tags) ? asset.compliance_tags : [];
  const hasRegulatoryTag = complianceTags.some((tag) => {
    const normalized = normalizeString(tag).replace(/\s+/g, '_').replace(/-/g, '_');
    return REGULATORY_TAGS.has(normalized);
  });
  const originBypass = factors.some((f) => f.factor === 'origin_bypass')
    || (snapshot.reason_codes ?? []).includes('origin_bypass_confirmed');
  const validationFailed = factors.some(
    (f) => f.factor === 'validation_result' && Number(f.contribution) >= 12,
  );

  if (status === 'excluded' || (status === 'unknown' && !CRITICAL_BUSINESS_VALUES.has(criticality))) {
    return 'tier_4';
  }
  if (
    riskScore >= 75
    || originBypass
    || (status === 'unprotected' && CRITICAL_BUSINESS_VALUES.has(criticality))
  ) {
    return 'tier_1';
  }
  if (
    (riskScore >= 50 && riskScore <= 74)
    || (status === 'underprotected' && HIGH_TRAFFIC_VALUES.has(traffic))
    || (hasRegulatoryTag && validationFailed)
  ) {
    return 'tier_2';
  }
  if (riskScore >= 25 && riskScore <= 49) return 'tier_3';
  return 'tier_4';
}

/**
 * Deterministic 0-100 WAF posture risk with explainable factor contributions.
 */
export function computeAssetRiskAssessment(input = {}) {
  const asset = input.asset ?? {};
  const snapshot = input.snapshot ?? { status: asset.status ?? 'unknown' };
  const summary = input.validationSummary ?? {};
  const targetGroup = input.targetGroup ?? null;
  const cveMatches = Array.isArray(input.cveMatches) ? input.cveMatches : [];
  const computedAt = input.computedAt ?? new Date().toISOString();

  const factors = [];
  const status = snapshot.status ?? 'unknown';

  const protectionContribution = protectionStateContribution(status);
  pushFactor(factors, 'protection_state', status, protectionContribution);

  const validationWeight = validationContribution(summary);
  pushFactor(
    factors,
    'validation_result',
    summary.validation_passed === true
      ? 'passed'
      : summary.validation_failed === true
        ? 'failed'
        : 'inconclusive',
    validationWeight,
  );

  const bypassWeight = originBypassContribution(snapshot, summary);
  pushFactor(factors, 'origin_bypass', bypassWeight ? 'confirmed' : 'none', bypassWeight);

  const businessWeight = businessCriticalityContribution(asset.business_criticality);
  pushFactor(factors, 'business_criticality', asset.business_criticality ?? 'unknown', businessWeight);

  const trafficWeight = trafficTierContribution(asset.traffic_tier);
  pushFactor(factors, 'traffic_tier', asset.traffic_tier ?? 'unknown', trafficWeight);

  const vulnWeight = vulnerabilityContribution(cveMatches);
  if (vulnWeight) {
    pushFactor(factors, 'known_vulnerabilities', `${cveMatches.length}_open_matches`, vulnWeight);
  }

  const owaspWeight = owaspExposureContribution(asset);
  if (owaspWeight) {
    const exposureClass = OWASP_EXPOSURE_BY_KIND[normalizeString(asset.asset_kind)]?.class ?? 'declared_surface';
    pushFactor(factors, 'owasp_exposure', exposureClass, owaspWeight);
  }

  const hostingWeight = hostingEnvironmentContribution(targetGroup);
  if (hostingWeight) {
    const hosting = normalizeString(
      targetGroup?.settings_json?.hosting_environment ?? targetGroup?.settings_json?.hosting ?? 'unknown',
    );
    pushFactor(factors, 'hosting_environment', hosting || 'unknown', hostingWeight);
  }

  const regulatoryWeight = regulatoryContribution(asset.compliance_tags ?? []);
  if (regulatoryWeight) {
    pushFactor(factors, 'regulatory_scope', 'in_scope', regulatoryWeight);
  }

  const confidence = deriveConfidence({ snapshot, asset, factors });
  if (confidence < 0.7) {
    pushFactor(factors, 'confidence_review', 'low_confidence', 0);
  }

  const rawScore = factors.reduce((sum, factor) => sum + Number(factor.contribution ?? 0), 0);
  const riskScore = clampScore(rawScore);
  const priorityBand = assignPriorityBand({ riskScore, asset, snapshot, factors });
  const recommendedAction = deriveRecommendedAction({ factors, snapshot, priorityBand });

  return {
    waf_asset_id: asset.id ?? snapshot.waf_asset_id ?? null,
    risk_score: riskScore,
    priority_band: priorityBand,
    factors,
    confidence,
    recommended_action: recommendedAction,
    computed_at: computedAt,
    method: WAF_RISK_METHOD,
  };
}

export function enrichSnapshotWithRisk(snapshot, assessment) {
  if (!snapshot || !assessment) return snapshot;
  return {
    ...snapshot,
    risk_score: assessment.risk_score,
    risk_factors_json: assessment.factors,
    priority_band: assessment.priority_band,
    recommended_action: assessment.recommended_action,
    confidence: assessment.confidence ?? snapshot.confidence,
  };
}

export function hostnameFromCanonicalUrl(canonicalUrl) {
  if (typeof canonicalUrl !== 'string' || !canonicalUrl.trim()) return null;
  try {
    return new URL(canonicalUrl).hostname;
  } catch {
    const trimmed = canonicalUrl.trim();
    return trimmed.includes('/') ? trimmed.split('/')[0] : trimmed;
  }
}