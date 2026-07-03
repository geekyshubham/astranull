import { createHash } from 'node:crypto';
import { getCheckById } from './checks.mjs';
import { assertNoRawWafEvidence } from './wafPosture.mjs';

export const CVE_PIPELINE_STAGES = Object.freeze([
  'ingest',
  'triage',
  'match',
  'validate',
  'recommend',
  'ticket',
  'retest',
  'resolved',
]);

export const TRIAGE_FACTORS = Object.freeze([
  'known_exploited',
  'unauthenticated_remote',
  'internet_facing',
  'public_poc',
  'critical_asset',
  'protected_validation_pass',
  'underprotected',
  'low_version_confidence',
]);

export const MATCH_CONFIDENCE_LEVELS = Object.freeze({
  cnapp_cspm: 'high',
  sbom_cmdb: 'high',
  connector_metadata: 'medium_high',
  http_fingerprint: 'medium',
  header_banner: 'low_medium',
  keyword_guess: 'low',
});

export const RECOMMENDATION_TYPES = Object.freeze([
  'managed_rule_enable',
  'custom_rule_add',
  'mode_change',
  'origin_restrict',
  'rate_limit_adjust',
  'virtual_patch',
  'patch_required',
  'manual_review',
]);

export const SUPPORTED_VENDORS = Object.freeze([
  'cloudflare',
  'akamai',
  'aws',
  'azure',
  'gcp',
  'imperva',
  'fortinet',
  'generic',
]);

export const CVE_VALIDATION_STATUSES = Object.freeze([
  'pending',
  'validation_pending',
  'exposed',
  'not_exploitable',
  'inconclusive',
  'skipped',
]);

export const CVE_SAFE_VALIDATION_CHECK_ID = 'waf.fingerprint.safe';

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/i;
const SEVERITY_LEVELS = new Set(['critical', 'high', 'medium', 'low', 'none', 'unknown']);

const FORBIDDEN_CVE_PIPELINE_KEYS = Object.freeze([
  'exploit_code',
  'exploit_payload',
  'poc_code',
  'attack_script',
  'raw_response',
  'credentials',
  'tokens',
  'secrets',
]);

const FORBIDDEN_KEY_SET = new Set(FORBIDDEN_CVE_PIPELINE_KEYS);

const CONFIDENCE_NUMERIC = Object.freeze({
  cnapp_cspm: 0.9,
  sbom_cmdb: 0.85,
  connector_metadata: 0.72,
  http_fingerprint: 0.58,
  header_banner: 0.42,
  keyword_guess: 0.22,
});

const TRIAGE_OUTCOMES = new Set(['relevant', 'not_relevant', 'needs_review']);

const STAGE_INDEX = Object.fromEntries(CVE_PIPELINE_STAGES.map((s, i) => [s, i]));

const VENDOR_DEPLOYMENT_HINTS = Object.freeze({
  cloudflare: 'Use Cloudflare WAF managed rulesets or custom rules in the zone firewall.',
  akamai: 'Apply Kona Site Defender or App & API Protector policy updates in staging first.',
  aws: 'Tune AWS WAF web ACL managed rule groups or add scoped custom rules per resource.',
  azure: 'Update Azure Front Door or Application Gateway WAF policy in detection-then-block mode.',
  gcp: 'Adjust Cloud Armor security policies on the backend service or load balancer.',
  imperva: 'Enable or tune Imperva WAF security rules for the protected site profile.',
  fortinet: 'Update FortiWeb or FortiGate WAF policy objects for the virtual server.',
  generic: 'Apply vendor-equivalent managed or custom WAF rules on the declared asset scope.',
});

function normalizeKey(key) {
  return String(key)
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function parseBooleanDefault(value, fallback = false) {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'boolean') return value;
  if (value === '1' || value === 1 || value === 'true') return true;
  if (value === '0' || value === 0 || value === 'false') return false;
  return fallback;
}

function normalizeStringList(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((v) => String(v).trim()).filter(Boolean))];
}

function normalizeProductToken(value) {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9.+_-]+/g, ' ');
}

function collectForbiddenKeys(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return [];
  }
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenKeys(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeKey(key);
    if (FORBIDDEN_KEY_SET.has(normalized)) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenKeys(nested, keyPath));
  }
  return findings;
}

export function validateCvePipelineItem(item) {
  if (item === null || item === undefined || typeof item !== 'object' || Array.isArray(item)) {
    const err = new Error('CVE pipeline item must be a plain object.');
    err.code = 'invalid_cve_pipeline_item';
    throw err;
  }
  const forbidden = collectForbiddenKeys(item);
  if (forbidden.length > 0) {
    const err = new Error(`Forbidden CVE pipeline field: ${forbidden[0]}`);
    err.code = 'unsafe_cve_pipeline_item';
    err.forbidden_paths = forbidden;
    throw err;
  }
  try {
    assertNoRawWafEvidence(item);
  } catch (rawErr) {
    const err = new Error(rawErr.message);
    err.code = 'unsafe_cve_pipeline_item';
    throw err;
  }
  return true;
}

export function createCvePipelineItem(fields) {
  if (fields === null || fields === undefined || typeof fields !== 'object' || Array.isArray(fields)) {
    const err = new Error('CVE pipeline item input must be a plain object.');
    err.code = 'invalid_cve_pipeline_item';
    throw err;
  }
  validateCvePipelineItem(fields);

  const cve_id = typeof fields.cve_id === 'string' ? fields.cve_id.trim().toUpperCase() : '';
  if (!CVE_ID_PATTERN.test(cve_id)) {
    const err = new Error('cve_id must match CVE-YYYY-NNNN format.');
    err.code = 'invalid_cve_pipeline_item';
    throw err;
  }

  const severityRaw = typeof fields.severity === 'string' ? fields.severity.trim().toLowerCase() : 'unknown';
  const severity = SEVERITY_LEVELS.has(severityRaw) ? severityRaw : 'unknown';

  const affected_products = normalizeStringList(fields.affected_products);
  if (affected_products.length === 0) {
    const err = new Error('affected_products must include at least one product identifier.');
    err.code = 'invalid_cve_pipeline_item';
    throw err;
  }

  const stageRaw = typeof fields.stage === 'string' ? fields.stage.trim().toLowerCase() : 'ingest';
  const stage = CVE_PIPELINE_STAGES.includes(stageRaw) ? stageRaw : 'ingest';

  const vendor_advisories = normalizeStringList(fields.vendor_advisories);
  const created_at =
    typeof fields.created_at === 'string' && fields.created_at.trim()
      ? fields.created_at.trim()
      : new Date().toISOString();

  return {
    cve_id,
    severity,
    affected_products,
    known_exploited: parseBooleanDefault(fields.known_exploited, false),
    poc_indicator: parseBooleanDefault(fields.poc_indicator ?? fields.public_poc_signal, false),
    vendor_advisories,
    stage,
    created_at,
  };
}

function productMatchesToken(productTokens, needle) {
  const normalizedNeedle = normalizeProductToken(needle);
  if (!normalizedNeedle) return false;
  return productTokens.some((token) => {
    const normalizedToken = normalizeProductToken(token);
    return normalizedToken.includes(normalizedNeedle) || normalizedNeedle.includes(normalizedToken);
  });
}

function deriveTenantProducts(footprint = {}) {
  const products = new Set();
  for (const entry of footprint.products ?? footprint.technologies ?? []) {
    const token = normalizeProductToken(entry);
    if (token) products.add(token);
  }
  for (const asset of footprint.assets ?? []) {
    for (const field of [
      asset.platform_product,
      asset.detected_product,
      asset.tech_stack,
      asset.sbom_product,
      asset.http_fingerprint,
      asset.header_banner,
      ...(Array.isArray(asset.keyword_tags) ? asset.keyword_tags : []),
    ]) {
      if (Array.isArray(field)) {
        for (const item of field) {
          const token = normalizeProductToken(item);
          if (token) products.add(token);
        }
      } else {
        const token = normalizeProductToken(field);
        if (token) products.add(token);
      }
    }
  }
  return products;
}

function footprintHasInternetFacing(footprint) {
  if (parseBooleanDefault(footprint.internet_facing, false)) return true;
  return (footprint.assets ?? []).some((asset) => parseBooleanDefault(asset.internet_facing, true));
}

function footprintHasCriticalAsset(footprint) {
  const criticalTiers = new Set(['critical', 'high', 'pii', 'payment', 'admin']);
  if (criticalTiers.has(String(footprint.business_criticality ?? '').trim().toLowerCase())) {
    return true;
  }
  return (footprint.assets ?? []).some((asset) =>
    criticalTiers.has(String(asset.business_criticality ?? '').trim().toLowerCase()),
  );
}

function footprintPostureSummary(footprint) {
  const statuses = (footprint.assets ?? []).map((asset) =>
    String(asset.posture_status ?? asset.status ?? 'unknown').trim().toLowerCase(),
  );
  return {
    protected: statuses.some((s) => s === 'protected'),
    underprotected: statuses.some((s) => s === 'underprotected' || s === 'unprotected'),
  };
}

export function triageCveItem(item, tenantTechFootprint = {}) {
  validateCvePipelineItem(item);

  const productTokens = item.affected_products.map((p) => normalizeProductToken(p));
  const tenantProducts = deriveTenantProducts(tenantTechFootprint);
  const productOverlap = productTokens.some((token) =>
    [...tenantProducts].some((tp) => tp.includes(token) || token.includes(tp)),
  );

  const factors = {
    known_exploited: Boolean(item.known_exploited),
    unauthenticated_remote: parseBooleanDefault(
      tenantTechFootprint.unauthenticated_remote ?? item.unauthenticated_remote,
      false,
    ),
    internet_facing: footprintHasInternetFacing(tenantTechFootprint),
    public_poc: Boolean(item.poc_indicator),
    critical_asset: footprintHasCriticalAsset(tenantTechFootprint),
    protected_validation_pass: footprintPostureSummary(tenantTechFootprint).protected,
    underprotected: footprintPostureSummary(tenantTechFootprint).underprotected,
    low_version_confidence: parseBooleanDefault(tenantTechFootprint.low_version_confidence, false),
  };

  let score = 0;
  if (factors.known_exploited) score += 30;
  if (factors.unauthenticated_remote) score += 20;
  if (factors.internet_facing) score += 15;
  if (factors.public_poc) score += 10;
  if (factors.critical_asset) score += 15;
  if (factors.underprotected) score += 12;
  if (factors.protected_validation_pass) score -= 8;
  if (factors.low_version_confidence) score -= 5;

  let outcome = 'not_relevant';
  if (!productOverlap && score < 20) {
    outcome = 'not_relevant';
  } else if (factors.low_version_confidence || (!productOverlap && score >= 20)) {
    outcome = 'needs_review';
  } else if (productOverlap && score >= 25) {
    outcome = 'relevant';
  } else if (productOverlap) {
    outcome = 'needs_review';
  }

  if (!TRIAGE_OUTCOMES.has(outcome)) {
    outcome = 'needs_review';
  }

  return {
    outcome,
    score,
    product_overlap: productOverlap,
    factors,
    summary:
      outcome === 'relevant'
        ? 'CVE affects tenant technology footprint with elevated exposure signals.'
        : outcome === 'needs_review'
          ? 'CVE may be relevant; confirm product/version mapping before matching assets.'
          : 'CVE does not appear relevant to the declared tenant technology footprint.',
  };
}

function assetMatchCandidate(item, asset) {
  const productTokens = item.affected_products.map((p) => normalizeProductToken(p));
  const candidates = [];

  const cnappFindings = Array.isArray(asset.cnapp_findings) ? asset.cnapp_findings : [];
  for (const finding of cnappFindings) {
    const cveRef = typeof finding.cve_id === 'string' ? finding.cve_id.trim().toUpperCase() : '';
    const productRef = normalizeProductToken(finding.product ?? finding.affected_product);
    if (cveRef === item.cve_id || productTokens.some((t) => productRef && (t.includes(productRef) || productRef.includes(t)))) {
      candidates.push({
        source: 'cnapp_cspm',
        confidence_level: MATCH_CONFIDENCE_LEVELS.cnapp_cspm,
        match_confidence: CONFIDENCE_NUMERIC.cnapp_cspm,
        match_reasons: [
          cveRef === item.cve_id
            ? `CNAPP/CSPM vulnerability record references ${item.cve_id}.`
            : `CNAPP/CSPM product mapping aligns with affected product metadata.`,
        ],
        requires_review: false,
      });
    }
  }

  const sbomProducts = Array.isArray(asset.sbom_products) ? asset.sbom_products : [];
  for (const sbom of sbomProducts) {
    const productRef = normalizeProductToken(sbom.product ?? sbom.name);
    const versionRef = normalizeProductToken(sbom.version);
    if (productTokens.some((t) => productRef && (t.includes(productRef) || productRef.includes(t)))) {
      candidates.push({
        source: 'sbom_cmdb',
        confidence_level: MATCH_CONFIDENCE_LEVELS.sbom_cmdb,
        match_confidence: CONFIDENCE_NUMERIC.sbom_cmdb,
        match_reasons: [
          versionRef
            ? `SBOM/CMDB declares ${sbom.product ?? sbom.name} version ${sbom.version}.`
            : `SBOM/CMDB declares ${sbom.product ?? sbom.name} without a confident version pin.`,
        ],
        requires_review: !versionRef,
      });
    }
  }

  const connectorMeta = asset.connector_metadata && typeof asset.connector_metadata === 'object'
    ? asset.connector_metadata
    : {};
  const connectorProduct = normalizeProductToken(
    connectorMeta.platform_product ?? connectorMeta.product ?? connectorMeta.app_platform,
  );
  if (connectorProduct && productTokens.some((t) => t.includes(connectorProduct) || connectorProduct.includes(t))) {
    candidates.push({
      source: 'connector_metadata',
      confidence_level: MATCH_CONFIDENCE_LEVELS.connector_metadata,
      match_confidence: CONFIDENCE_NUMERIC.connector_metadata,
      match_reasons: ['Connector metadata platform/product aligns with CVE affected product.'],
      requires_review: false,
    });
  }

  const fingerprint = normalizeProductToken(asset.http_fingerprint ?? asset.tech_fingerprint);
  if (fingerprint && productTokens.some((t) => t.includes(fingerprint) || fingerprint.includes(t))) {
    candidates.push({
      source: 'http_fingerprint',
      confidence_level: MATCH_CONFIDENCE_LEVELS.http_fingerprint,
      match_confidence: CONFIDENCE_NUMERIC.http_fingerprint,
      match_reasons: ['HTTP technology fingerprint suggests a possible product match; confirm version separately.'],
      requires_review: true,
    });
  }

  const banner = normalizeProductToken(asset.header_banner ?? asset.server_banner);
  if (banner && productTokens.some((t) => t.includes(banner) || banner.includes(t))) {
    candidates.push({
      source: 'header_banner',
      confidence_level: MATCH_CONFIDENCE_LEVELS.header_banner,
      match_confidence: CONFIDENCE_NUMERIC.header_banner,
      match_reasons: ['Header/banner hint is broad; treat as weak evidence pending validation.'],
      requires_review: true,
    });
  }

  const keywordTags = Array.isArray(asset.keyword_tags) ? asset.keyword_tags : [];
  for (const tag of keywordTags) {
    const tagToken = normalizeProductToken(tag);
    if (tagToken && productTokens.some((t) => t.includes(tagToken) || tagToken.includes(t))) {
      candidates.push({
        source: 'keyword_guess',
        confidence_level: MATCH_CONFIDENCE_LEVELS.keyword_guess,
        match_confidence: CONFIDENCE_NUMERIC.keyword_guess,
        match_reasons: ['Keyword/tag guess only; human review required before exposure claims.'],
        requires_review: true,
      });
      break;
    }
  }

  if (candidates.length === 0) return null;

  candidates.sort((a, b) => b.match_confidence - a.match_confidence);
  return candidates[0];
}

export function matchCveToAssets(item, assets = []) {
  validateCvePipelineItem(item);
  if (!Array.isArray(assets)) {
    const err = new Error('assets must be an array.');
    err.code = 'invalid_cve_pipeline_item';
    throw err;
  }

  const cve_asset_matches = [];
  for (const asset of assets) {
    if (!asset || typeof asset !== 'object') continue;
    const best = assetMatchCandidate(item, asset);
    if (!best) continue;

    const exposure_claim_allowed = best.confidence_level === 'high' || best.confidence_level === 'medium_high';

    cve_asset_matches.push({
      waf_asset_id: asset.id ?? asset.waf_asset_id ?? null,
      asset_display: asset.canonical_url ?? asset.hostname ?? asset.id ?? 'declared asset',
      match_source: best.source,
      confidence_level: best.confidence_level,
      match_confidence: best.match_confidence,
      match_reasons: best.match_reasons,
      requires_review: best.requires_review,
      exposure_claim_allowed,
      validation_status: exposure_claim_allowed ? 'pending' : 'inconclusive',
    });
  }

  return cve_asset_matches;
}

function resolveRecommendationType(match, item) {
  if (match.requires_review || match.confidence_level === 'low') {
    return 'manual_review';
  }
  if (item.known_exploited && match.confidence_level === 'high') {
    return 'virtual_patch';
  }
  if (match.confidence_level === 'medium' || match.confidence_level === 'low_medium') {
    return 'managed_rule_enable';
  }
  return 'managed_rule_enable';
}

export function buildWafRuleRecommendation(match, vendor, item = {}) {
  if (!match || typeof match !== 'object') {
    const err = new Error('match is required to build a WAF rule recommendation.');
    err.code = 'invalid_cve_pipeline_item';
    throw err;
  }
  const vendorKey = String(vendor ?? 'generic').trim().toLowerCase();
  if (!SUPPORTED_VENDORS.includes(vendorKey)) {
    const err = new Error(`Unsupported WAF vendor: ${vendor || '(empty)'}`);
    err.code = 'invalid_cve_pipeline_item';
    throw err;
  }

  const cve_id = typeof item.cve_id === 'string' ? item.cve_id : 'unknown';
  const recommendation_type = resolveRecommendationType(match, item);
  const vendorHint = VENDOR_DEPLOYMENT_HINTS[vendorKey];

  const action_summary =
    recommendation_type === 'manual_review'
      ? 'Escalate to a security engineer for human review before any WAF change.'
      : recommendation_type === 'virtual_patch'
        ? 'Enable or tune a blocking managed/custom WAF rule as a temporary mitigation while patching proceeds.'
        : 'Enable or tune the relevant managed WAF ruleset for the matched vulnerable technology.';

  return {
    vendor: vendorKey,
    recommendation_type,
    asset: match.asset_display ?? 'declared asset',
    cve_id,
    why:
      match.exposure_claim_allowed
        ? 'Matched vulnerable technology with supported confidence and declared internet exposure context.'
        : 'Possible technology alignment detected; validate relevance before blocking changes.',
    action_summary,
    deployment_notes: [
      vendorHint,
      'Review in staging or with vendor simulation before production enforcement.',
      'Apply only to listed hostnames/paths for the matched asset.',
      'Monitor false positives and keep a rollback path to the prior policy version.',
    ],
    validation_plan:
      'Rerun AstraNull WAF marker/CVE-safe validation after deployment to confirm blocking behavior.',
    rollback_plan:
      'Revert to the previous WAF policy or rule version, or disable the custom rule if business impact occurs.',
  };
}

export function assertValidStageTransition(currentStage, nextStage) {
  const current = String(currentStage ?? 'ingest').trim().toLowerCase();
  const next = String(nextStage ?? '').trim().toLowerCase();

  if (!CVE_PIPELINE_STAGES.includes(next)) {
    const err = new Error(`Unsupported pipeline stage: ${nextStage}`);
    err.code = 'invalid_cve_pipeline_stage';
    throw err;
  }
  if (!CVE_PIPELINE_STAGES.includes(current)) {
    const err = new Error(`Unsupported pipeline stage: ${currentStage}`);
    err.code = 'invalid_cve_pipeline_stage';
    throw err;
  }

  const currentIdx = STAGE_INDEX[current];
  const nextIdx = STAGE_INDEX[next];

  if (nextIdx === currentIdx) return next;
  if (next === 'resolved' && nextIdx > currentIdx) return next;
  if (nextIdx === currentIdx + 1) return next;

  const err = new Error(`Invalid stage transition from ${current} to ${next}.`);
  err.code = 'invalid_cve_pipeline_stage';
  throw err;
}

function boundedProbeLimit(value, fallback, max) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) return fallback;
  return Math.min(parsed, max);
}

export function resolveSafeCveValidationCheck(item, match) {
  validateCvePipelineItem(item);
  if (!match || typeof match !== 'object') {
    const err = new Error('CVE asset match is required to resolve a safe validation check.');
    err.code = 'invalid_cve_pipeline_item';
    throw err;
  }
  if (match.validation_status === 'inconclusive' || match.validation_status === 'skipped') {
    return null;
  }
  if (!match.exposure_claim_allowed) {
    return null;
  }
  const check = getCheckById(CVE_SAFE_VALIDATION_CHECK_ID);
  if (!check) {
    const err = new Error(`Safe CVE validation check is unavailable: ${CVE_SAFE_VALIDATION_CHECK_ID}`);
    err.code = 'cve_validation_check_unavailable';
    throw err;
  }
  return CVE_SAFE_VALIDATION_CHECK_ID;
}

export function assertCveSafeValidationAllowed(item, match, body = {}) {
  validateCvePipelineItem(item);
  if (match === null || match === undefined || typeof match !== 'object' || Array.isArray(match)) {
    const err = new Error('CVE asset match is required for safe validation.');
    err.code = 'invalid_cve_pipeline_item';
    throw err;
  }
  const forbidden = collectForbiddenKeys(body);
  if (forbidden.length > 0) {
    const err = new Error(`Forbidden CVE validation field: ${forbidden[0]}`);
    err.code = 'unsafe_cve_pipeline_item';
    err.forbidden_paths = forbidden;
    throw err;
  }
  try {
    assertNoRawWafEvidence(body);
  } catch (rawErr) {
    const err = new Error(rawErr.message);
    err.code = 'unsafe_cve_pipeline_item';
    throw err;
  }

  if (match.validation_status === 'inconclusive' || match.validation_status === 'skipped') {
    const err = new Error('CVE asset match is not eligible for safe validation.');
    err.code = 'cve_validation_not_applicable';
    throw err;
  }

  const socApproved = parseBooleanDefault(body.soc_approved, false);
  if (item.known_exploited && match.requires_review && !socApproved) {
    const err = new Error(
      'Known-exploited CVE matches requiring review need SOC approval before safe validation.',
    );
    err.code = 'cve_validation_soc_gated';
    throw err;
  }

  if (body.risk_class === 'soc_gated' || body.risk_class === 'prohibited') {
    const err = new Error('soc_gated and prohibited validations require SOC workflow.');
    err.code = 'unsafe_waf_profile';
    throw err;
  }

  return true;
}

export function buildSafeCveValidationRequest(item, match, asset = {}) {
  assertCveSafeValidationAllowed(item, match);
  const checkId = resolveSafeCveValidationCheck(item, match);
  if (!checkId) {
    const err = new Error('CVE asset match does not qualify for safe validation.');
    err.code = 'cve_validation_not_applicable';
    throw err;
  }

  const check = getCheckById(checkId);
  const probe = check?.probe_profile && typeof check.probe_profile === 'object' ? check.probe_profile : {};
  const wafAssetId = match.waf_asset_id ?? asset.id ?? asset.waf_asset_id ?? null;
  if (!wafAssetId) {
    const err = new Error('CVE asset match requires a bound waf_asset_id.');
    err.code = 'invalid_cve_pipeline_item';
    throw err;
  }

  return {
    waf_asset_id: wafAssetId,
    modes: ['fingerprint'],
    probe_profile: {
      max_requests: boundedProbeLimit(probe.max_requests, 3, 3),
      timeout_ms: boundedProbeLimit(probe.timeout_ms, 5000, 5000),
      risk_class: 'safe',
    },
    marker_profile: {
      marker_type: 'header',
      expected_action: 'log_only_expected',
    },
  };
}

export function buildCveValidationEvidenceBinding(item, match, validationRun, checkId) {
  validateCvePipelineItem(item);
  return {
    cve_id: item.cve_id,
    cve_pipeline_item_id: item.id ?? match.cve_pipeline_item_id ?? null,
    cve_asset_match_id: match.id ?? null,
    waf_asset_id: match.waf_asset_id ?? null,
    waf_validation_run_id: validationRun?.id ?? null,
    check_id: checkId,
    match_confidence: match.match_confidence ?? null,
    confidence_level: match.confidence_level ?? null,
    validation_status: 'validation_pending',
    bound_at: new Date().toISOString(),
  };
}

export const CVE_DEPLOYED_RECOMMENDATION_STATUSES = Object.freeze([
  'deployed',
  'deployed_external',
  'retest_pending',
]);

export const CVE_RETEST_PIPELINE_STAGES = Object.freeze(['ticket', 'retest']);

const CVE_RETEST_CLOSURE_STATUSES = new Set(['not_exploitable', 'skipped', 'inconclusive']);

export function isCveRecommendationDeployed(recommendation) {
  if (!recommendation || typeof recommendation !== 'object') return false;
  const status = String(recommendation.approval_status ?? '').trim().toLowerCase();
  return CVE_DEPLOYED_RECOMMENDATION_STATUSES.includes(status);
}

export function assertCvePostMitigationRetestAllowed(item, match, recommendation, body = {}) {
  validateCvePipelineItem(item);
  if (match === null || match === undefined || typeof match !== 'object' || Array.isArray(match)) {
    const err = new Error('CVE asset match is required for post-mitigation retest.');
    err.code = 'invalid_cve_pipeline_item';
    throw err;
  }
  if (!recommendation || typeof recommendation !== 'object') {
    const err = new Error('Deployed WAF rule recommendation is required for post-mitigation retest.');
    err.code = 'cve_deployed_recommendation_required';
    throw err;
  }
  if (!isCveRecommendationDeployed(recommendation)) {
    const err = new Error('Recommendation must be marked deployed before post-mitigation retest.');
    err.code = 'cve_deployed_recommendation_required';
    throw err;
  }

  const forbidden = collectForbiddenKeys(body);
  if (forbidden.length > 0) {
    const err = new Error(`Forbidden CVE retest field: ${forbidden[0]}`);
    err.code = 'unsafe_cve_pipeline_item';
    err.forbidden_paths = forbidden;
    throw err;
  }
  try {
    assertNoRawWafEvidence(body);
  } catch (rawErr) {
    const err = new Error(rawErr.message);
    err.code = 'unsafe_cve_pipeline_item';
    throw err;
  }

  const socApproved = parseBooleanDefault(body.soc_approved, false);
  if (item.known_exploited && match.requires_review && !socApproved) {
    const err = new Error(
      'Known-exploited CVE matches requiring review need SOC approval before post-mitigation retest.',
    );
    err.code = 'cve_validation_soc_gated';
    throw err;
  }

  if (body.risk_class === 'soc_gated' || body.risk_class === 'prohibited') {
    const err = new Error('soc_gated and prohibited validations require SOC workflow.');
    err.code = 'unsafe_waf_profile';
    throw err;
  }

  return true;
}

export function buildCvePostMitigationRetestRequest(item, match, asset = {}, recommendation = {}) {
  assertCvePostMitigationRetestAllowed(item, match, recommendation);
  const checkId = resolveSafeCveValidationCheck(item, match);
  if (!checkId) {
    const err = new Error('CVE asset match does not qualify for post-mitigation retest.');
    err.code = 'cve_validation_not_applicable';
    throw err;
  }

  const check = getCheckById(checkId);
  const probe = check?.probe_profile && typeof check.probe_profile === 'object' ? check.probe_profile : {};
  const wafAssetId = match.waf_asset_id ?? asset.id ?? asset.waf_asset_id ?? null;
  if (!wafAssetId) {
    const err = new Error('CVE asset match requires a bound waf_asset_id.');
    err.code = 'invalid_cve_pipeline_item';
    throw err;
  }

  return {
    waf_asset_id: wafAssetId,
    modes: ['fingerprint'],
    probe_profile: {
      max_requests: boundedProbeLimit(probe.max_requests, 3, 3),
      timeout_ms: boundedProbeLimit(probe.timeout_ms, 5000, 5000),
      risk_class: 'safe',
    },
    marker_profile: {
      marker_type: 'header',
      expected_action: 'block',
    },
  };
}

export function buildCveRetestEvidenceBinding(item, match, validationRun, checkId, recommendation = {}) {
  const base = buildCveValidationEvidenceBinding(item, match, validationRun, checkId);
  return {
    ...base,
    retest_phase: 'post_mitigation',
    waf_rule_recommendation_id: recommendation.id ?? null,
    recommendation_type: recommendation.recommendation_type ?? null,
    validation_status: 'retest_pending',
  };
}

export function deriveCveRetestOutcomeFromValidationRun(validationRun) {
  if (!validationRun || validationRun.status !== 'finalized') {
    return {
      status: 'retest_pending',
      closure_ready: false,
      verdict: null,
    };
  }

  const summary = validationRun.summary_json && typeof validationRun.summary_json === 'object'
    ? validationRun.summary_json
    : {};
  if (summary.validation_passed === true || summary.posture_status === 'protected') {
    return {
      status: 'not_exploitable',
      closure_ready: true,
      verdict: 'mitigated',
    };
  }
  if (summary.validation_failed === true || summary.posture_status === 'underprotected') {
    return {
      status: 'exposed',
      closure_ready: true,
      verdict: 'persistent_exposure',
    };
  }
  return {
    status: 'inconclusive',
    closure_ready: true,
    verdict: 'inconclusive',
  };
}

export function resolveCvePipelineRetestClosure(matchOutcomes = []) {
  if (!Array.isArray(matchOutcomes) || matchOutcomes.length === 0) {
    return {
      ready: false,
      resolved_match_count: 0,
      pending_match_count: 0,
      open_match_count: 0,
      verdict: null,
    };
  }

  let resolved_match_count = 0;
  let pending_match_count = 0;
  let open_match_count = 0;

  for (const outcome of matchOutcomes) {
    if (!outcome?.closure_ready) {
      pending_match_count += 1;
      continue;
    }
    if (outcome.status === 'not_exploitable') {
      resolved_match_count += 1;
      continue;
    }
    if (CVE_RETEST_CLOSURE_STATUSES.has(outcome.status)) {
      resolved_match_count += 1;
      continue;
    }
    open_match_count += 1;
  }

  const ready = pending_match_count === 0 && open_match_count === 0 && resolved_match_count > 0;
  let verdict = null;
  if (ready) {
    verdict = 'resolved';
  } else if (pending_match_count > 0) {
    verdict = 'retest_pending';
  } else if (open_match_count > 0) {
    verdict = 'keep_open';
  }

  return {
    ready,
    resolved_match_count,
    pending_match_count,
    open_match_count,
    verdict,
  };
}

export const CVE_PLAYBOOK_STATUSES = Object.freeze([
  'draft',
  'approved',
  'retest_pending',
  'resolved',
  'accepted_risk',
]);

const VENDOR_DEPLOYMENT_ORDER = Object.fromEntries(
  SUPPORTED_VENDORS.map((vendor, index) => [vendor, index + 1]),
);

export function resolveVendorDeploymentOrder(vendor) {
  const key = String(vendor ?? 'generic').trim().toLowerCase();
  return VENDOR_DEPLOYMENT_ORDER[key] ?? 99;
}

export function hostnameScopeHash(assetDisplay) {
  const raw = String(assetDisplay ?? '').trim().toLowerCase();
  if (!raw) return null;
  try {
    const hostname = new URL(raw).hostname.toLowerCase();
    return createHash('sha256').update(hostname).digest('hex');
  } catch {
    return createHash('sha256').update(raw).digest('hex');
  }
}

function recommendationActionSummary(recommendation) {
  const payload = recommendation?.recommendation_json ?? recommendation?.recommendation ?? {};
  if (typeof payload.action_summary === 'string' && payload.action_summary.trim()) {
    return payload.action_summary.trim();
  }
  return `Deploy vendor-specific WAF mitigations for ${recommendation?.vendor ?? 'generic'}.`;
}

export function groupRecommendationsIntoVendorSlices(recommendations = [], matches = []) {
  if (!Array.isArray(recommendations)) {
    const err = new Error('recommendations must be an array.');
    err.code = 'invalid_cve_playbook';
    throw err;
  }
  const matchById = new Map(matches.map((match) => [match.id, match]));
  const byVendor = new Map();

  for (const recommendation of recommendations) {
    const vendor = String(recommendation.vendor ?? 'generic').trim().toLowerCase();
    const slice = byVendor.get(vendor) ?? {
      vendor,
      recommendation_ids: [],
      asset_ids: new Set(),
      action_summaries: [],
      hostname_scope_hashes: new Set(),
    };
    slice.recommendation_ids.push(recommendation.id);
    if (recommendation.waf_asset_id) {
      slice.asset_ids.add(recommendation.waf_asset_id);
    }
    const linkedMatch = matchById.get(recommendation.cve_asset_match_id);
    if (linkedMatch?.asset_display) {
      const hash = hostnameScopeHash(linkedMatch.asset_display);
      if (hash) slice.hostname_scope_hashes.add(hash);
    }
    slice.action_summaries.push(recommendationActionSummary(recommendation));
    byVendor.set(vendor, slice);
  }

  return [...byVendor.values()]
    .map((slice) => ({
      vendor: slice.vendor,
      asset_count: slice.asset_ids.size || slice.recommendation_ids.length,
      recommendation_ids: [...new Set(slice.recommendation_ids.filter(Boolean))],
      deployment_order: resolveVendorDeploymentOrder(slice.vendor),
      action_summary: slice.action_summaries[0],
      hostname_scope_hashes: [...slice.hostname_scope_hashes],
      child_action_item_id: slice.child_action_item_id ?? null,
    }))
    .sort((left, right) => left.deployment_order - right.deployment_order);
}

export function buildCveMitigationPlaybook(pipelineItem, recommendations = [], matches = [], existing = null) {
  validateCvePipelineItem(pipelineItem);
  const vendor_slices = groupRecommendationsIntoVendorSlices(recommendations, matches);
  if (vendor_slices.length === 0) {
    const err = new Error('At least one WAF rule recommendation is required to build a mitigation playbook.');
    err.code = 'cve_playbook_recommendations_required';
    throw err;
  }

  const affected_asset_count = new Set(
    recommendations.map((rec) => rec.waf_asset_id).filter(Boolean),
  ).size || matches.length;

  return {
    playbook_id: existing?.playbook_id ?? null,
    cve_id: pipelineItem.cve_id,
    pipeline_item_id: pipelineItem.id,
    severity: pipelineItem.severity ?? 'unknown',
    known_exploited: pipelineItem.known_exploited ?? false,
    affected_asset_count,
    vendor_slices,
    coordinated_retest_plan_id: existing?.coordinated_retest_plan_id ?? pipelineItem.id,
    status: existing?.status ?? 'draft',
    human_approval_required: true,
    parent_action_item_id: existing?.parent_action_item_id ?? null,
    approved_at: existing?.approved_at ?? null,
    approval_note: existing?.approval_note ?? null,
    created_at: existing?.created_at ?? null,
    updated_at: null,
  };
}

export function assertCvePlaybookApprovable(playbook, pipelineItem) {
  if (!playbook || typeof playbook !== 'object') {
    const err = new Error('CVE mitigation playbook is required.');
    err.code = 'invalid_cve_playbook';
    throw err;
  }
  validateCvePipelineItem(pipelineItem);
  if (!CVE_PLAYBOOK_STATUSES.includes(playbook.status)) {
    const err = new Error(`Unsupported playbook status: ${playbook.status}`);
    err.code = 'invalid_cve_playbook';
    throw err;
  }
  if (playbook.status !== 'draft') {
    const err = new Error('Only draft playbooks can be approved.');
    err.code = 'cve_playbook_not_approvable';
    throw err;
  }
  if (!Array.isArray(playbook.vendor_slices) || playbook.vendor_slices.length === 0) {
    const err = new Error('Playbook must include at least one vendor slice.');
    err.code = 'cve_playbook_recommendations_required';
    throw err;
  }
  return true;
}

export function assertCvePlaybookCoordinatedRetestAllowed(playbook) {
  if (!playbook || typeof playbook !== 'object') {
    const err = new Error('CVE mitigation playbook is required.');
    err.code = 'invalid_cve_playbook';
    throw err;
  }
  if (!['approved', 'retest_pending'].includes(playbook.status)) {
    const err = new Error('Coordinated retest requires an approved playbook.');
    err.code = 'cve_playbook_not_approved';
    throw err;
  }
  return true;
}

export function buildPlaybookVendorChecklist(playbook) {
  return (playbook.vendor_slices ?? []).map((slice) => ({
    vendor: slice.vendor,
    deployment_order: slice.deployment_order,
    asset_count: slice.asset_count,
    action_summary: slice.action_summary,
  }));
}

export function buildPlaybookParentActionItem(playbook, pipelineItemId, actionItemId) {
  const vendorCount = playbook.vendor_slices.length;
  const checklist = buildPlaybookVendorChecklist(playbook);
  const retestPath = `/v1/waf/cve-pipeline/${pipelineItemId}/coordinated-retest`;

  return {
    action_item_id: actionItemId,
    category: 'cve_mitigation',
    title: `CVE mitigation playbook: ${playbook.cve_id} (${vendorCount} vendor${vendorCount === 1 ? '' : 's'}, ${playbook.affected_asset_count} assets)`,
    asset: {
      display: `${playbook.cve_id} multi-vendor playbook`,
    },
    owner: 'security-operations',
    severity: ['critical', 'high', 'medium', 'low'].includes(playbook.severity) ? playbook.severity : 'high',
    evidence: {
      summary: [
        `Coordinated CVE mitigation playbook for ${playbook.cve_id}.`,
        `Known exploited: ${playbook.known_exploited ? 'yes' : 'no'}.`,
        `Vendor slices: ${vendorCount}.`,
        'Deploy mitigations per vendor console using the ordered checklist below.',
      ].join(' '),
      links: [
        {
          type: 'playbook',
          url: `/v1/waf/cve-pipeline/${pipelineItemId}/playbook`,
          label: 'CVE mitigation playbook',
        },
        {
          type: 'retest',
          url: retestPath,
          label: 'Coordinated retest endpoint',
        },
      ],
      vendor_checklist: checklist,
      playbook_id: playbook.playbook_id,
      pipeline_item_id: pipelineItemId,
      known_exploited: playbook.known_exploited === true,
    },
    recommended_solution: checklist
      .map((entry) => `${entry.deployment_order}. ${entry.vendor}: ${entry.action_summary}`)
      .join(' '),
    retest_url: retestPath,
    status: 'open',
    dedupe_key: `cve_playbook:${playbook.playbook_id}:parent`,
    playbook_id: playbook.playbook_id,
    cve_pipeline_item_id: pipelineItemId,
    waf_asset_id: `cve_playbook:${pipelineItemId}`,
    primary_reason: 'cve_mitigation_parent',
  };
}

export function buildPlaybookChildActionItem(playbook, slice, pipelineItemId, actionItemId, parentActionItemId) {
  const retestPath = `/v1/waf/cve-pipeline/${pipelineItemId}/coordinated-retest`;
  return {
    action_item_id: actionItemId,
    category: 'cve_mitigation',
    title: `${playbook.cve_id}: ${slice.vendor} mitigation (${slice.asset_count} asset${slice.asset_count === 1 ? '' : 's'})`,
    asset: {
      display: `${slice.vendor} vendor slice`,
    },
    owner: 'security-operations',
    severity: ['critical', 'high', 'medium', 'low'].includes(playbook.severity) ? playbook.severity : 'high',
    evidence: {
      summary: [
        `Vendor slice ${slice.deployment_order} for ${playbook.cve_id}.`,
        slice.action_summary,
        'Hostname scope is represented by metadata-only SHA-256 hashes only.',
      ].join(' '),
      links: [
        {
          type: 'playbook',
          url: `/v1/waf/cve-pipeline/${pipelineItemId}/playbook`,
          label: 'Parent CVE playbook',
        },
      ],
      hostname_scope_hashes: slice.hostname_scope_hashes ?? [],
      vendor: slice.vendor,
      recommendation_ids: slice.recommendation_ids ?? [],
      playbook_id: playbook.playbook_id,
      pipeline_item_id: pipelineItemId,
    },
    recommended_solution: slice.action_summary,
    retest_url: retestPath,
    status: 'open',
    dedupe_key: `cve_playbook:${playbook.playbook_id}:${slice.vendor}`,
    playbook_id: playbook.playbook_id,
    parent_action_item_id: parentActionItemId,
    cve_pipeline_item_id: pipelineItemId,
    waf_asset_id: `cve_playbook:${pipelineItemId}:${slice.vendor}`,
    primary_reason: `cve_mitigation_vendor:${slice.vendor}`,
  };
}

export function resolvePlaybookStatusFromRetestClosure(closure, currentStatus = 'approved') {
  if (closure?.ready) {
    return 'resolved';
  }
  if (currentStatus === 'approved') {
    return 'retest_pending';
  }
  return currentStatus;
}