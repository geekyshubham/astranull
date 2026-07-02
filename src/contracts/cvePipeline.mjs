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