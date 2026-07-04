import { validateProductionReleaseEvidence } from './productionReleaseEvidence.mjs';

export const EXTERNAL_VERIFICATION_TIERS = Object.freeze([
  'unverified',
  'metadata_only',
  'live_external',
]);

export const EXTERNAL_VERIFICATION_MANIFEST_REQUIRED_FIELDS = Object.freeze([
  'tier',
  'custody_uri',
  'verified_at',
  'operator_reference',
]);

export const EXTERNAL_VERIFICATION_DOMAINS = Object.freeze([
  Object.freeze({
    id: 'enterprise_idp_mfa',
    label: 'Enterprise IdP/SSO tenant-role mapping and MFA policy',
    evidence_kinds: ['oidc_prod_auth_preflight'],
  }),
  Object.freeze({
    id: 'kms_hsm_custody',
    label: 'KMS/HSM secret custody, rotation drill, and break-glass procedure',
    evidence_kinds: ['kms_vault_posture'],
  }),
  Object.freeze({
    id: 'notification_provider_credentials',
    label: 'Encrypted notification provider credentials and live delivery drill',
    evidence_kinds: ['notification_provider_config'],
  }),
  Object.freeze({
    id: 'artifact_pinned_deploy_rollback',
    label: 'Artifact-pinned control-plane deploy and rollback checkpoint',
    evidence_kinds: ['control_plane_container_release', 'rollback_fixforward'],
  }),
  Object.freeze({
    id: 'retained_security_legal_soc',
    label: 'Retained independent security, legal/compliance, and SOC artifacts',
    evidence_kinds: ['third_party_security_review', 'compliance_legal_signoff', 'staging_e2e_matrix'],
  }),
]);

const ENCRYPTED_CREDENTIAL_REF_RE = /^(?:secret|vault|encref):\/\/.+/i;
const CUSTODY_URI_RE = /^(?:custody|evidence|artifact|signoff|retained):\/\/.+/i;
const PLACEHOLDER_KMS_RE = /(?:metadata|example|fixture|local-staging|placeholder|staging-sim)/i;

function resolveKmsProviderLabel(vaultSummary = {}) {
  return vaultSummary.kms_provider ?? vaultSummary.provider_class ?? null;
}

function hasKmsRotationDrillReference(kms = {}) {
  const drill = kms.drill_reference;
  if (!hasValue(drill)) return false;
  if (typeof drill === 'string') return true;
  if (typeof drill === 'object' && !Array.isArray(drill)) {
    return hasValue(drill.drill_id) || hasValue(drill.drill_evidence_uri);
  }
  return false;
}

function providerUsesMetadataOnlyDelivery(provider = {}) {
  const mode = String(provider?.delivery_mode ?? '').trim().toLowerCase();
  return mode === 'metadata-only' || mode === 'metadata_only';
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function acceptedEvidenceForKind(record, kind) {
  if (!record || record.status === 'rejected') return null;
  if (record.kind === kind) return record.evidence ?? record.metadata ?? record;
  if (kind === 'staging_e2e_matrix' && record?.evidence?.artifact_type === 'staging_e2e_matrix_evidence') {
    return record.evidence;
  }
  return null;
}

function findValidEvidenceRecord(records = [], kind) {
  for (const record of records) {
    const evidence = acceptedEvidenceForKind(record, kind);
    if (evidence && validateProductionReleaseEvidence(kind, evidence).ok) return evidence;
  }
  return null;
}

function imageHasPinnedDigest(image) {
  if (!image) return false;
  if (typeof image === 'string') {
    return /@sha256:[a-f0-9]{64}$/i.test(image) || /^sha256:[a-f0-9]{64}$/i.test(image);
  }
  if (typeof image === 'object') {
    const digest = image.digest_sha256 ?? image.digest ?? image.sha256 ?? null;
    if (typeof digest === 'string' && /^[a-f0-9]{64}$/i.test(digest.trim())) return true;
    const ref = image.reference ?? image.image ?? null;
    if (typeof ref === 'string' && /@sha256:[a-f0-9]{64}$/i.test(ref)) return true;
  }
  return false;
}

function manifestDomainEntry(manifest, domainId) {
  const domains = manifest?.domains;
  if (!domains || typeof domains !== 'object' || Array.isArray(domains)) return null;
  const entry = domains[domainId];
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
  return entry;
}

function manifestFieldGaps(entry) {
  return EXTERNAL_VERIFICATION_MANIFEST_REQUIRED_FIELDS.filter((field) => !hasValue(entry?.[field]));
}

function manifestTierIsLiveExternal(entry) {
  return typeof entry?.tier === 'string' && entry.tier.trim() === 'live_external';
}

function metadataOnlyEvidenceReady(domainId, records = []) {
  const domain = EXTERNAL_VERIFICATION_DOMAINS.find((entry) => entry.id === domainId);
  if (!domain) return { ready: false, blockers: [`unknown_domain:${domainId}`] };

  const blockers = [];
  for (const kind of domain.evidence_kinds) {
    const evidence = findValidEvidenceRecord(records, kind);
    if (!evidence) blockers.push(`missing_or_invalid_evidence:${kind}`);
  }
  if (blockers.length > 0) return { ready: false, blockers };

  if (domainId === 'enterprise_idp_mfa') {
    const oidc = findValidEvidenceRecord(records, 'oidc_prod_auth_preflight');
    if (oidc?.ok !== true) blockers.push('oidc_prod_auth_preflight_not_ok');
    const authMode = oidc?.auth_posture?.auth_mode;
    if (authMode !== 'oidc-jwt') blockers.push('oidc_auth_mode_not_oidc_jwt');
  }

  if (domainId === 'retained_security_legal_soc') {
    const matrix = findValidEvidenceRecord(records, 'staging_e2e_matrix');
    if (matrix?.overall_status !== 'passed') blockers.push('staging_e2e_matrix_not_passed');
  }

  return { ready: blockers.length === 0, blockers };
}

function liveExternalEvidenceReady(domainId, records = []) {
  const baseline = metadataOnlyEvidenceReady(domainId, records);
  if (!baseline.ready) return baseline;

  const blockers = [];

  if (domainId === 'enterprise_idp_mfa') {
    const oidc = findValidEvidenceRecord(records, 'oidc_prod_auth_preflight');
    if (oidc?.auth_posture?.oidc?.require_mfa !== true) {
      blockers.push('oidc_mfa_policy_not_required');
    }
  }

  if (domainId === 'kms_hsm_custody') {
    const kms = findValidEvidenceRecord(records, 'kms_vault_posture');
    const provider = resolveKmsProviderLabel(kms?.vault_summary);
    if (!hasValue(provider) || PLACEHOLDER_KMS_RE.test(String(provider))) {
      blockers.push('kms_provider_placeholder_or_missing');
    }
    if (!hasKmsRotationDrillReference(kms)) blockers.push('kms_rotation_drill_missing');
  }

  if (domainId === 'notification_provider_credentials') {
    const config = findValidEvidenceRecord(records, 'notification_provider_config');
    const providers = Array.isArray(config?.providers) ? config.providers : [];
    if (providers.length === 0) {
      blockers.push('notification_providers_missing');
    }
    for (const provider of providers) {
      const ref = provider?.encrypted_credential_ref_id;
      if (!hasValue(ref) || !ENCRYPTED_CREDENTIAL_REF_RE.test(String(ref))) {
        blockers.push('notification_encrypted_credential_ref_missing');
        break;
      }
      if (providerUsesMetadataOnlyDelivery(provider)) {
        blockers.push('notification_delivery_mode_metadata_only');
        break;
      }
    }
  }

  if (domainId === 'artifact_pinned_deploy_rollback') {
    const release = findValidEvidenceRecord(records, 'control_plane_container_release');
    const rollback = findValidEvidenceRecord(records, 'rollback_fixforward');
    if (!imageHasPinnedDigest(release?.image)) blockers.push('control_plane_image_not_digest_pinned');
    if (!hasValue(release?.rollback_reference)) blockers.push('control_plane_rollback_reference_missing');
    const testedCount = Number(rollback?.plan_summary?.tested_command_count ?? 0);
    if (!Number.isFinite(testedCount) || testedCount < 1) {
      blockers.push('rollback_fixforward_not_exercised');
    }
  }

  if (domainId === 'retained_security_legal_soc') {
    const security = findValidEvidenceRecord(records, 'third_party_security_review');
    const legal = findValidEvidenceRecord(records, 'compliance_legal_signoff');
    if (!hasValue(security?.review_report_uri)) blockers.push('security_review_report_uri_missing');
    const signoffs = Array.isArray(legal?.signoffs) ? legal.signoffs : [];
    const hasRetainedSignoff = signoffs.some((entry) => hasValue(entry?.reference));
    if (!hasRetainedSignoff) blockers.push('legal_signoff_reference_missing');
  }

  return { ready: blockers.length === 0, blockers };
}

function resolveDomainTier(domainId, records = [], manifest = null) {
  const manifestEntry = manifestDomainEntry(manifest, domainId);
  if (manifestEntry && manifestTierIsLiveExternal(manifestEntry)) {
    const manifestGaps = manifestFieldGaps(manifestEntry);
    const liveEvidence = liveExternalEvidenceReady(domainId, records);
    const custodyUri = manifestEntry.custody_uri;
    if (!hasValue(custodyUri) || !CUSTODY_URI_RE.test(String(custodyUri))) {
      manifestGaps.push('custody_uri_invalid');
    }
    if (manifestGaps.length > 0 || !liveEvidence.ready) {
      return {
        tier: 'metadata_only',
        blockers: [
          ...manifestGaps.map((field) => `manifest_${field}`),
          ...liveEvidence.blockers,
        ],
        manifest_attested: false,
      };
    }
    return {
      tier: 'live_external',
      blockers: [],
      manifest_attested: true,
      custody_uri: String(custodyUri).trim(),
      verified_at: manifestEntry.verified_at,
      operator_reference: manifestEntry.operator_reference,
    };
  }

  const metadata = metadataOnlyEvidenceReady(domainId, records);
  if (metadata.ready) {
    return {
      tier: 'metadata_only',
      blockers: ['live_external_manifest_required'],
      manifest_attested: false,
    };
  }

  return {
    tier: 'unverified',
    blockers: metadata.blockers,
    manifest_attested: false,
  };
}

export function validateExternalVerificationManifest(manifest = {}) {
  const forbidden = [];
  const gaps = [];
  if (!hasValue(manifest?.schema_version)) gaps.push('schema_version');
  if (manifest?.artifact_type !== 'external_production_verification_manifest') {
    gaps.push('artifact_type');
  }
  if (!hasValue(manifest?.release_id)) gaps.push('release_id');
  if (!manifest?.domains || typeof manifest.domains !== 'object' || Array.isArray(manifest.domains)) {
    gaps.push('domains');
  }

  const domains = manifest?.domains ?? {};
  for (const domain of EXTERNAL_VERIFICATION_DOMAINS) {
    const entry = domains[domain.id];
    if (!entry) continue;
    if (typeof entry !== 'object' || Array.isArray(entry)) {
      gaps.push(`domains.${domain.id}`);
      continue;
    }
    for (const field of EXTERNAL_VERIFICATION_MANIFEST_REQUIRED_FIELDS) {
      if (!hasValue(entry[field])) gaps.push(`domains.${domain.id}.${field}`);
    }
    if (hasValue(entry.tier) && !EXTERNAL_VERIFICATION_TIERS.includes(entry.tier)) {
      gaps.push(`domains.${domain.id}.tier`);
    }
    for (const key of Object.keys(entry)) {
      if (['password', 'secret', 'token', 'api_key', 'webhook_url'].includes(key)) {
        forbidden.push(`domains.${domain.id}.${key}`);
      }
    }
  }

  return {
    ok: gaps.length === 0 && forbidden.length === 0,
    gaps,
    forbidden_fields: forbidden,
  };
}

export function aggregateExternalProductionVerification(records = [], options = {}) {
  const manifest = options.manifest ?? null;
  const manifestValidation = manifest ? validateExternalVerificationManifest(manifest) : null;

  const domains = EXTERNAL_VERIFICATION_DOMAINS.map((domain) => {
    const resolved = resolveDomainTier(domain.id, records, manifest);
    return {
      id: domain.id,
      label: domain.label,
      evidence_kinds: [...domain.evidence_kinds],
      tier: resolved.tier,
      manifest_attested: resolved.manifest_attested === true,
      custody_uri: resolved.custody_uri ?? null,
      verified_at: resolved.verified_at ?? null,
      operator_reference: resolved.operator_reference ?? null,
      blockers: resolved.blockers,
    };
  });

  const liveCount = domains.filter((entry) => entry.tier === 'live_external').length;
  const metadataCount = domains.filter((entry) => entry.tier === 'metadata_only').length;
  const unverifiedCount = domains.filter((entry) => entry.tier === 'unverified').length;
  const complete = liveCount === EXTERNAL_VERIFICATION_DOMAINS.length;

  const blocker_summary = [];
  if (!complete) {
    for (const domain of domains) {
      if (domain.tier === 'live_external') continue;
      const reason = domain.blockers.length > 0 ? domain.blockers.join(', ') : 'not_verified';
      blocker_summary.push(`${domain.label}: ${reason}`);
    }
  }
  if (manifest && manifestValidation && !manifestValidation.ok) {
    blocker_summary.push(
      `External verification manifest invalid: gaps=${manifestValidation.gaps.join(', ')}`,
    );
  }

  return {
    schema_version: 1,
    artifact_type: 'external_production_verification',
    complete,
    live_external_count: liveCount,
    metadata_only_count: metadataCount,
    unverified_count: unverifiedCount,
    required_domain_count: EXTERNAL_VERIFICATION_DOMAINS.length,
    domains,
    manifest_present: manifest !== null,
    manifest_valid: manifest ? manifestValidation?.ok === true : false,
    blocker_summary,
    message: complete
      ? 'All external production verification domains attested live_external with retained artifacts.'
      : 'Customer production launch requires live_external verification for enterprise IdP/MFA, KMS/HSM custody, notification credentials, artifact-pinned deploy/rollback, and retained security/legal/SOC artifacts.',
    caveats: [
      'Metadata-only release evidence does not satisfy live_external verification by itself.',
      'Operators attach live_external markers via output/external-production-verification.json after retaining real IdP, KMS, provider, deploy, and signoff artifacts.',
      'customer_production_ready stays false until every domain reaches live_external tier.',
    ],
  };
}

export function buildLiveExternalVerificationManifestTemplate(input = {}) {
  const releaseId = input.releaseId ?? input.release_id ?? null;
  const createdAt = input.createdAt ?? new Date().toISOString();
  const operatorReference = input.operatorReference ?? 'operator://release/on-call';
  const domains = Object.fromEntries(
    EXTERNAL_VERIFICATION_DOMAINS.map((domain) => [
      domain.id,
      {
        tier: 'live_external',
        custody_uri: `custody://external/${domain.id}/${releaseId ?? 'unscoped'}`,
        verified_at: createdAt,
        operator_reference: operatorReference,
        retained_artifact_refs: [],
      },
    ]),
  );

  return {
    schema_version: 1,
    artifact_type: 'external_production_verification_manifest',
    created_at: createdAt,
    release_id: releaseId,
    verification_tier: 'live_external',
    domains,
    caveats: [
      'Replace custody_uri and retained_artifact_refs with real retained artifact locations before customer launch.',
      'Re-run npm run release:external-verify after updating this manifest.',
    ],
  };
}