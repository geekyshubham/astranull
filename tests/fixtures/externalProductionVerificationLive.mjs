import {
  buildLiveExternalVerificationManifestTemplate,
} from '../../src/contracts/externalProductionVerification.mjs';
import {
  completeEvidenceRecords,
  PRODUCTION_RELEASE_EVIDENCE_COMPLETE,
} from './productionReleaseEvidenceComplete.mjs';
import { PRODUCTION_RELEASE_EVIDENCE_KINDS } from '../../src/contracts/productionReleaseEvidence.mjs';

export const LIVE_EXTERNAL_EVIDENCE_OVERRIDES = Object.freeze({
  oidc_prod_auth_preflight: {
    ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.oidc_prod_auth_preflight,
    ok: true,
    node_env: 'production',
    auth_posture: {
      auth_mode: 'oidc-jwt',
      jwks_redirect_policy: 'manual',
      oidc: {
        issuer_redacted: 'https://idp.example/oauth2/default',
        audience: 'astranull-api',
        jwks_url_redacted: 'https://idp.example/oauth2/default/v1/keys',
        require_mfa: true,
        mfa_claim: 'amr',
        mfa_values: ['mfa', 'otp'],
      },
    },
  },
  kms_vault_posture: {
    ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.kms_vault_posture,
    environment: 'production',
    vault_summary: {
      vault_reference: 'vault://prod/secrets',
      kms_provider: 'aws-kms-prod',
      encryption_at_rest: 'enabled',
    },
    drill_reference: 'drill://kms/vault-access-live-2026-07-04',
  },
  notification_provider_config: {
    ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.notification_provider_config,
    providers: [{
      provider_id: 'email-primary',
      channel: 'email',
      encrypted_credential_ref_id: 'vault://notifications/email-primary',
      rotation_owner: 'sre-lead',
      retry_dlq_policy: {
        max_attempts: 5,
        backoff_summary: 'exponential',
        dlq_reference: 'dlq://notifications/email-primary',
      },
      tenant_scope: 'tenant-wide',
      test_delivery_artifact_ids: ['artifact://notifications/email-test-001'],
      delivery_mode: 'email',
    }],
  },
  control_plane_container_release: {
    ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.control_plane_container_release,
    image: {
      repository: 'registry.example/astranull-control-plane',
      digest_sha256: 'e'.repeat(64),
      tag: '2026-07-04-prod',
    },
    rollback_reference: 'rollback://control-plane/rel-2026-07-03',
  },
  rollback_fixforward: {
    ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.rollback_fixforward,
    plan_summary: {
      ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.rollback_fixforward.plan_summary,
      environment: 'production',
      tested_command_count: 2,
    },
  },
});

export function liveExternalEvidenceRecords(releaseId = 'rel-live-external-2026-07-04') {
  const records = completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS).map((entry) => {
    const override = LIVE_EXTERNAL_EVIDENCE_OVERRIDES[entry.kind];
    return {
      kind: entry.kind,
      status: 'accepted',
      release_id: releaseId,
      evidence: override ?? entry.evidence,
    };
  });
  return records;
}

export function liveExternalVerificationManifest(releaseId = 'rel-live-external-2026-07-04') {
  return buildLiveExternalVerificationManifestTemplate({
    releaseId,
    operatorReference: 'operator://security/release-lead',
    createdAt: '2026-07-04T00:00:00.000Z',
  });
}