import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { EDGE_PROTECTION_REQUIRED_CONTROLS } from '../../src/contracts/edgeProtectionBaseline.mjs';
import { REQUIRED_ARTIFACT_TYPES } from '../../src/lib/highScalePolicy.mjs';
import { REQUIRED_NOTIFICATION_CHANNELS } from '../notification-provider-config-evidence.mjs';
import { AGENT_INSTALL_MATRIX_FORMATS } from '../agent-install-matrix-evidence.mjs';
import { ALLOWED_FINGERPRINT_HEADER_NAMES } from '../agent-mtls-gateway-evidence.mjs';
import {
  GATEWAY_LOAD_ABUSE_ABUSE_CONTROL_IDS,
  GATEWAY_LOAD_ABUSE_RATE_LIMIT_CONTROL_IDS,
} from '../gateway-load-abuse-evidence.mjs';
import { PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS } from '../placement-confidence-staging-evidence.mjs';
import {
  PROBE_FLEET_MATRIX_REGIONS,
  PROBE_FLEET_REQUIRED_PROBE_PROFILES,
} from '../probe-fleet-matrix-evidence.mjs';
import { REQUIRED_SCENARIOS } from '../staging-e2e-matrix-evidence.mjs';
import { REQUIRED_CONCURRENCY_ROUTE_FAMILIES } from '../postgres-concurrency-evidence.mjs';
import { REQUIRED_PAGES } from '../ui-accessibility-matrix-evidence.mjs';
import { computeSnapshotHash } from '../evidence-snapshot-manifest.mjs';
import { PRODUCTION_RELEASE_EVIDENCE_COMPLETE } from '../../tests/fixtures/productionReleaseEvidenceComplete.mjs';

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);

const MINIMAL_SBOM = {
  bomFormat: 'CycloneDX',
  specVersion: '1.4',
  serialNumber: 'urn:uuid:11111111-1111-4111-8111-111111111111',
  components: [{ type: 'application', name: 'astranull-agent', version: '1.0.0' }],
};

const MINIMAL_PROVENANCE = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'astranull-agent', digest: { sha256: 'abc' } }],
  materials: [{ uri: 'git+https://example/astranull@main' }],
  predicateType: 'https://slsa.dev/provenance/v1',
  predicate: { builder: { id: 'local-builder' } },
};

function clone(value) {
  return structuredClone(value);
}

function replaceEnvironment(value, environment) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    return value
      .replaceAll('staging', environment)
      .replaceAll('rel-2026-07-02', 'rel-staging-sim-2026-07-03');
  }
  if (Array.isArray(value)) return value.map((entry) => replaceEnvironment(entry, environment));
  if (typeof value === 'object') {
    const out = {};
    for (const [key, nested] of Object.entries(value)) {
      out[key] = key === 'environment' ? environment : replaceEnvironment(nested, environment);
    }
    return out;
  }
  return value;
}

export function adaptContractEvidence(kind, context = {}) {
  const environment = context.environment ?? 'staging-sim';
  const releaseId = context.releaseId ?? 'rel-staging-sim-2026-07-03';
  const createdAt = context.createdAt ?? '2026-07-03T00:00:00.000Z';
  const base = clone(PRODUCTION_RELEASE_EVIDENCE_COMPLETE[kind] ?? {});
  const adapted = replaceEnvironment(base, environment);
  if (typeof adapted === 'object' && adapted !== null) {
    if ('release_id' in adapted) adapted.release_id = releaseId;
    if ('created_at' in adapted) adapted.created_at = createdAt;
  }
  return adapted;
}

function completeEdgeControls() {
  return EDGE_PROTECTION_REQUIRED_CONTROLS.map((control) => ({
    control_id: control.control_id,
    evidence_uri: `evidence://edge/${control.control_id}`,
    validated_at: '2026-07-03T00:00:00.000Z',
    owner: 'security-team',
    tls_policy: 'TLS 1.2+ with managed certificate rotation',
    allowed_hosts: ['app.astranull.example', 'api.astranull.example'],
    limit_summary: 'Gateway enforces bounded body, header count, and header size limits.',
    protection_summary: 'Credential-stuffing and bot protections enabled at the edge.',
    rule_family_summary: 'Managed API and application rule groups in block/challenge mode.',
    origin_exposure_summary: 'Origin accepts traffic only from the edge or private network.',
    log_destination: 'siem://edge-events',
    health_path_policy: '/health and /ready are allowlisted with narrow method and rate policy.',
    header_policy_summary: 'HSTS, frame, content-type, and referrer policies enabled.',
    spoofing_control_summary: 'Proxy strips inbound forwarding headers before adding trusted values.',
  }));
}

function passedScenario(scenarioId, overrides = {}) {
  return {
    scenario_id: scenarioId,
    status: 'passed',
    evidence_uri: `evidence://staging-e2e/${scenarioId}`,
    owner: 'qa-oncall',
    completed_at: '2026-07-03T00:00:00.000Z',
    ...overrides,
  };
}

export function localStagingE2eMatrixInputPath(context = {}) {
  const outDir = context.outDir ?? 'output/release-evidence';
  return path.join(outDir, 'local-staging-e2e-matrix-input.json');
}

export function loadExecutedLocalStagingE2eMatrix(context = {}) {
  const inputPath = localStagingE2eMatrixInputPath(context);
  if (!existsSync(inputPath)) return null;
  try {
    const parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
    if (parsed?.environment !== 'local-staging' || !Array.isArray(parsed?.scenarios)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function hostedStagingE2eMatrixInputPath(context = {}) {
  const outDir = context.outDir ?? 'output/release-evidence';
  return path.join(outDir, 'hosted-staging-e2e-matrix-input.json');
}

function loadLiveEvidenceInput(context, filename) {
  const inputPath = path.join(context.outDir ?? 'output/release-evidence', filename);
  if (!existsSync(inputPath)) return null;
  try {
    return JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    return null;
  }
}

export function loadExecutedHostedStagingE2eMatrix(context = {}) {
  const inputPath = hostedStagingE2eMatrixInputPath(context);
  if (!existsSync(inputPath)) return null;
  try {
    const parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
    if (parsed?.environment !== 'staging' || !Array.isArray(parsed?.scenarios)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function localStagingScenario(scenarioId, executedMatrix = null) {
  const executed = executedMatrix?.scenarios?.find(
    (entry) => String(entry?.scenario_id ?? entry?.id ?? '').trim().toLowerCase() === scenarioId,
  );
  if (executed?.status === 'passed') {
    return {
      scenario_id: scenarioId,
      status: 'passed',
      evidence_uri: executed.evidence_uri ?? `evidence://local-staging/e2e/${scenarioId}`,
      owner: executed.owner ?? 'internal-soc-qa',
      completed_at: executed.completed_at ?? new Date().toISOString(),
      ...(executed.notes ? { notes: executed.notes } : {}),
    };
  }
  return passedScenario(scenarioId, {
    status: 'not_run',
    evidence_uri: `evidence://local-staging/e2e/${scenarioId}/pending`,
    notes: 'Run npm run staging:local:e2e-matrix after staging:local:smoke to execute local production-like scenarios.',
  });
}

function notificationProvider(channel, suffix) {
  return {
    provider_id: `${channel}-${suffix}`,
    channel,
    delivery_mode: channel,
    encrypted_credential_ref_id: `secret://vault/notif/${channel}-${suffix}`,
    rotation_owner: 'platform-ops',
    retry_dlq_policy: {
      max_attempts: 3,
      backoff_summary: 'exponential 30s to 15m with jitter',
      dlq_reference: `dlq://notif/${channel}`,
    },
    tenant_scope: 'tenant_staging_sim_01',
    test_delivery_artifact_ids: [`artifact://notif/${channel}-test-20260703`],
  };
}

function snapshotBody(overrides = {}) {
  const base = {
    snapshot_id: 'snap_2026_07_03_001',
    custody_manifest_digest: DIGEST_A,
    storage_reference: 'evidence://immutable/tenant-a/2026-07-03/snap-001',
    retention_policy: {
      metadata_retention_days: 90,
      report_days: 365,
      audit_log_days: 2555,
      legal_hold: false,
    },
    signer: {
      key_reference: 'key://vault/astranull/evidence-signing/staging-sim',
      algorithm: 'ed25519',
      signature_reference: 'evidence://signatures/staging-sim/snap-001',
    },
    previous_snapshot_hash: null,
    operator_signoff: {
      operator: 'custody-operator',
      signed_at: '2026-07-03T00:00:00.000Z',
      signoff_reference: 'signoff://custody/snapshot-batch-2026-07-03',
    },
    ...overrides,
  };
  return { ...base, snapshot_hash: computeSnapshotHash(base) };
}

function buildSnapshotBatch() {
  const first = snapshotBody();
  const second = snapshotBody({
    snapshot_id: 'snap_2026_07_03_002',
    custody_manifest_digest: DIGEST_B,
    storage_reference: 'evidence://immutable/tenant-a/2026-07-03/snap-002',
    previous_snapshot_hash: first.snapshot_hash,
  });
  return {
    schema_version: 1,
    artifact_type: 'immutable_evidence_snapshot_batch',
    tenant_id: 'ten_staging_sim',
    batch_id: 'snapbatch_2026_07_03',
    snapshots: [first, second],
  };
}

function agentInstallRow(format) {
  const checkPassed = (extra = {}) => ({
    status: 'passed',
    observed_at: '2026-07-03T00:00:00.000Z',
    ...extra,
  });
  const signingFormat = format === 'generic' ? 'tarball' : format;
  const trustAnchorByFormat = {
    generic: 'ed25519://tenant/agent-update-trust-key',
    deb: 'gpg://astranull/agent-package-signing',
    rpm: 'gpg://astranull/agent-package-signing',
    container: 'cosign://astranull/agent-release-signer',
    kubernetes: 'cosign://astranull/agent-release-signer',
  };
  const row = {
    format,
    environment: 'staging-sim',
    agent_id_redacted: 'ag_…01',
    checks: {
      install: checkPassed(),
      heartbeat: checkPassed({ heartbeat_count: 2 }),
      job_poll: checkPassed({ job_poll_count: 1 }),
      upgrade_rollback: checkPassed(),
      revoke: checkPassed(),
      uninstall: checkPassed(),
      no_inbound_port: checkPassed({ inbound_listener_count: 0 }),
      signature_verify: checkPassed({
        signing_format: signingFormat,
        trust_anchor_reference: trustAnchorByFormat[format],
      }),
    },
  };
  if (format === 'container') {
    row.runtime = 'docker';
    row.image_reference_redacted = 'registry.example/astranull-agent@sha256:…01';
  }
  if (format === 'kubernetes') {
    row.runtime = 'kubernetes';
    row.deployment_mode = 'daemonset';
    row.namespace_redacted = 'astranull-…';
  }
  return row;
}

function placementScenario(scenarioId) {
  const defaults = {
    strong_agent_observation: {
      status: 'passed',
      confidence_label: 'High',
      target_group_reference: 'tg://staging-sim/edge-primary',
      run_reference: 'run://staging-sim/strong-agent-01',
      verdict_reference: 'verdict://staging-sim/strong-agent-01',
    },
    misplaced_agent_detection: {
      status: 'passed',
      confidence_label: 'Invalid',
      target_group_reference: 'tg://staging-sim/misplaced-edge',
      run_reference: 'run://staging-sim/misplaced-agent-01',
      verdict_reference: 'verdict://staging-sim/misplaced-agent-01',
    },
    external_only_inconclusive: {
      status: 'passed',
      confidence_label: 'Low',
      target_group_reference: 'tg://staging-sim/external-only',
      run_reference: 'run://staging-sim/external-only-01',
      verdict_reference: 'verdict://staging-sim/external-only-01',
    },
    canary_path_observation: {
      status: 'passed',
      confidence_label: 'High',
      target_group_reference: 'tg://staging-sim/canary-path',
      run_reference: 'run://staging-sim/canary-path-01',
      verdict_reference: 'verdict://staging-sim/canary-path-01',
    },
  }[scenarioId];
  return {
    scenario_id: scenarioId,
    evidence_uri: `evidence://placement/${scenarioId}`,
    owner: 'detection-lead',
    completed_at: '2026-07-03T00:00:00.000Z',
    ...defaults,
  };
}

function authorizationArtifactEntry(artifactType, index) {
  return {
    artifact_type: artifactType,
    custody_id: `custody://${artifactType}/${index}`,
    custody_uri: `metadata://custody/${artifactType}/${index}`,
    status: 'sealed',
  };
}

function probeFleetControls(observedAt = '2026-07-03T00:00:00.000Z') {
  return {
    signed_job_route: {
      status: 'passed',
      observed_at: observedAt,
      route_paths: ['/internal/probe/jobs', '/internal/probe/jobs/pjob_staging_sim_1/result'],
    },
    job_signature_verified: { status: 'passed', observed_at: observedAt },
    tenant_header_signing: { status: 'passed', observed_at: observedAt },
    worker_hmac_auth: { status: 'passed', observed_at: observedAt },
    health_status: { status: 'passed', observed_at: observedAt, health: 'healthy' },
    rate_budget: {
      status: 'passed',
      observed_at: observedAt,
      max_jobs_per_minute: 30,
      max_requests_per_job: 1,
    },
    egress_controls: {
      status: 'passed',
      observed_at: observedAt,
      default_deny: true,
      allowed_destination_count: 2,
    },
    abuse_monitoring: { status: 'passed', observed_at: observedAt, alerts_enabled: true },
  };
}

function writeAgentSbomFixtureFiles(scratchDir) {
  mkdirSync(scratchDir, { recursive: true });
  const pkgPath = path.join(scratchDir, 'agent-package.tar.gz');
  const sbomPath = path.join(scratchDir, 'sbom.json');
  const provenancePath = path.join(scratchDir, 'provenance.json');
  const pkgBytes = Buffer.from('astranull-agent-package-staging-sim');
  writeFileSync(pkgPath, pkgBytes);
  writeFileSync(sbomPath, `${JSON.stringify(MINIMAL_SBOM, null, 2)}\n`);
  writeFileSync(provenancePath, `${JSON.stringify(MINIMAL_PROVENANCE, null, 2)}\n`);
  return {
    package: pkgPath,
    sbom: sbomPath,
    provenance: provenancePath,
    packageSha256: createHash('sha256').update(pkgBytes).digest('hex'),
  };
}

/**
 * Build script input payloads and optional extra CLI args for release evidence collectors.
 * @param {string} kind
 * @param {Record<string, unknown>} context
 */
export function buildCollectorScriptInput(kind, context = {}) {
  const environment = context.environment ?? 'staging-sim';
  const releaseId = context.releaseId ?? 'rel-staging-sim-2026-07-03';
  const createdAt = context.createdAt ?? '2026-07-03T00:00:00.000Z';
  const scratchDir = context.scratchDir ?? path.join(context.outDir ?? 'output/release-evidence', 'scratch');

  switch (kind) {
    case 'third_party_security_review':
      return { input: adaptContractEvidence(kind, context) };

    case 'migration_apply':
      return { input: adaptContractEvidence(kind, context) };

    case 'operator_runbook_exercise': {
      const live = loadLiveEvidenceInput(context, 'operator-runbook-exercise-input.json');
      return { input: live ?? adaptContractEvidence(kind, context) };
    }

    case 'edge_protection':
      return {
        input: {
          release_id: releaseId,
          edge_stack_summary: 'Managed WAF and API gateway in front of customer API and UI; CDN caches static UI assets.',
          rate_limiting_summary: 'Per-IP and per-route rate limits at the gateway with burst caps on auth and write paths.',
          logging_redaction_summary: 'Edge access logs route to SIEM with authorization, cookie, and body fields stripped.',
          signoff_owner: 'security-lead',
          signoff_at: createdAt,
          controls: completeEdgeControls(),
          evidence_uri: `evidence://edge/protection-matrix-${environment}`,
        },
      };

    case 'staging_e2e_matrix': {
      const executedMatrix = environment === 'local-staging'
        ? loadExecutedLocalStagingE2eMatrix(context)
        : environment === 'staging'
          ? loadExecutedHostedStagingE2eMatrix(context)
          : null;
      if (executedMatrix) {
        return { input: executedMatrix };
      }
      return {
        input: {
          release_id: releaseId,
          environment,
          evidence_uri: `evidence://release/staging-e2e-matrix-${environment}`,
          signoff: {
            owner: 'internal-soc-qa',
            signed_at: createdAt,
            signoff_reference: `signoff://internal-soc/staging-e2e-${environment}`,
          },
          scenarios: REQUIRED_SCENARIOS.map((scenarioId) => (
            environment === 'local-staging'
              ? localStagingScenario(scenarioId)
              : passedScenario(scenarioId)
          )),
        },
      };
    }

    case 'notification_provider_config':
      return {
        input: {
          release_id: releaseId,
          tenant_scope: 'tenant_staging_sim_01',
          providers: REQUIRED_NOTIFICATION_CHANNELS.map((channel) => notificationProvider(channel, 'staging-sim')),
          soc_signoff: {
            owner: 'soc-lead',
            signed_at: createdAt,
            reference: 'ticket://soc/notif-config/2026-07-03',
          },
          security_signoff: {
            owner: 'security-lead',
            signed_at: createdAt,
            reference: 'ticket://security/notif-config/2026-07-03',
          },
        },
      };

    case 'support_readiness':
      return {
        input: {
          readiness_id: 'support_readiness_2026_07_03_staging_sim',
          environment,
          on_call_rotation: {
            rotation_name: 'platform-primary',
            owner: 'support-oncall-lead',
            schedule_reference: 'pagerduty://services/astranull-platform-primary',
          },
          escalation_contacts: [
            { role: 'support', contact_reference: 'escalation://support/primary-queue' },
            { role: 'engineering', contact_reference: 'escalation://eng/platform-oncall' },
            { role: 'soc', contact_reference: 'escalation://soc/high-scale' },
          ],
          sla_policy: {
            policy_reference: 'policy://support/customer-sla/v2026-07',
            severity_tiers: [
              { severity: 'S1', response_minutes: 15 },
              { severity: 'S2', response_minutes: 60 },
              { severity: 'S3', response_minutes: 240 },
            ],
          },
          incident_tabletop: {
            tabletop_id: 'tabletop_2026_07_03_soc_escalation',
            conducted_at: createdAt,
            scenario_reference: 'scenario://drills/agent-mass-offline-s2',
            owner: 'incident-commander',
            evidence_uri: 'evidence://support/tabletop/2026-07-03',
          },
          soc_escalation_path: {
            path_reference: 'runbook://support/soc-escalation-v3',
            severity_routes: [
              { severity: 'S1', escalation_reference: 'escalation://soc/kill-switch-page' },
              { severity: 'S2', escalation_reference: 'escalation://soc/review-queue' },
            ],
          },
          customer_comms_templates: [
            {
              template_id: 'incident_initial_notice',
              purpose: 'initial_customer_notification',
              reference_uri: 'template://comms/incident-initial-v2',
            },
            {
              template_id: 'incident_resolution',
              purpose: 'resolution_summary',
              reference_uri: 'template://comms/incident-resolution-v2',
            },
          ],
          support_signoff: {
            signoff_owner: 'support-operations-lead',
            signed_at: createdAt,
            signoff_reference: 'signoff://support/readiness-staging-sim',
          },
        },
      };

    case 'kill_switch_drill': {
      const contract = adaptContractEvidence(kind, context);
      return { input: { ...contract.transcript, drill_id: contract.drill_id, tenant_id: contract.tenant_id } };
    }

    case 'kms_vault_posture':
      return {
        input: {
          environment: 'staging',
          evidence_uri: `evidence://security/kms-vault-posture-${environment}`,
          vault_posture: {
            provider_class: 'cloud_hsm',
            vault_reference: `vaultref://vendor/${environment}/astranull-secrets`,
            kms_key_references: [
              `keyref://${environment}/astranull-envelope/v1`,
              `keyref://${environment}/astranull-bootstrap/v2`,
            ],
          },
          key_rotation_policy: {
            policy_reference: 'policy://security/envelope-key-rotation',
            rotation_interval_days: 90,
            auto_rotation_enabled: true,
          },
          access_control_summary: {
            rbac_reference: 'rbac://security/kms-operators',
            break_glass_reference: 'runbook://security/kms-break-glass',
            audit_logging_reference: 'audit://kms/vault-access',
            least_privilege_attested: true,
          },
          drill_reference: {
            drill_id: 'kms_posture_drill_2026_07_03',
            drill_evidence_uri: 'evidence://drill/secret-rotation-2026-07-03',
            completed_at: createdAt,
          },
          security_signoff: {
            owner: 'security-lead',
            role: 'security-owner',
            signed_at: createdAt,
            signoff_reference: 'signoff://security/kms-vault-posture',
          },
        },
        extraArgs: ['--release-id', releaseId],
      };

    case 'secret_rotation_drill':
      return {
        input: {
          drill_id: 'sec_rot_drill_2026_07_03',
          environment: 'staging',
          started_at: createdAt,
          completed_at: createdAt,
          key_rotation: {
            provider_reference: 'kms://vendor/staging/astranull-secrets',
            key_reference_before: 'keyref://staging/astranull-secrets/v3',
            key_reference_after: 'keyref://staging/astranull-secrets/v4',
          },
          tenant_count: 12,
          envelope_rekey: { envelopes_total: 48, envelopes_rekeyed: 48 },
          failed_rotations: [],
          rollback_plan: {
            plan_reference: 'runbook://security/envelope-rotation-rollback',
            rollback_tested: true,
            rollback_test_reference: 'evidence://drill/rollback-tabletop-2026-07-03',
          },
          operator_signoff: {
            operator: 'platform-oncall',
            role: 'secrets-operator',
            signed_at: createdAt,
            signoff_reference: 'signoff://ops/envelope-rotation-drill',
          },
          security_signoff: {
            operator: 'security-lead',
            role: 'security-owner',
            signed_at: createdAt,
            signoff_reference: 'signoff://security/envelope-rotation-drill',
          },
          audit_event_ids: ['audit_sec_rot_1', 'audit_sec_rot_2'],
          zero_plaintext_exposure: {
            attested: true,
            attestation_reference: 'attestation://security/zero-plaintext-envelope-rotation',
            attested_at: createdAt,
            attested_by: 'security-lead',
          },
        },
      };

    case 'evidence_snapshot_manifest':
      return { input: buildSnapshotBatch() };

    case 'ui_accessibility_matrix': {
      const live = loadLiveEvidenceInput(context, 'ui-accessibility-matrix-input.json');
      if (live?.runs?.length) {
        return {
          input: {
            schema_version: 1,
            artifact_type: 'ui_accessibility_matrix_input',
            captured_at: createdAt,
            runs: live.runs,
          },
        };
      }
      const runs = [];
      for (const page of REQUIRED_PAGES) {
        runs.push({
          page,
          viewport: 'desktop',
          browser: 'chromium',
          axe_status: 'pass',
          keyboard_status: 'pass',
          screen_reader_status: 'pass',
          issues: { critical: 0, serious: 0, moderate: 0, minor: 0 },
          captured_at: createdAt,
        });
        runs.push({
          page,
          viewport: 'mobile',
          browser: 'webkit',
          axe_status: 'pass',
          keyboard_status: 'pass',
          screen_reader_status: 'pass',
          issues: { critical: 0, serious: 0, moderate: 0, minor: 0 },
          captured_at: createdAt,
        });
      }
      return {
        input: {
          schema_version: 1,
          artifact_type: 'ui_accessibility_matrix_input',
          captured_at: createdAt,
          runs,
        },
      };
    }

    case 'agent_install_matrix':
      return {
        input: {
          matrix_id: `agent-install-${releaseId}`,
          rows: AGENT_INSTALL_MATRIX_FORMATS.map((format) => agentInstallRow(format)),
        },
        extraArgs: ['--matrix-id', `agent-install-${releaseId}`],
      };

    case 'agent_sbom_provenance': {
      const files = writeAgentSbomFixtureFiles(path.join(scratchDir, 'agent-sbom'));
      return {
        input: null,
        extraArgs: [
          '--package', files.package,
          '--sbom', files.sbom,
          '--provenance', files.provenance,
          '--format', 'tar',
        ],
      };
    }

    case 'postgres_concurrency':
      return {
        input: {
          schema_version: 1,
          artifact_type: 'postgres_tenant_concurrency_evidence',
          environment: 'staging',
          tenant_count: 3,
          concurrent_actors: 12,
          duration_seconds: 180,
          route_families_exercised: [...REQUIRED_CONCURRENCY_ROUTE_FAMILIES],
          isolation: {
            cross_tenant_read_rejections: 48,
            cross_tenant_write_rejections: 22,
            cross_tenant_leaks: 0,
          },
          rls_evidence: {
            error_ids: ['rls_err_staging_20260703_01'],
            audit_evidence_ids: ['aud_staging_20260703_09'],
          },
          operator_signoff: {
            operator: 'platform-ops',
            signed_at: createdAt,
            reference: 'ticket://staging/concurrency/2026-07-03',
          },
        },
      };

    case 'postgres_tenant_query_audit':
      return {
        input: null,
        extraArgs: [
          '--allow-findings',
          '--evidence-uri',
          `evidence://db/tenant-query-audit-${environment}`,
        ],
      };

    case 'oidc_prod_auth_preflight':
    case 'vector_safety_policy':
      return { input: null };

    case 'agent_mtls_gateway':
      return {
        input: {
          release_id: releaseId,
          environment: 'staging',
          gateway_proxy: {
            gateway_reference: 'gateway://staging-sim/agent-control',
            proxy_type: 'nginx-ingress',
            tls_termination_point: 'edge_gateway',
            validated_at: createdAt,
          },
          client_certificate_issuance: {
            issuer_reference: 'pki://corp/agent-client-ca',
            issuance_runbook_reference: 'runbook://agent/client-cert-issuance',
            validated_at: createdAt,
          },
          fingerprint_forwarding: {
            allowed_header_names: [...ALLOWED_FINGERPRINT_HEADER_NAMES],
            gateway_sets_fingerprint_header: true,
            strips_untrusted_client_headers: true,
            control_reference: 'config://gateway/agent-mtls-fingerprint-forwarding',
            validated_at: createdAt,
          },
          header_spoofing_protection: {
            rejects_untrusted_fingerprint_headers: true,
            trusted_proxy_hop_policy: 'single_trusted_hop_strips_client_supplied_fingerprint',
            control_reference: 'config://gateway/agent-mtls-spoofing-controls',
            validated_at: createdAt,
          },
          agent_registration_heartbeat_proof: {
            staging_agent_reference: 'agent://staging-sim/prod-origin-01',
            registration_evidence_uri: 'evidence://agent/staging-sim-registration',
            heartbeat_evidence_uri: 'evidence://agent/staging-sim-heartbeat',
            fingerprint_match_confirmed: true,
            validated_at: createdAt,
          },
          rotation_revocation_drill: {
            drill_reference: 'drill://agent/client-cert-rotation-revocation-staging-sim',
            rotation_tested: true,
            revocation_tested: true,
            validated_at: createdAt,
          },
          security_signoff: {
            owner: 'security-lead',
            role: 'security-owner',
            signed_at: createdAt,
            signoff_reference: 'signoff://security/agent-mtls-gateway',
          },
        },
      };

    case 'agent_trust_key_ceremony':
      return {
        input: {
          drill_id: 'agent_trust_key_drill_2026_07_03',
          environment: 'staging',
          tenant_id: 'ten_staging_sim',
          started_at: createdAt,
          completed_at: createdAt,
          signing_key_ceremony: {
            method: 'generate',
            signing_key_reference: 'keyref://hsm/agent-update-signing/v1',
            custody_uri: 'custody://security/agent-signing-key/v1',
          },
          active_trust_key_registration: {
            trust_key_id: 'autk_0123456789abcdef',
            name: 'staging-sim-agent-update-signing',
            fingerprint_sha256: DIGEST_A,
            registration_reference: 'evidence://agent/trust-key/register-001',
          },
          staged_release_binding: {
            release_id: 'aurel_0123456789abcdef',
            signing_fingerprint_sha256: DIGEST_A,
            rollout_percentage: 25,
            binding_verified: true,
            binding_reference: 'evidence://agent/release/staged-binding-001',
          },
          trust_key_rotation: {
            previous_trust_key_id: 'autk_aaaaaaaaaaaaaaaa',
            new_trust_key_id: 'autk_bbbbbbbbbbbbbbbb',
            previous_fingerprint_sha256: DIGEST_B,
            new_fingerprint_sha256: DIGEST_A,
            rotation_reference: 'evidence://agent/trust-key/rotation-001',
          },
          trust_key_revocation: {
            revoked_trust_key_id: 'autk_bbbbbbbbbbbbbbbb',
            fingerprint_sha256: DIGEST_B,
            revocation_reference: 'evidence://agent/trust-key/revoke-001',
          },
          rollback_trust_behavior: {
            scenario: 'revoked_signing_key_release_rejected',
            untrusted_signing_key_observed: true,
            behavior_reference: 'evidence://agent/trust-key/rollback-trust-001',
            verified_at: createdAt,
          },
          custody_uris: ['custody://security/agent-trust-key-ceremony/2026-07-03'],
          operator_signoff: {
            operator: 'release-admin',
            role: 'agent-update-operator',
            signed_at: createdAt,
            signoff_reference: 'signoff://ops/agent-trust-key-drill',
          },
          security_signoff: {
            operator: 'security-lead',
            role: 'security-owner',
            signed_at: createdAt,
            signoff_reference: 'signoff://security/agent-trust-key-drill',
          },
          audit_event_ids: ['audit_trust_key_1', 'audit_trust_key_2'],
        },
      };

    case 'provider_approval':
      return {
        input: {
          high_scale_request_id: 'hsr_provider_evidence_staging_sim',
          requested_scenario_families: ['volumetric_metadata'],
          authorized_scope_hash: 'sha256:scope-staging-sim-001',
          soc_reviewer: 'usr_soc_reviewer',
          legal_signoff: {
            reference: 'legal://signoff/provider-approval/staging-sim',
            signed_at: createdAt,
          },
          custody_ids: ['cust_doc_provider_approval_staging_sim'],
          provider_approval: {
            provider_name: 'Cloudflare',
            approval_reference: 'CF-1001',
            valid_window: { valid_from: '2026-07-01T00:00:00.000Z', valid_to: '2026-07-10T00:00:00.000Z' },
            approved_targets: ['tg_staging_sim'],
            approved_scenario_families: ['volumetric_metadata'],
            contact_path: 'provider-war-room@example.invalid',
            approved_limits: { max_rate: '500_rps_metadata', max_duration_minutes: 30 },
            provider_specific_evidence: { provider_ticket: 'CF-1001' },
            emergency_stop_path: 'provider-stop-bridge',
          },
        },
        extraArgs: ['--as-of', createdAt],
      };

    case 'probe_fleet_matrix':
      return {
        input: {
          rows: PROBE_FLEET_MATRIX_REGIONS.map((region) => ({
            region,
            environment: 'staging',
            worker_id_redacted: `pw_${region}_…01`,
            probe_profiles_exercised: [...PROBE_FLEET_REQUIRED_PROBE_PROFILES],
            controls: probeFleetControls(createdAt),
          })),
        },
        extraArgs: ['--fleet-id', `probe-fleet-${releaseId}`],
      };

    case 'observability_slo':
      return {
        input: {
          release_id: releaseId,
          environment: 'staging',
          incident_drill_id: 'obs_incident_drill_2026_07_03',
          metric_scrape_auth: {
            auth_mechanism: 'mTLS via internal scrape gateway',
            gateway_reference: 'scrape-gateway/staging/astranull',
            evidence_uri: 'evidence://observability/scrape-auth/staging-sim',
            validated_at: createdAt,
          },
          dashboard_ids: ['dash_platform_availability', 'dash_soc'],
          alert_routes: [{
            route_id: 'route_api_5xx',
            alert_name: 'API error rate high',
            destination_reference: 'pagerduty://astranull-platform-oncall',
          }],
          slo_targets: [{
            slo_id: 'api_availability',
            target: '99.9% under 60 seconds',
            measurement_window: '30d',
          }],
          on_call: {
            owner: 'platform-oncall',
            rotation_reference: 'oncall://platform/rotation-2026-q3',
            evidence_uri: 'evidence://oncall/rotation-2026-q3',
          },
          redaction_policy: {
            policy_reference: 'policy://logging/redaction-v3',
            summary: 'Strip authorization, cookies, bodies, tokens, and database URLs from logs and traces.',
          },
        },
      };

    case 'rollback_fixforward':
      return {
        input: {
          release_id: releaseId,
          environment: 'staging',
          owner: 'release-manager',
          migration_plan: {
            plan_reference: 'runbook://db/migration-rollback-forward-fix',
            strategy: 'forward_fix',
            migration_version: '0007_production_release_evidence',
            decision_reference: `change://release/${releaseId}/migration-plan`,
          },
          postgres_backup_reference: {
            backup_reference: `rds-snapshot/staging/astranull-pre-${releaseId}`,
            manifest_uri: `evidence://db/backup-manifest/pre-${releaseId}`,
          },
          tested_command_references: [{
            command_id: 'postgres_startup_check',
            reference_uri: 'runbook://db/postgres-startup-check',
            tested_at: createdAt,
          }],
          adapter_disablement_plan: {
            plan_reference: 'runbook://soc/adapter-disablement',
            flag_reference: 'config://env/ASTRANULL_HIGH_SCALE_ADAPTER_MODE=disabled',
            runbook_reference: 'runbook://soc/stop-the-line',
          },
          probe_worker_flag_plan: {
            plan_reference: 'runbook://probe/worker-flag-plan',
            flag_reference: 'config://env/ASTRANULL_PROBE_MODE=signed-worker',
            runbook_reference: 'runbook://probe/worker-incident',
          },
          notification_comms_plan: {
            plan_reference: 'runbook://comms/notification-incident',
            owner: 'support-lead',
            template_references: [{ template_id: 'incident-customer-update', reference_uri: 'template://incident-customer-update' }],
          },
          support_comms_plan: {
            plan_reference: 'runbook://support/escalation',
            owner: 'support-lead',
            template_references: [{ template_id: 'severity-1-bridge', reference_uri: 'template://severity-1-bridge' }],
          },
          success_criteria: [{
            criterion_id: 'api_ready',
            check_reference: 'checklist://rollback/api-ready',
            expected_outcome_reference: 'outcome://rollback/api-200-ready',
          }],
          signoffs: [
            {
              role: 'release-owner',
              operator: 'release-manager',
              signed_at: createdAt,
              signoff_reference: 'signoff://release/rollback-plan',
            },
            {
              role: 'database-operator',
              operator: 'db-oncall',
              signed_at: createdAt,
              signoff_reference: 'signoff://db/rollback-plan',
            },
          ],
        },
      };

    case 'compliance_legal_signoff':
      return {
        input: {
          release_id: releaseId,
          legal_owner: 'legal-counsel',
          auditor_owner: 'compliance-auditor',
          review_date: createdAt,
          signoffs: [
            { role: 'legal', signoff_reference: `signoff://legal/${releaseId}`, signed_at: createdAt },
            { role: 'compliance', signoff_reference: `signoff://compliance/${releaseId}`, signed_at: createdAt },
          ],
          reviewed_templates: [
            {
              template_kind: 'soc2',
              review_date: createdAt,
              signoff_reference: 'signoff://compliance/soc2-mapping-review',
              review_status: 'approved',
              evidence_uri: 'evidence://compliance/soc2-review',
            },
            {
              template_kind: 'iso27001',
              review_date: createdAt,
              signoff_reference: 'signoff://compliance/iso27001-mapping-review',
              review_status: 'approved',
              evidence_uri: 'evidence://compliance/iso27001-review',
            },
            {
              local_contract_name: 'customer-dpa-v2026',
              review_date: createdAt,
              signoff_reference: 'signoff://legal/dpa-review',
              review_status: 'approved',
              evidence_uri: 'evidence://legal/dpa-review',
            },
          ],
          caveats: ['Metadata-only compliance mapping pack for staging-sim attestation.'],
          evidence_uri: 'evidence://compliance/legal-signoff',
        },
        extraArgs: ['--release-id', releaseId],
      };

    case 'authorization_custody':
      return {
        input: {
          high_scale_request_id: 'hsr_custody_evidence_staging_sim',
          release_id: releaseId,
          soc_reviewer: 'usr_soc_custody_reviewer',
          requires_provider_approval: false,
          custody_summary: {
            custody_system_reference: 'custody://soc/authorization-vault',
            chain_of_custody_verified: true,
          },
          retention_policy: {
            policy_reference: 'policy://custody/retention/v1',
            retention_years: 7,
            retention_classification: 'high_scale_authorization',
          },
          legal_signoff: {
            reference: `signoff://legal/custody-${releaseId}`,
            signed_at: createdAt,
          },
          scoped_authorization_references: {
            valid_window: {
              valid_from: '2026-07-03T00:00:00.000Z',
              valid_to: '2026-07-04T00:00:00.000Z',
            },
            scenario_families: ['volumetric_metadata', 'protocol_metadata'],
            rate_caps: { max_rate: '500_rps_metadata', max_duration_minutes: 30 },
          },
          artifact_custody: REQUIRED_ARTIFACT_TYPES.map((type, index) => authorizationArtifactEntry(type, index)),
          evidence_uri: 'evidence://soc/authorization-custody',
        },
        extraArgs: ['--release-id', releaseId],
      };

    case 'placement_confidence_staging':
      return {
        input: {
          release_id: releaseId,
          environment: 'staging',
          created_at: createdAt,
          evidence_uri: 'evidence://detection/placement-confidence-staging-sim',
          signoff: {
            owner: 'detection-lead',
            signed_at: createdAt,
            signoff_reference: 'signoff://detection/placement-confidence',
          },
          evidence_correlation_summary: {
            probe_evidence_count: 12,
            agent_evidence_count: 9,
            correlated_pairs: 7,
            gaps: [],
          },
          scenarios: PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS.map((scenarioId) => placementScenario(scenarioId)),
        },
        extraArgs: ['--release-id', releaseId],
      };

    case 'gateway_load_abuse':
      return {
        input: {
          release_id: releaseId,
          environment: 'staging',
          gateway_summary: 'API and UI traffic terminate at managed gateway with per-route rate policies.',
          waf_edge_summary: 'Managed WAF rule groups in challenge/block mode with redacted SIEM routing.',
          rate_limit_results: GATEWAY_LOAD_ABUSE_RATE_LIMIT_CONTROL_IDS.map((controlId) => ({
            control_id: controlId,
            status: 'passed',
            threshold_metadata: 'metadata-only-bounded-staging-sim-exercise',
            evidence_uri: `evidence://edge/rate-limit/${controlId}`,
          })),
          abuse_detection_results: GATEWAY_LOAD_ABUSE_ABUSE_CONTROL_IDS.map((controlId) => ({
            control_id: controlId,
            status: 'passed',
            alert_fired: true,
            evidence_uri: `evidence://edge/abuse/${controlId}`,
          })),
          edge_alerting_summary: {
            siem_route_reference: 'siem://edge-alerts/staging-sim',
            alert_count: 2,
            false_positive_rate_metadata: 'within-threshold',
          },
          signoff: {
            owner: 'security-lead',
            signed_at: createdAt,
            signoff_reference: 'signoff://security/gateway-load-abuse',
          },
          evidence_uri: 'evidence://edge/gateway-load-abuse',
        },
        extraArgs: ['--release-id', releaseId],
      };

    case 'dr_restore':
      return {
        input: {
          drill_id: 'dr_2026_07_03_staging_sim_restore',
          environment: 'staging',
          drill_type: 'restore',
          started_at: createdAt,
          completed_at: createdAt,
          backup_manifest: {
            manifest_uri: 'evidence://dr/backup-manifest/staging-sim',
            sha256: DIGEST_A,
            backup_reference: 'rds-snapshot/staging-sim/astranull',
          },
          restore_target: {
            cluster_reference: 'db-cluster/staging-sim/astranull-restore-clone',
            database_reference: 'postgres/staging-sim/astranull',
            restore_mode: 'non_production_clone',
          },
          rpo_rto: {
            rpo_target_minutes: 60,
            rto_target_minutes: 240,
            measured_rpo_minutes: 15,
            measured_rto_minutes: 90,
          },
          operator_approvals: [{
            role: 'database-operator',
            operator: 'db-oncall',
            approved_at: createdAt,
            signoff_reference: 'signoff://ops/db-restore-approval',
          }],
          evidence_custody_ids: ['custody://dr/staging-sim/backup-manifest'],
          recovery_decision: {
            decision: 'forward_fix',
            decision_reference: 'change://drill-forward-fix',
            operator: 'release-manager',
            decided_at: createdAt,
          },
          post_restore_verification: {
            signoff_reference: 'signoff://dr/post-restore',
            checks: [{ check_id: 'schema_ok', status: 'passed', evidence_uri: 'evidence://dr/check-1' }],
          },
        },
      };

    case 'control_plane_container_release':
      return {
        input: adaptContractEvidence(kind, context),
        extraArgs: ['--release-id', releaseId],
      };

    default:
      return { input: adaptContractEvidence(kind, context) };
  }
}
