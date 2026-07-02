import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  createSupportReadinessEvidenceManifest,
  main,
  parseSupportReadinessEvidenceArgs,
  validateSupportReadinessEvidence,
} from '../../scripts/support-readiness-evidence.mjs';

const VALID_EVIDENCE = {
  readiness_id: 'support_readiness_2026_07_02_staging',
  environment: 'staging',
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
    tabletop_id: 'tabletop_2026_07_01_soc_escalation',
    conducted_at: '2026-07-01T18:00:00.000Z',
    scenario_reference: 'scenario://drills/agent-mass-offline-s2',
    owner: 'incident-commander',
    evidence_uri: 'evidence://support/tabletop/2026-07-01',
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
    signed_at: '2026-07-02T12:00:00.000Z',
    signoff_reference: 'signoff://support/readiness-ga-prep',
  },
};

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-support-evidence-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('support readiness evidence validator', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseSupportReadinessEvidenceArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/support-readiness-evidence.json',
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(
      parseSupportReadinessEvidenceArgs(['--input', 'evidence.json', '--out', 'out.json', '--validate-only']),
      {
        input: 'evidence.json',
        out: 'out.json',
        validateOnly: true,
        help: false,
      },
    );
    assert.throws(() => parseSupportReadinessEvidenceArgs([]), /--input is required/);
  });

  it('accepts complete valid metadata-only evidence', () => {
    const result = validateSupportReadinessEvidence(VALID_EVIDENCE);
    assert.equal(result.ok, true);
    assert.deepEqual(result.missing_fields, []);
    assert.deepEqual(result.forbidden_fields, []);
    assert.equal(result.missing_owner, false);
    assert.equal(result.missing_sla, false);
    assert.equal(result.missing_tabletop, false);
    assert.equal(result.missing_signoff, false);
  });

  it('fails when SLA policy or support signoff is missing', () => {
    const missingSla = {
      ...VALID_EVIDENCE,
      sla_policy: { policy_reference: 'policy://support/empty' },
    };
    const slaResult = validateSupportReadinessEvidence(missingSla);
    assert.equal(slaResult.ok, false);
    assert.equal(slaResult.missing_sla, true);
    assert.ok(slaResult.missing_fields.some((f) => f.startsWith('sla_policy')));

    const missingSignoff = {
      ...VALID_EVIDENCE,
      support_signoff: {
        signoff_owner: 'support-operations-lead',
        signed_at: '2026-07-02T12:00:00.000Z',
      },
    };
    const signoffResult = validateSupportReadinessEvidence(missingSignoff);
    assert.equal(signoffResult.ok, false);
    assert.equal(signoffResult.missing_signoff, true);
    assert.ok(signoffResult.missing_fields.includes('support_signoff.signoff_reference'));
  });

  it('fails when on-call owner or incident tabletop owner is missing', () => {
    const missingRotationOwner = {
      ...VALID_EVIDENCE,
      on_call_rotation: {
        rotation_name: 'platform-primary',
        schedule_reference: 'pagerduty://services/astranull-platform-primary',
      },
    };
    const ownerResult = validateSupportReadinessEvidence(missingRotationOwner);
    assert.equal(ownerResult.ok, false);
    assert.equal(ownerResult.missing_owner, true);
    assert.ok(ownerResult.missing_fields.includes('on_call_rotation.owner'));

    const missingTabletopOwner = {
      ...VALID_EVIDENCE,
      incident_tabletop: {
        ...VALID_EVIDENCE.incident_tabletop,
        owner: '',
      },
    };
    const tabletopResult = validateSupportReadinessEvidence(missingTabletopOwner);
    assert.equal(tabletopResult.ok, false);
    assert.equal(tabletopResult.missing_tabletop, true);
    assert.ok(tabletopResult.missing_fields.includes('incident_tabletop.owner'));
  });

  it('rejects forbidden raw ticket, log, and attachment fields', () => {
    const withTicket = { ...VALID_EVIDENCE, ticket: { id: 'INC-100', body: 'customer said service down' } };
    const ticketResult = validateSupportReadinessEvidence(withTicket);
    assert.equal(ticketResult.ok, false);
    assert.ok(ticketResult.forbidden_fields.includes('ticket'));

    const withLog = {
      ...VALID_EVIDENCE,
      incident_tabletop: {
        ...VALID_EVIDENCE.incident_tabletop,
        logs: ['stderr from rehearsal'],
      },
    };
    const logResult = validateSupportReadinessEvidence(withLog);
    assert.equal(logResult.ok, false);
    assert.deepEqual(logResult.forbidden_fields, ['incident_tabletop.logs']);

    const withAttachment = {
      ...VALID_EVIDENCE,
      attachments: [{ filename: 'paste.txt', raw_log: 'secret paste' }],
    };
    const attachmentResult = validateSupportReadinessEvidence(withAttachment);
    assert.equal(attachmentResult.ok, false);
    assert.deepEqual(attachmentResult.forbidden_fields.sort(), ['attachments', 'attachments[0].raw_log']);
  });

  it('rejects token patterns in evidence_uri without requiring email-like strings', () => {
    const evidence = {
      ...VALID_EVIDENCE,
      incident_tabletop: {
        ...VALID_EVIDENCE.incident_tabletop,
        evidence_uri: 'ast_v1.fake.fake.fake',
      },
    };
    const result = validateSupportReadinessEvidence(evidence);
    assert.equal(result.ok, false);
    assert.ok(
      result.forbidden_fields.some((field) => field.includes('incident_tabletop.evidence_uri')),
    );
    assert.ok(result.forbidden_fields.some((field) => field.includes('token_pattern')));

    const manifest = createSupportReadinessEvidenceManifest({
      evidence,
      validation: result,
    });
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
  });

  it('rejects emails or contact strings that embed secrets', () => {
    const withSecretEmail = {
      ...VALID_EVIDENCE,
      escalation_contacts: [
        {
          role: 'support',
          contact_reference: 'ops-leak@example.invalid password=supersecret',
        },
      ],
    };
    const result = validateSupportReadinessEvidence(withSecretEmail);
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.some((f) => f.includes('password_in_text')));
  });

  it('writes redacted manifest and exits nonzero on validation failure', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, {
      ...VALID_EVIDENCE,
      notes: 'rehearsal carried ast_v1.fake.fake.fake in runbook notes',
      support_signoff: {
        signoff_owner: 'support-operations-lead',
        signed_at: '2026-07-02T12:00:00.000Z',
      },
      token: 'must-not-appear',
    });

    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 1);
    assert.equal(existsSync(out), true);

    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.artifact_type, 'support_on_call_readiness_evidence');
    assert.equal(manifest.validation.ok, false);
    assert.equal(manifest.validation.missing_signoff, true);
    assert.equal(manifest.readiness_summary.readiness_id, VALID_EVIDENCE.readiness_id);

    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('must-not-appear'), false);
    assert.match(blob, /\[REDACTED\]/);
  });

  it('validate-only succeeds for valid evidence without writing output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, VALID_EVIDENCE);

    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('createSupportReadinessEvidenceManifest omits forbidden extras from summary', () => {
    const manifest = createSupportReadinessEvidenceManifest({
      evidence: {
        ...VALID_EVIDENCE,
        customer_payload: { tenant: 'secret' },
      },
      validation: validateSupportReadinessEvidence(VALID_EVIDENCE),
    });
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('customer_payload'), false);
    assert.equal(manifest.validation.ok, true);
  });
});