#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  collectForbiddenEvidenceFields,
  collectForbiddenEvidenceStringPatterns,
  redactObject,
  redactString,
  sanitizeForbiddenFieldPaths,
} from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/support-readiness-evidence.json';

export const SUPPORT_READINESS_REQUIRED_FIELDS = Object.freeze([
  'readiness_id',
  'environment',
  'on_call_rotation',
  'escalation_contacts',
  'sla_policy',
  'incident_tabletop',
  'soc_escalation_path',
  'customer_comms_templates',
  'support_signoff',
]);

const ON_CALL_ROTATION_REQUIRED = Object.freeze(['rotation_name', 'owner', 'schedule_reference']);

const ESCALATION_CONTACT_REQUIRED = Object.freeze(['role', 'contact_reference']);

const SLA_POLICY_REQUIRED = Object.freeze(['policy_reference', 'severity_tiers']);

const INCIDENT_TABLETOP_REQUIRED = Object.freeze([
  'tabletop_id',
  'conducted_at',
  'scenario_reference',
  'owner',
  'evidence_uri',
]);

const SOC_ESCALATION_REQUIRED = Object.freeze(['path_reference', 'severity_routes']);

const COMMS_TEMPLATE_REQUIRED = Object.freeze(['template_id', 'purpose', 'reference_uri']);

const SUPPORT_SIGNOFF_REQUIRED = Object.freeze(['signoff_owner', 'signed_at', 'signoff_reference']);

const FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'attachment',
  'attachments',
  'authorization',
  'body',
  'credential',
  'credentials',
  'customer_payload',
  'email_body',
  'log',
  'logs',
  'password',
  'payload',
  'raw_body',
  'raw_email',
  'raw_headers',
  'raw_log',
  'raw_ticket',
  'secret',
  'ticket',
  'ticket_body',
  'ticket_content',
  'ticket_payload',
  'tickets',
  'token',
]);

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function collectForbiddenFields(value, fieldPath = '') {
  return collectForbiddenEvidenceFields(value, fieldPath, {
    extraForbiddenKeys: FORBIDDEN_KEYS,
    extraForbiddenPredicate: (normalized) => normalized.includes('customer_payload'),
  });
}

function collectForbiddenStringPatterns(value, fieldPath = '') {
  return collectForbiddenEvidenceStringPatterns(value, fieldPath);
}

function missingNestedFields(object, requiredFields, prefix) {
  if (!isObject(object)) {
    return requiredFields.map((field) => `${prefix}.${field}`);
  }
  return requiredFields
    .filter((field) => !hasValue(object[field]))
    .map((field) => `${prefix}.${field}`);
}

function validateEscalationContacts(contacts) {
  const missing = [];
  if (!Array.isArray(contacts) || contacts.length === 0) {
    return { missing: ['escalation_contacts'], missing_owner: true };
  }
  let missingOwner = false;
  contacts.forEach((entry, index) => {
    if (!isObject(entry)) {
      missing.push(`escalation_contacts[${index}]`);
      missingOwner = true;
      return;
    }
    for (const field of ESCALATION_CONTACT_REQUIRED) {
      if (!hasValue(entry[field])) {
        missing.push(`escalation_contacts[${index}].${field}`);
        if (field === 'role' && !['soc', 'support', 'engineering'].includes(entry.role)) {
          // role still required; owner tracked via on_call_rotation.owner
        }
      }
    }
  });
  return { missing, missing_owner: missingOwner };
}

function validateSlaPolicy(slaPolicy) {
  const missing = missingNestedFields(slaPolicy, SLA_POLICY_REQUIRED, 'sla_policy');
  const missing_sla = missing.length > 0
    || !Array.isArray(slaPolicy?.severity_tiers)
    || slaPolicy.severity_tiers.length === 0;
  if (Array.isArray(slaPolicy?.severity_tiers)) {
    slaPolicy.severity_tiers.forEach((tier, index) => {
      if (!isObject(tier)) {
        missing.push(`sla_policy.severity_tiers[${index}]`);
        return;
      }
      if (!hasValue(tier.severity)) missing.push(`sla_policy.severity_tiers[${index}].severity`);
      if (!Number.isFinite(tier.response_minutes) || tier.response_minutes < 0) {
        missing.push(`sla_policy.severity_tiers[${index}].response_minutes`);
      }
    });
  }
  return { missing, missing_sla };
}

function validateIncidentTabletop(tabletop) {
  const missing = missingNestedFields(tabletop, INCIDENT_TABLETOP_REQUIRED, 'incident_tabletop');
  const missing_tabletop = missing.some((f) => f.startsWith('incident_tabletop'))
    || !hasValue(tabletop?.owner);
  if (isObject(tabletop) && !hasValue(tabletop.owner)) {
    if (!missing.includes('incident_tabletop.owner')) {
      missing.push('incident_tabletop.owner');
    }
  }
  return { missing, missing_tabletop };
}

function validateSocEscalationPath(socPath) {
  const missing = missingNestedFields(socPath, SOC_ESCALATION_REQUIRED, 'soc_escalation_path');
  if (Array.isArray(socPath?.severity_routes) && socPath.severity_routes.length > 0) {
    socPath.severity_routes.forEach((route, index) => {
      if (!isObject(route)) {
        missing.push(`soc_escalation_path.severity_routes[${index}]`);
        return;
      }
      if (!hasValue(route.severity)) {
        missing.push(`soc_escalation_path.severity_routes[${index}].severity`);
      }
      if (!hasValue(route.escalation_reference)) {
        missing.push(`soc_escalation_path.severity_routes[${index}].escalation_reference`);
      }
    });
  } else if (isObject(socPath)) {
    missing.push('soc_escalation_path.severity_routes');
  }
  return { missing };
}

function validateCustomerCommsTemplates(templates) {
  const missing = [];
  if (!Array.isArray(templates) || templates.length === 0) {
    return ['customer_comms_templates'];
  }
  templates.forEach((entry, index) => {
    if (!isObject(entry)) {
      missing.push(`customer_comms_templates[${index}]`);
      return;
    }
    for (const field of COMMS_TEMPLATE_REQUIRED) {
      if (!hasValue(entry[field])) {
        missing.push(`customer_comms_templates[${index}].${field}`);
      }
    }
  });
  return missing;
}

function validateSupportSignoff(signoff) {
  const missing = missingNestedFields(signoff, SUPPORT_SIGNOFF_REQUIRED, 'support_signoff');
  const missing_signoff = missing.length > 0;
  return { missing, missing_signoff };
}

function validateOnCallRotation(rotation) {
  const missing = missingNestedFields(rotation, ON_CALL_ROTATION_REQUIRED, 'on_call_rotation');
  const missing_owner = !hasValue(rotation?.owner);
  if (missing_owner && !missing.includes('on_call_rotation.owner')) {
    missing.push('on_call_rotation.owner');
  }
  return { missing, missing_owner };
}

/**
 * @param {unknown} evidence
 */
export function validateSupportReadinessEvidence(evidence) {
  const missing_fields = SUPPORT_READINESS_REQUIRED_FIELDS.filter(
    (field) => !hasValue(evidence?.[field]),
  );

  const rotation = validateOnCallRotation(evidence?.on_call_rotation);
  missing_fields.push(...rotation.missing);

  const escalation = validateEscalationContacts(evidence?.escalation_contacts);
  missing_fields.push(...escalation.missing);

  const sla = validateSlaPolicy(evidence?.sla_policy);
  missing_fields.push(...sla.missing);

  const tabletop = validateIncidentTabletop(evidence?.incident_tabletop);
  missing_fields.push(...tabletop.missing);

  missing_fields.push(...validateSocEscalationPath(evidence?.soc_escalation_path).missing);
  missing_fields.push(...validateCustomerCommsTemplates(evidence?.customer_comms_templates));

  const signoff = validateSupportSignoff(evidence?.support_signoff);
  missing_fields.push(...signoff.missing);

  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(evidence),
      ...collectForbiddenStringPatterns(evidence),
    ]),
  ].sort();

  const missing_owner = rotation.missing_owner;
  const missing_sla = sla.missing_sla;
  const missing_tabletop = tabletop.missing_tabletop;
  const missing_signoff = signoff.missing_signoff;

  const uniqueMissing = [...new Set(missing_fields)].sort();

  const ok =
    uniqueMissing.length === 0
    && forbidden_fields.length === 0
    && !missing_owner
    && !missing_sla
    && !missing_tabletop
    && !missing_signoff;

  return {
    ok,
    missing_fields: uniqueMissing,
    forbidden_fields,
    missing_owner,
    missing_sla,
    missing_tabletop,
    missing_signoff,
  };
}

export function parseSupportReadinessEvidenceArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    validateOnly: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`support-readiness-evidence: missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`support-readiness-evidence: unknown argument ${arg}`);
  }
  if (!opts.help && !opts.input) {
    throw new Error('support-readiness-evidence: --input is required');
  }
  return opts;
}

function readEvidence(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`support-readiness-evidence: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('support-readiness-evidence: input must be a JSON object');
  }
  return parsed;
}

/**
 * @param {{ evidence: Record<string, unknown>, validation: ReturnType<typeof validateSupportReadinessEvidence>, createdAt?: string, notes?: string }} input
 */
export function createSupportReadinessEvidenceManifest(input) {
  const { evidence, validation, createdAt, notes } = input;
  const redactedEvidence = redactObject(evidence, 0, { omitSensitiveKeys: true });
  return {
    schema_version: 1,
    artifact_type: 'support_on_call_readiness_evidence',
    created_at: createdAt ?? new Date().toISOString(),
    validation: {
      ok: validation.ok,
      missing_fields: validation.missing_fields,
      forbidden_fields: sanitizeForbiddenFieldPaths(validation.forbidden_fields),
      missing_owner: validation.missing_owner,
      missing_sla: validation.missing_sla,
      missing_tabletop: validation.missing_tabletop,
      missing_signoff: validation.missing_signoff,
    },
    readiness_summary: {
      readiness_id: redactedEvidence.readiness_id ?? null,
      environment: redactedEvidence.environment ?? null,
      on_call_rotation: redactedEvidence.on_call_rotation
        ? {
            rotation_name: redactedEvidence.on_call_rotation.rotation_name ?? null,
            owner: redactedEvidence.on_call_rotation.owner ?? null,
            schedule_reference: redactedEvidence.on_call_rotation.schedule_reference ?? null,
          }
        : null,
      sla_policy_reference: redactedEvidence.sla_policy?.policy_reference ?? null,
      incident_tabletop_id: redactedEvidence.incident_tabletop?.tabletop_id ?? null,
      soc_escalation_path_reference: redactedEvidence.soc_escalation_path?.path_reference ?? null,
      customer_comms_template_count: Array.isArray(redactedEvidence.customer_comms_templates)
        ? redactedEvidence.customer_comms_templates.length
        : 0,
      support_signoff_owner: redactedEvidence.support_signoff?.signoff_owner ?? null,
    },
    ...(notes ? { notes: redactString(String(notes)) } : {}),
    caveats: [
      'Metadata-only support/on-call readiness manifest; no raw tickets, logs, customer payloads, attachments, or secrets.',
      'Named rotation, SLA policy, tabletop rehearsal, and support signoff must be recorded in immutable custody outside this validator.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseSupportReadinessEvidenceArgs(argv);
  if (opts.help) {
    console.log(`Usage: node scripts/support-readiness-evidence.mjs --input evidence.json [--out manifest.json] [--validate-only]

Validates metadata-only support/on-call readiness evidence (rotation, escalation contacts, SLA policy, incident tabletop, SOC escalation path, customer comms templates, support signoff).
Rejects raw tickets, logs, customer payloads, tokens, credentials, emails with secrets, and attachments. Writes a redacted manifest when --out is set.`);
    return 0;
  }

  const evidence = readEvidence(opts.input);
  const validation = validateSupportReadinessEvidence(evidence);
  const manifest = createSupportReadinessEvidenceManifest({
    evidence,
    validation,
    notes: typeof evidence.notes === 'string' ? evidence.notes : undefined,
  });

  if (opts.validateOnly) {
    console.log(
      `support-readiness-evidence: ${validation.ok ? 'ok' : 'failed'} (readiness_id=${manifest.readiness_summary.readiness_id ?? 'none'})`,
    );
    return validation.ok ? 0 : 1;
  }

  if (opts.out) {
    mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
    writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(`support-readiness-evidence: wrote ${opts.out}`);
  } else {
    console.log(`support-readiness-evidence: ${validation.ok ? 'ok' : 'failed'}`);
  }

  return validation.ok ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    },
  );
}