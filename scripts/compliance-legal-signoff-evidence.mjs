#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeReportKind, REPORT_KINDS } from '../src/contracts/complianceReports.mjs';
import { validateProductionReleaseEvidence } from '../src/contracts/productionReleaseEvidence.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/compliance-legal-signoff-evidence.json';

export const COMPLIANCE_LEGAL_SIGNOFF_REQUIRED_FIELDS = Object.freeze([
  'legal_owner',
  'auditor_owner',
  'signoffs',
  'reviewed_templates',
  'review_date',
  'caveats',
  'evidence_uri',
]);

export const FRAMEWORK_REVIEW_KINDS = Object.freeze([
  'soc2',
  'iso27001',
  'dora',
  'nis2',
  'internal_audit',
]);

const SIGNOFF_REQUIRED_FIELDS = Object.freeze(['role', 'signed_at']);

const REVIEWED_TEMPLATE_REQUIRED_FIELDS = Object.freeze(['review_date', 'signoff_reference']);

const FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'attachment',
  'attachments',
  'authorization',
  'body',
  'connection_string',
  'contract',
  'contract_attachment',
  'contract_body',
  'contracts',
  'credential',
  'credentials',
  'customer_data',
  'customer_payload',
  'database_url',
  'headers',
  'legal_document',
  'legal_doc',
  'log',
  'logs',
  'password',
  'payload',
  'raw_body',
  'raw_headers',
  'raw_legal',
  'raw_log',
  'secret',
  'token',
]);

const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;

const SECRET_IN_STRING_PATTERNS = [
  { pattern: /ast_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/, reason: 'token_pattern' },
  { pattern: /password\s*[:=]\s*\S+/i, reason: 'password_in_text' },
  { pattern: /api[_-]?key\s*[:=]\s*\S+/i, reason: 'api_key_in_text' },
];

const LEGAL_SIGNOFF_ROLES = new Set(['legal', 'legal_owner', 'general_counsel']);
const AUDITOR_SIGNOFF_ROLES = new Set(['auditor', 'auditor_owner', 'compliance', 'internal_audit']);

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

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
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenFields(entry, `${fieldPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = fieldPath ? `${fieldPath}.${key}` : key;
    const normalized = normalizeKey(key);
    if (
      FORBIDDEN_KEYS.has(normalized)
      || normalized.startsWith('raw_')
      || normalized.includes('customer_payload')
      || normalized.includes('customer_data')
    ) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenFields(nested, keyPath));
  }
  return findings;
}

function collectForbiddenStringPatterns(value, fieldPath = '') {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') {
    const findings = [];
    if (PG_URL_RE.test(value)) {
      PG_URL_RE.lastIndex = 0;
      findings.push(`${fieldPath}:database_url_pattern`);
    }
    for (const { pattern, reason } of SECRET_IN_STRING_PATTERNS) {
      if (pattern.test(value)) {
        pattern.lastIndex = 0;
        findings.push(`${fieldPath}:${reason}`);
      }
    }
    return findings;
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) =>
      collectForbiddenStringPatterns(entry, `${fieldPath}[${index}]`),
    );
  }
  if (typeof value === 'object') {
    return Object.entries(value).flatMap(([key, nested]) =>
      collectForbiddenStringPatterns(nested, fieldPath ? `${fieldPath}.${key}` : key),
    );
  }
  return [];
}

function signoffReference(entry) {
  if (!isObject(entry)) return null;
  return entry.signoff_reference ?? entry.reference ?? null;
}

function resolveTemplateKind(entry) {
  if (!isObject(entry)) return null;
  if (hasValue(entry.template_kind)) {
    return normalizeReportKind(entry.template_kind);
  }
  if (hasValue(entry.kind)) {
    return normalizeReportKind(entry.kind);
  }
  if (hasValue(entry.template_id)) {
    const normalized = normalizeReportKind(entry.template_id);
    if (REPORT_KINDS.includes(normalized) && normalized !== 'technical') {
      return normalized;
    }
  }
  return null;
}

function hasLocalContractName(entry) {
  if (!isObject(entry)) return false;
  return hasValue(entry.local_contract_name) || hasValue(entry.template_id);
}

function validateReviewedTemplates(templates) {
  const missing = [];
  const gaps = [];
  let hasFrameworkTemplate = false;
  let hasLocalContract = false;

  if (!Array.isArray(templates) || templates.length === 0) {
    return {
      missing: ['reviewed_templates'],
      reviewed_template_gaps: true,
      missing_framework_templates: FRAMEWORK_REVIEW_KINDS.map((kind) => `framework:${kind}`),
    };
  }

  templates.forEach((entry, index) => {
    const prefix = `reviewed_templates[${index}]`;
    if (!isObject(entry)) {
      missing.push(prefix);
      gaps.push(`${prefix}:invalid_entry`);
      return;
    }

    const templateKind = resolveTemplateKind(entry);
    const localContract = hasLocalContractName(entry);
    if (templateKind && FRAMEWORK_REVIEW_KINDS.includes(templateKind)) {
      hasFrameworkTemplate = true;
    } else if (localContract) {
      hasLocalContract = true;
    } else {
      gaps.push(`${prefix}.template_kind`);
      missing.push(`${prefix}.template_kind`);
    }

    for (const field of REVIEWED_TEMPLATE_REQUIRED_FIELDS) {
      if (field === 'signoff_reference') {
        if (!hasValue(signoffReference(entry))) {
          missing.push(`${prefix}.signoff_reference`);
        }
        continue;
      }
      if (!hasValue(entry[field])) {
        missing.push(`${prefix}.${field}`);
      }
    }
  });

  const missing_framework_templates = [];
  if (!hasFrameworkTemplate && !hasLocalContract) {
    for (const kind of FRAMEWORK_REVIEW_KINDS) {
      missing_framework_templates.push(`framework:${kind}`);
    }
  }

  return {
    missing,
    reviewed_template_gaps:
      gaps.length > 0
      || missing.some((field) => field.startsWith('reviewed_templates'))
      || missing_framework_templates.length > 0,
    missing_framework_templates,
  };
}

function validateSignoffs(signoffs) {
  const missing = [];
  let hasLegal = false;
  let hasAuditor = false;

  if (!Array.isArray(signoffs) || signoffs.length === 0) {
    return {
      missing: ['signoffs'],
      missing_signoffs: true,
      missing_legal_signoff: true,
      missing_auditor_signoff: true,
    };
  }

  signoffs.forEach((entry, index) => {
    const prefix = `signoffs[${index}]`;
    if (!isObject(entry)) {
      missing.push(prefix);
      return;
    }
    for (const field of SIGNOFF_REQUIRED_FIELDS) {
      if (!hasValue(entry[field])) {
        missing.push(`${prefix}.${field}`);
      }
    }
    if (!hasValue(signoffReference(entry))) {
      missing.push(`${prefix}.signoff_reference`);
    }

    const role = String(entry.role ?? '').trim().toLowerCase();
    if (LEGAL_SIGNOFF_ROLES.has(role)) hasLegal = true;
    if (AUDITOR_SIGNOFF_ROLES.has(role)) hasAuditor = true;
  });

  if (!hasLegal) {
    missing.push('signoffs.legal');
  }
  if (!hasAuditor) {
    missing.push('signoffs.auditor');
  }

  return {
    missing,
    missing_signoffs: !hasLegal || !hasAuditor,
    missing_legal_signoff: !hasLegal,
    missing_auditor_signoff: !hasAuditor,
  };
}

function normalizeSignoffs(signoffs) {
  if (!Array.isArray(signoffs)) return [];
  return signoffs.map((entry) => {
    if (!isObject(entry)) return entry;
    const reference = signoffReference(entry);
    return {
      role: entry.role ?? null,
      reference: reference ?? null,
      signed_at: entry.signed_at ?? null,
    };
  });
}

function normalizeReviewedTemplates(templates) {
  if (!Array.isArray(templates)) return [];
  return templates.map((entry) => {
    if (!isObject(entry)) return entry;
    const templateKind = resolveTemplateKind(entry);
    return {
      template_kind: templateKind,
      template_id: entry.template_id ?? entry.local_contract_name ?? null,
      local_contract_name: entry.local_contract_name ?? null,
      review_status: entry.review_status ?? null,
      review_date: entry.review_date ?? null,
      signoff_reference: signoffReference(entry),
      evidence_uri: entry.evidence_uri ?? null,
    };
  });
}

/**
 * @param {unknown} pack
 * @param {{ releaseId?: string | null }} [options]
 */
export function validateComplianceLegalSignoffEvidence(pack, options = {}) {
  const missing_fields = COMPLIANCE_LEGAL_SIGNOFF_REQUIRED_FIELDS.filter(
    (field) => !hasValue(pack?.[field]),
  );

  const release_id = options.releaseId ?? pack?.release_id;
  if (!hasValue(release_id)) {
    missing_fields.push('release_id');
  }

  const missing_owner = !hasValue(pack?.legal_owner) || !hasValue(pack?.auditor_owner);
  if (!hasValue(pack?.legal_owner)) {
    missing_fields.push('legal_owner');
  }
  if (!hasValue(pack?.auditor_owner)) {
    missing_fields.push('auditor_owner');
  }

  const signoffResult = validateSignoffs(pack?.signoffs);
  missing_fields.push(...signoffResult.missing);

  const templateResult = validateReviewedTemplates(pack?.reviewed_templates);
  missing_fields.push(...templateResult.missing);

  if (Array.isArray(pack?.caveats) && pack.caveats.length === 0) {
    if (!missing_fields.includes('caveats')) {
      missing_fields.push('caveats');
    }
  }

  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(pack),
      ...collectForbiddenStringPatterns(pack),
    ]),
  ].sort();

  const uniqueMissing = [...new Set(missing_fields)].sort();

  const ok =
    uniqueMissing.length === 0
    && forbidden_fields.length === 0
    && !missing_owner
    && !signoffResult.missing_signoffs
    && !templateResult.reviewed_template_gaps;

  return {
    ok,
    release_id: release_id ?? null,
    missing_fields: uniqueMissing,
    forbidden_fields,
    missing_owner,
    missing_signoffs: signoffResult.missing_signoffs,
    missing_legal_signoff: signoffResult.missing_legal_signoff,
    missing_auditor_signoff: signoffResult.missing_auditor_signoff,
    reviewed_template_gaps: templateResult.reviewed_template_gaps,
    missing_framework_templates: templateResult.missing_framework_templates,
  };
}

/**
 * @param {Record<string, unknown>} pack
 * @param {ReturnType<typeof validateComplianceLegalSignoffEvidence>} validation
 * @param {{ createdAt?: string, releaseId?: string | null }} [options]
 */
export function buildComplianceLegalSignoffProductionEvidence(pack, validation, options = {}) {
  const redacted = redactObject(pack);
  const releaseId = options.releaseId ?? validation.release_id ?? redacted.release_id ?? null;
  return {
    schema_version: 1,
    artifact_type: 'compliance_legal_signoff_evidence',
    created_at: options.createdAt ?? new Date().toISOString(),
    release_id: releaseId,
    legal_owner: redacted.legal_owner ?? null,
    auditor_owner: redacted.auditor_owner ?? null,
    signoffs: normalizeSignoffs(redacted.signoffs),
    reviewed_templates: normalizeReviewedTemplates(redacted.reviewed_templates),
    evidence_uri: redacted.evidence_uri ?? null,
    review_date: redacted.review_date ?? null,
    caveats: Array.isArray(redacted.caveats) ? redacted.caveats : [],
    validation: {
      ok: validation.ok,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
      missing_owner: validation.missing_owner,
      missing_signoffs: validation.missing_signoffs,
      reviewed_template_gaps: validation.reviewed_template_gaps,
      production_release_contract: validateProductionReleaseEvidence(
        'compliance_legal_signoff',
        {
          schema_version: 1,
          artifact_type: 'compliance_legal_signoff_evidence',
          created_at: options.createdAt ?? new Date().toISOString(),
          release_id: releaseId,
          legal_owner: redacted.legal_owner ?? null,
          auditor_owner: redacted.auditor_owner ?? null,
          signoffs: normalizeSignoffs(redacted.signoffs),
          reviewed_templates: normalizeReviewedTemplates(redacted.reviewed_templates),
          evidence_uri: redacted.evidence_uri ?? null,
        },
      ),
    },
    ...(typeof pack?.notes === 'string' ? { notes: redactString(pack.notes) } : {}),
  };
}

export function createComplianceLegalSignoffEvidenceManifest(input = {}) {
  const pack = input.pack ?? {};
  const validation = input.validation ?? validateComplianceLegalSignoffEvidence(pack, {
    releaseId: input.releaseId,
  });
  return buildComplianceLegalSignoffProductionEvidence(pack, validation, {
    createdAt: input.createdAt,
    releaseId: input.releaseId ?? validation.release_id,
  });
}

export function parseComplianceLegalSignoffEvidenceArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    releaseId: null,
    validateOnly: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) {
        throw new Error(`compliance-legal-signoff-evidence: missing value for ${arg}`);
      }
      return argv[i];
    };
    if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`compliance-legal-signoff-evidence: unknown argument ${arg}`);
  }
  if (!opts.help && !opts.input) {
    throw new Error('compliance-legal-signoff-evidence: --input is required');
  }
  return opts;
}

function readSignoffPack(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`compliance-legal-signoff-evidence: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('compliance-legal-signoff-evidence: input must be a JSON object');
  }
  if (parsed.evidence && typeof parsed.evidence === 'object' && !Array.isArray(parsed.evidence)) {
    return parsed.evidence;
  }
  return parsed;
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseComplianceLegalSignoffEvidenceArgs(argv);
  if (opts.help) {
    console.log(`Usage: node scripts/compliance-legal-signoff-evidence.mjs --input evidence.json [--out output/compliance-legal-signoff-evidence.json] [--release-id rel] [--validate-only]

Validates metadata-only compliance and legal/auditor signoff packs for production release readiness.
Covers reviewed compliance templates (SOC 2, ISO 27001, DORA, NIS2, internal audit, or local contract names),
legal owner, auditor owner, signoff references, review date, caveats, and evidence_uri.
Rejects contracts as attachments, raw legal documents, customer data, credentials, tokens, logs, payloads,
database URLs, and raw body/header fields.`);
    return 0;
  }

  const pack = readSignoffPack(opts.input);
  const validation = validateComplianceLegalSignoffEvidence(pack, { releaseId: opts.releaseId });
  const manifest = createComplianceLegalSignoffEvidenceManifest({
    pack,
    validation,
    releaseId: opts.releaseId,
  });

  if (opts.validateOnly) {
    console.log(
      `compliance-legal-signoff-evidence: ${validation.ok ? 'ok' : 'failed'} (release_id=${manifest.release_id ?? 'none'})`,
    );
    return validation.ok ? 0 : 1;
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`compliance-legal-signoff-evidence: wrote ${opts.out}`);
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