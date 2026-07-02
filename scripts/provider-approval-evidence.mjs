#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildProviderApprovalMetadata,
  getProviderApprovalPath,
  normalizeProviderKey,
  providerApprovalMissingFields,
} from '../src/contracts/providerApprovalPaths.mjs';
import {
  collectForbiddenEvidenceFields,
  collectForbiddenEvidenceStringPatterns,
  redactObject,
  sanitizeForbiddenFieldPaths,
} from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/provider-approval-evidence.json';

const SOC_REQUIRED_FIELDS = Object.freeze([
  'authorized_scope_hash',
  'soc_reviewer',
  'legal_signoff',
  'custody_ids',
]);

const LEGAL_SIGNOFF_REQUIRED_FIELDS = Object.freeze(['reference', 'signed_at']);

const FORBIDDEN_KEYS = new Set([
  'authorization',
  'body',
  'connection_string',
  'credential',
  'credentials',
  'database_url',
  'headers',
  'ip_inventory',
  'ip_list',
  'log_blob',
  'packet',
  'packet_payload',
  'password',
  'payload',
  'raw_body',
  'raw_headers',
  'raw_log',
  'raw_packet',
  'secret',
  'target_ip_inventory',
  'target_ips',
  'token',
]);

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0) return false;
  return true;
}

function collectForbiddenFields(value, pathPrefix = '') {
  return collectForbiddenEvidenceFields(value, pathPrefix, {
    extraForbiddenKeys: FORBIDDEN_KEYS,
  });
}

function providerApprovalRecord(evidence) {
  const nested = evidence?.provider_approval;
  const base = nested && typeof nested === 'object' ? { ...nested } : {};
  return {
    ...base,
    provider_key: evidence?.provider_key ?? base.provider_key,
    provider_name: evidence?.provider_name ?? base.provider_name,
    approval_reference: evidence?.approval_reference ?? base.approval_reference,
    valid_window: evidence?.valid_window ?? base.valid_window,
    approved_targets: evidence?.approved_targets ?? base.approved_targets,
    approved_scenario_families: evidence?.approved_scenario_families ?? base.approved_scenario_families,
    contact_path: evidence?.contact_path ?? base.contact_path,
    approved_limits: evidence?.approved_limits ?? base.approved_limits,
    provider_specific_evidence: evidence?.provider_specific_evidence ?? base.provider_specific_evidence,
    emergency_stop_path: evidence?.emergency_stop_path ?? base.emergency_stop_path,
  };
}

function validWindowEnd(validWindow) {
  if (!validWindow || typeof validWindow !== 'object') return null;
  const raw = validWindow.valid_to ?? validWindow.end ?? validWindow.window_end;
  if (!raw) return null;
  const parsed = Date.parse(String(raw));
  return Number.isNaN(parsed) ? null : parsed;
}

function isApprovalExpired(evidence, asOfMs) {
  const endMs = validWindowEnd(providerApprovalRecord(evidence).valid_window);
  if (endMs == null) return false;
  return endMs < asOfMs;
}

function missingSocFields(evidence) {
  const missing = SOC_REQUIRED_FIELDS.filter((field) => !hasValue(evidence?.[field]));
  if (hasValue(evidence?.legal_signoff) && typeof evidence.legal_signoff === 'object') {
    for (const field of LEGAL_SIGNOFF_REQUIRED_FIELDS) {
      if (!hasValue(evidence.legal_signoff[field])) {
        missing.push(`legal_signoff.${field}`);
      }
    }
  }
  return missing;
}

function uncoveredScenarioFamilies(evidence) {
  const requested = Array.isArray(evidence?.requested_scenario_families)
    ? evidence.requested_scenario_families.map(String)
    : [];
  if (requested.length === 0) return [];
  const approved = providerApprovalRecord(evidence).approved_scenario_families;
  const approvedSet = new Set(Array.isArray(approved) ? approved.map(String) : []);
  return requested.filter((family) => !approvedSet.has(family));
}

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    validateOnly: false,
    asOf: null,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--as-of') opts.asOf = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.input) throw new Error('--input is required');
  return opts;
}

function parseInputJson(inputPath) {
  const parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
  throw new Error('Input must be a JSON object.');
}

export function validateProviderApprovalEvidence(evidence, options = {}) {
  const asOfMs = options.asOfMs ?? Date.now();
  const providerItem = providerApprovalRecord(evidence);
  const providerKey = normalizeProviderKey(providerItem.provider_key ?? providerItem.provider_name ?? evidence);
  const profile = getProviderApprovalPath(providerKey);

  const missing_provider_fields = providerApprovalMissingFields(providerItem);
  const missing_soc_fields = missingSocFields(evidence);
  const uncovered_scenario_families = uncoveredScenarioFamilies(evidence);
  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(evidence),
      ...collectForbiddenEvidenceStringPatterns(evidence),
    ]),
  ].sort();
  const expired = isApprovalExpired(evidence, asOfMs);

  const missing_requirements = [
    ...missing_soc_fields,
    ...missing_provider_fields.map((field) => `provider_approval.${field}`),
    ...(uncovered_scenario_families.length > 0
      ? uncovered_scenario_families.map((family) => `scenario_family:${family}`)
      : []),
    ...(expired ? ['approval_expired'] : []),
  ];

  const ok =
    missing_requirements.length === 0
    && forbidden_fields.length === 0
    && !expired;

  return {
    ok,
    provider_key: providerKey,
    approval_path: profile.approval_path,
    missing_requirements,
    missing_provider_fields,
    missing_soc_fields,
    uncovered_scenario_families,
    forbidden_fields,
    expired,
    provider_metadata: buildProviderApprovalMetadata(providerItem),
  };
}

function buildRedactedMetadata(evidence, validation) {
  const providerItem = providerApprovalRecord(evidence);
  return redactObject({
    high_scale_request_id: evidence?.high_scale_request_id ?? null,
    requested_scenario_families: evidence?.requested_scenario_families ?? [],
    authorized_scope_hash: evidence?.authorized_scope_hash ?? null,
    soc_reviewer: evidence?.soc_reviewer ?? null,
    legal_signoff: evidence?.legal_signoff ?? null,
    custody_ids: evidence?.custody_ids ?? [],
    provider_key: validation.provider_key,
    approval_path: validation.approval_path,
    provider_approval: {
      provider_name: providerItem.provider_name ?? null,
      approval_reference: providerItem.approval_reference ?? null,
      valid_window: providerItem.valid_window ?? null,
      approved_targets: providerItem.approved_targets ?? [],
      approved_scenario_families: providerItem.approved_scenario_families ?? [],
      contact_path: providerItem.contact_path ?? null,
      approved_limits: providerItem.approved_limits ?? null,
      provider_specific_evidence: providerItem.provider_specific_evidence ?? null,
      emergency_stop_path: providerItem.emergency_stop_path ?? null,
    },
    provider_review_summary: validation.provider_metadata.soc_review_summary,
  }, 0, { omitSensitiveKeys: true });
}

export function createProviderApprovalEvidenceManifest(input = {}) {
  const evidence = input.evidence ?? {};
  const asOfMs = input.asOfMs ?? Date.now();
  const validation = validateProviderApprovalEvidence(evidence, { asOfMs });
  return {
    schema_version: 1,
    artifact_type: 'provider_approval_evidence',
    created_at: input.createdAt ?? new Date(asOfMs).toISOString(),
    validation: {
      ok: validation.ok,
      missing_requirements: validation.missing_requirements,
      forbidden_fields: sanitizeForbiddenFieldPaths(validation.forbidden_fields),
      expired: validation.expired,
      uncovered_scenario_families: validation.uncovered_scenario_families,
    },
    metadata: buildRedactedMetadata(evidence, validation),
    caveats: [
      'Manifest records metadata-only provider approval evidence for SOC high-scale readiness review.',
      'Production scheduling still requires durable document custody, legal retention, and live provider coordination.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/provider-approval-evidence.mjs --input evidence.json [--out file] [--as-of ISO] [--validate-only]',
    );
    return 0;
  }

  const evidence = parseInputJson(opts.input);
  const asOfMs = opts.asOf ? Date.parse(opts.asOf) : Date.now();
  if (opts.asOf && Number.isNaN(asOfMs)) {
    throw new Error(`Invalid --as-of timestamp: ${opts.asOf}`);
  }

  const manifest = createProviderApprovalEvidenceManifest({ evidence, asOfMs });

  if (!manifest.validation.ok) {
    const parts = [];
    if (manifest.validation.missing_requirements.length > 0) {
      parts.push(`missing: ${manifest.validation.missing_requirements.join(', ')}`);
    }
    if (manifest.validation.forbidden_fields.length > 0) {
      parts.push(`forbidden: ${manifest.validation.forbidden_fields.join(', ')}`);
    }
    if (!opts.validateOnly) {
      mkdirSync(path.dirname(opts.out), { recursive: true });
      writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
      console.log(`provider-approval-evidence: wrote ${opts.out}`);
    }
    throw new Error(`Provider approval evidence invalid (${parts.join('; ')})`);
  }

  if (opts.validateOnly) {
    console.log(`provider-approval-evidence: ok (provider=${manifest.metadata.provider_key})`);
    return 0;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`provider-approval-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`provider-approval-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}