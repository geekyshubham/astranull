import { createHash } from 'node:crypto';
import { FORBIDDEN_RAW_RISK_KEYS } from '../contracts/supplyChainRisk.mjs';

export const SUPPLY_CHAIN_SOURCES = Object.freeze([
  'dangling_cname',
  'vendor_dependency',
]);

export const MAX_SUPPLY_CHAIN_INGEST_RECORDS = 500;

const FORBIDDEN_SUPPLY_CHAIN_RECORD_KEYS = new Set([
  ...FORBIDDEN_RAW_RISK_KEYS,
  'raw_log',
  'ct_log_entry',
  'ct_log',
  'certificate',
  'cert_pem',
  'pem',
  'der',
  'issuer_dn',
  'serial_number',
  'dns_zone_file',
  'ip_address',
  'ip',
  'ipv4',
  'ipv6',
  'a_record',
  'aaaa_record',
  'cname_target',
  'dns_response',
  'dns_lookup',
  'raw_page_body',
  'html_content',
  'page_source',
  'dependency_url',
  'script_url',
  'page_url',
  'redirect_url',
]);

const HOSTNAME_RE =
  /^(?=.{1,253}$)(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function contractError(message, code, extra = {}) {
  const err = new Error(message);
  err.code = code;
  Object.assign(err, extra);
  return err;
}

function normalizeFieldKey(key) {
  return String(key)
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function collectForbiddenSupplyChainKeys(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return [];
  }
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenSupplyChainKeys(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeFieldKey(key);
    if (FORBIDDEN_SUPPLY_CHAIN_RECORD_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenSupplyChainKeys(nested, keyPath));
  }
  return findings;
}

export function normalizeSupplyChainHostname(hostname) {
  return String(hostname ?? '').trim().toLowerCase();
}

export function isIpHostname(hostname) {
  const normalized = normalizeSupplyChainHostname(hostname);
  if (!normalized) return false;
  if (IPV4_RE.test(normalized)) return true;
  if (normalized.includes(':')) return true;
  return false;
}

export function buildSupplyChainSourceRef(source, hostname, observedAt) {
  const payload = [source, normalizeSupplyChainHostname(hostname), observedAt].join('|');
  const hash = createHash('sha256').update(payload, 'utf8').digest('hex').slice(0, 32);
  return `redacted:${source}:${hash}`;
}

function requireConfidence(value, fieldName) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0 || n > 1) {
    throw contractError(`${fieldName} must be a number between 0 and 1.`, 'invalid_supply_chain_source_record');
  }
  return n;
}

function requireIsoTimestamp(value, fieldName) {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) {
    throw contractError(`${fieldName} is required.`, 'invalid_supply_chain_source_record');
  }
  if (Number.isNaN(Date.parse(trimmed))) {
    throw contractError(`${fieldName} must be a valid ISO timestamp.`, 'invalid_supply_chain_source_record');
  }
  return trimmed;
}

function optionalTrimmedString(value) {
  return typeof value === 'string' && value.trim() ? value.trim() : '';
}

function defaultConfidenceForDanglingCname(record) {
  if (record.connector_confirmation === true) return 0.75;
  if (optionalTrimmedString(record.provider_error_signature_id)) return 0.7;
  if (optionalTrimmedString(record.cname_chain_hash)) return 0.4;
  return 0.35;
}

function defaultConfidenceForVendorDependency(record) {
  const statusCode = record.status_code !== undefined ? Number(record.status_code) : null;
  let confidence = 0.45;
  if (statusCode === 404 || statusCode === 410) confidence = 0.7;
  if (optionalTrimmedString(record.dependency_url_hash)) confidence = Math.min(1, confidence + 0.1);
  if (record.connector_confirmation === true) confidence = Math.min(1, confidence + 0.15);
  return confidence;
}

function parseSharedRecordFields(sourceName, record, index) {
  const recordSourceType = String(record.source_type ?? sourceName).trim();
  if (recordSourceType !== sourceName) {
    throw contractError(
      `records[${index}].source_type must match batch source ${sourceName}.`,
      'invalid_supply_chain_source_record',
      { record_index: index },
    );
  }

  const hostname = normalizeSupplyChainHostname(record.hostname);
  if (!hostname) {
    throw contractError(`records[${index}].hostname is required.`, 'invalid_supply_chain_source_record', {
      record_index: index,
    });
  }
  if (isIpHostname(hostname)) {
    throw contractError(
      `records[${index}].hostname must be a hostname, not an IP address.`,
      'invalid_supply_chain_source_record',
      { record_index: index },
    );
  }
  if (!HOSTNAME_RE.test(hostname)) {
    throw contractError(`records[${index}].hostname is not a valid hostname.`, 'invalid_supply_chain_source_record', {
      record_index: index,
    });
  }

  const observedAt = requireIsoTimestamp(record.observed_at, `records[${index}].observed_at`);
  const ownerHint = optionalTrimmedString(record.owner_hint);
  const pageType = optionalTrimmedString(record.page_type);

  return {
    hostname,
    observedAt,
    ownerHint,
    pageType,
    claimableProviderSignature: record.claimable_provider_signature === true,
    connectorConfirmation: record.connector_confirmation === true,
    subsidiaryAcquisition: record.subsidiary_acquisition === true,
  };
}

/**
 * Parse a metadata-only dangling CNAME source record into assess-ready fields.
 * No DNS lookups or provider probing.
 */
export function parseDanglingCnameSourceRecord(record, index = 0) {
  const sourceName = 'dangling_cname';
  if (record === null || record === undefined || typeof record !== 'object' || Array.isArray(record)) {
    throw contractError(
      `records[${index}] must be a plain object.`,
      'invalid_supply_chain_source_record',
      { record_index: index },
    );
  }

  const forbidden = collectForbiddenSupplyChainKeys(record);
  if (forbidden.length > 0) {
    throw contractError(
      `Forbidden supply chain source field at records[${index}].${forbidden[0]}`,
      'unsafe_supply_chain_source_record',
      { record_index: index, forbidden_paths: forbidden },
    );
  }

  const shared = parseSharedRecordFields(sourceName, record, index);
  const cnameChainHash = optionalTrimmedString(record.cname_chain_hash);
  const providerErrorSignatureId = optionalTrimmedString(record.provider_error_signature_id);
  const confidence =
    record.confidence === undefined || record.confidence === null
      ? defaultConfidenceForDanglingCname(record)
      : requireConfidence(record.confidence, `records[${index}].confidence`);

  return {
    source: sourceName,
    exposure_type: 'dangling_cname',
    hostname: shared.hostname,
    observed_at: shared.observedAt,
    source_ref: buildSupplyChainSourceRef(sourceName, shared.hostname, shared.observedAt),
    confidence,
    assess_body: {
      hostname: shared.hostname,
      ...(cnameChainHash ? { cname_chain_hash: cnameChainHash } : {}),
      ...(providerErrorSignatureId ? { provider_error_signature_id: providerErrorSignatureId } : {}),
      ...(shared.connectorConfirmation ? { connector_confirmation: true } : {}),
      ...(shared.subsidiaryAcquisition ? { subsidiary_acquisition: true } : {}),
      ...(shared.claimableProviderSignature ? { claimable_provider_signature: true } : {}),
      ...(shared.pageType ? { page_type: shared.pageType } : {}),
      ...(shared.ownerHint ? { owner_hint: shared.ownerHint } : {}),
      confidence,
    },
  };
}

/**
 * Parse a metadata-only vendor dependency source record into assess-ready fields.
 * No page scraping or outbound HTTP.
 */
export function parseVendorDependencySourceRecord(record, index = 0) {
  const sourceName = 'vendor_dependency';
  if (record === null || record === undefined || typeof record !== 'object' || Array.isArray(record)) {
    throw contractError(
      `records[${index}] must be a plain object.`,
      'invalid_supply_chain_source_record',
      { record_index: index },
    );
  }

  const forbidden = collectForbiddenSupplyChainKeys(record);
  if (forbidden.length > 0) {
    throw contractError(
      `Forbidden supply chain source field at records[${index}].${forbidden[0]}`,
      'unsafe_supply_chain_source_record',
      { record_index: index, forbidden_paths: forbidden },
    );
  }

  const shared = parseSharedRecordFields(sourceName, record, index);
  const scriptHost = optionalTrimmedString(record.script_host);
  const dependencyUrlHash = optionalTrimmedString(record.dependency_url_hash);
  const contentType = optionalTrimmedString(record.content_type);
  const statusCode = record.status_code !== undefined ? Number(record.status_code) : null;
  const confidence =
    record.confidence === undefined || record.confidence === null
      ? defaultConfidenceForVendorDependency(record)
      : requireConfidence(record.confidence, `records[${index}].confidence`);

  return {
    source: sourceName,
    exposure_type: 'vendor_dependency_risk',
    hostname: shared.hostname,
    observed_at: shared.observedAt,
    source_ref: buildSupplyChainSourceRef(sourceName, shared.hostname, shared.observedAt),
    confidence,
    assess_body: {
      hostname: shared.hostname,
      ...(scriptHost ? { script_host: scriptHost } : {}),
      ...(dependencyUrlHash ? { dependency_url_hash: dependencyUrlHash } : {}),
      ...(Number.isFinite(statusCode) ? { status_code: statusCode } : {}),
      ...(contentType ? { content_type: contentType } : {}),
      ...(shared.connectorConfirmation ? { connector_confirmation: true } : {}),
      ...(shared.claimableProviderSignature ? { claimable_provider_signature: true } : {}),
      ...(shared.pageType ? { page_type: shared.pageType } : {}),
      ...(shared.ownerHint ? { owner_hint: shared.ownerHint } : {}),
      confidence,
    },
  };
}

export function parseSupplyChainSourceRecord(source, record, index = 0) {
  const sourceName = String(source ?? '').trim();
  if (!SUPPLY_CHAIN_SOURCES.includes(sourceName)) {
    throw contractError(
      `source must be one of: ${SUPPLY_CHAIN_SOURCES.join(', ')}.`,
      'invalid_supply_chain_source',
    );
  }
  if (sourceName === 'dangling_cname') {
    return parseDanglingCnameSourceRecord(record, index);
  }
  return parseVendorDependencySourceRecord(record, index);
}

export function parseSupplyChainSourceRecords(source, records) {
  if (!Array.isArray(records)) {
    throw contractError('records must be an array.', 'invalid_supply_chain_source');
  }
  if (records.length === 0) {
    throw contractError('records must include at least one entry.', 'invalid_supply_chain_source');
  }
  if (records.length > MAX_SUPPLY_CHAIN_INGEST_RECORDS) {
    throw contractError(
      `records exceeds maximum batch size of ${MAX_SUPPLY_CHAIN_INGEST_RECORDS}.`,
      'invalid_supply_chain_source',
    );
  }
  return records.map((record, index) => parseSupplyChainSourceRecord(source, record, index));
}