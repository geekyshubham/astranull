import { createHash } from 'node:crypto';
import { scoreConfidence } from '../contracts/externalDiscovery.mjs';

export const PASSIVE_DISCOVERY_SOURCES = Object.freeze([
  'passive_dns',
  'certificate_transparency',
]);

export const MAX_PASSIVE_INGEST_RECORDS = 500;

const FORBIDDEN_PASSIVE_RECORD_KEYS = new Set([
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
  'raw_page_body',
  'html_content',
  'page_source',
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

function collectForbiddenPassiveKeys(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return [];
  }
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenPassiveKeys(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeFieldKey(key);
    if (FORBIDDEN_PASSIVE_RECORD_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenPassiveKeys(nested, keyPath));
  }
  return findings;
}

export function normalizePassiveHostname(hostname) {
  return String(hostname ?? '').trim().toLowerCase();
}

export function isIpHostname(hostname) {
  const normalized = normalizePassiveHostname(hostname);
  if (!normalized) return false;
  if (IPV4_RE.test(normalized)) return true;
  if (normalized.includes(':')) return true;
  return false;
}

export function mapPassiveSourceToCandidateSourceType(source) {
  const normalized = String(source ?? '').trim();
  if (normalized === 'passive_dns') return 'passive_dns';
  if (normalized === 'certificate_transparency') return 'ct_log';
  throw contractError(
    `source must be one of: ${PASSIVE_DISCOVERY_SOURCES.join(', ')}.`,
    'invalid_discovery_source',
  );
}

export function buildPassiveSourceRef(source, hostname, observedAt) {
  const payload = [source, normalizePassiveHostname(hostname), observedAt].join('|');
  const hash = createHash('sha256').update(payload, 'utf8').digest('hex').slice(0, 32);
  return `redacted:${source}:${hash}`;
}

function requireConfidence(value, fieldName) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0 || n > 1) {
    throw contractError(`${fieldName} must be a number between 0 and 1.`, 'invalid_discovery_source_record');
  }
  return n;
}

function requireIsoTimestamp(value, fieldName) {
  const trimmed = String(value ?? '').trim();
  if (!trimmed) {
    throw contractError(`${fieldName} is required.`, 'invalid_discovery_source_record');
  }
  if (Number.isNaN(Date.parse(trimmed))) {
    throw contractError(`${fieldName} must be a valid ISO timestamp.`, 'invalid_discovery_source_record');
  }
  return trimmed;
}

function defaultConfidenceForSource(source) {
  if (source === 'passive_dns') {
    return scoreConfidence({ passive_dns_only: true });
  }
  if (source === 'certificate_transparency') {
    return scoreConfidence({ cert_cn_san_under_root: true });
  }
  return 0;
}

function buildEvidenceSummary(source, observedAt, confidence) {
  const summary = {
    source_kind: source,
    first_observed_at: observedAt,
    last_observed_at: observedAt,
    confidence_signals:
      source === 'passive_dns' ? ['passive_dns_only'] : ['cert_cn_san_under_root'],
    signal_count: 1,
  };
  if (source === 'certificate_transparency') {
    summary.cert_san_count = 1;
  }
  if (Number.isFinite(confidence)) {
    summary.ownership_hint = confidence >= 0.7 ? 'likely_owned' : 'unknown';
  }
  return summary;
}

/**
 * Parse a metadata-only passive discovery source record into candidate fields.
 * Rejects raw CT logs, IP inventory fields, and hostnames that look like IPs.
 */
export function parsePassiveDiscoveryRecord(source, record, index = 0) {
  const sourceName = String(source ?? '').trim();
  if (!PASSIVE_DISCOVERY_SOURCES.includes(sourceName)) {
    throw contractError(
      `source must be one of: ${PASSIVE_DISCOVERY_SOURCES.join(', ')}.`,
      'invalid_discovery_source',
    );
  }
  if (record === null || record === undefined || typeof record !== 'object' || Array.isArray(record)) {
    throw contractError(
      `records[${index}] must be a plain object.`,
      'invalid_discovery_source_record',
      { record_index: index },
    );
  }

  const forbidden = collectForbiddenPassiveKeys(record);
  if (forbidden.length > 0) {
    throw contractError(
      `Forbidden passive source field at records[${index}].${forbidden[0]}`,
      'unsafe_discovery_source_record',
      { record_index: index, forbidden_paths: forbidden },
    );
  }

  const recordSourceType = String(record.source_type ?? sourceName).trim();
  if (recordSourceType !== sourceName) {
    throw contractError(
      `records[${index}].source_type must match batch source ${sourceName}.`,
      'invalid_discovery_source_record',
      { record_index: index },
    );
  }

  const hostname = normalizePassiveHostname(record.hostname);
  if (!hostname) {
    throw contractError(`records[${index}].hostname is required.`, 'invalid_discovery_source_record', {
      record_index: index,
    });
  }
  if (isIpHostname(hostname)) {
    throw contractError(
      `records[${index}].hostname must be a hostname, not an IP address.`,
      'invalid_discovery_source_record',
      { record_index: index },
    );
  }
  if (!HOSTNAME_RE.test(hostname)) {
    throw contractError(`records[${index}].hostname is not a valid hostname.`, 'invalid_discovery_source_record', {
      record_index: index,
    });
  }

  const observedAt = requireIsoTimestamp(record.observed_at, `records[${index}].observed_at`);
  const confidence =
    record.confidence === undefined || record.confidence === null
      ? defaultConfidenceForSource(sourceName)
      : requireConfidence(record.confidence, `records[${index}].confidence`);

  const candidateSourceType = mapPassiveSourceToCandidateSourceType(sourceName);

  return {
    hostname,
    source_type: candidateSourceType,
    passive_source: sourceName,
    source_ref: buildPassiveSourceRef(sourceName, hostname, observedAt),
    confidence,
    ownership_status: 'unknown',
    approval_status: 'pending',
    first_seen_at: observedAt,
    last_seen_at: observedAt,
    evidence_summary: buildEvidenceSummary(sourceName, observedAt, confidence),
    state: 'candidate',
  };
}

export function parsePassiveDiscoveryRecords(source, records) {
  if (!Array.isArray(records)) {
    throw contractError('records must be an array.', 'invalid_discovery_source');
  }
  if (records.length === 0) {
    throw contractError('records must include at least one entry.', 'invalid_discovery_source');
  }
  if (records.length > MAX_PASSIVE_INGEST_RECORDS) {
    throw contractError(
      `records exceeds maximum batch size of ${MAX_PASSIVE_INGEST_RECORDS}.`,
      'invalid_discovery_source',
    );
  }
  return records.map((record, index) => parsePassiveDiscoveryRecord(source, record, index));
}