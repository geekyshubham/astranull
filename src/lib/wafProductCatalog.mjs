import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CVE_SAFE_VALIDATION_CHECK_ID } from '../contracts/cvePipeline.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_CATALOG_REL = path.join('db', 'seeds', 'waf-product-catalog.json');

export const WAF_PRODUCT_CATALOG_MIN_ENTRIES = 50;
export const WAF_FINGERPRINT_PROBE_CHECK_ID = CVE_SAFE_VALIDATION_CHECK_ID;

export const WAF_CATALOG_DEPLOYMENT_TYPES = Object.freeze([
  'cdn',
  'cloud_native',
  'appliance',
  'reverse_proxy',
  'custom',
]);

const DEPLOYMENT_TYPE_SET = new Set(WAF_CATALOG_DEPLOYMENT_TYPES);

const FORBIDDEN_CATALOG_KEYS = new Set([
  'payload',
  'raw_payload',
  'exploit',
  'exploit_code',
  'exploit_payload',
  'attack_script',
  'poc_code',
  'shellcode',
  'credentials',
  'secret',
  'secrets',
  'token',
  'tokens',
  'password',
  'private_key',
]);

const UNSAFE_PATTERN_TERMS = [
  /union\s+select/i,
  /<script/i,
  /\.\.\//,
  /eval\s*\(/i,
  /cmd\.exe/i,
  /\/etc\/passwd/i,
  /drop\s+table/i,
];

const REQUIRED_ENTRY_FIELDS = [
  'vendor',
  'product',
  'deployment_type',
  'header_name_patterns',
  'cookie_name_patterns',
  'dns_patterns',
  'block_page_signature_ids',
  'connector_provider_ids',
  'fingerprint_version',
  'enabled',
];

let cachedDocument = null;
let cachedCatalogPath = null;

/**
 * @returns {string}
 */
export function resolveWafProductCatalogPath(customPath) {
  if (customPath && String(customPath).trim()) {
    const trimmed = String(customPath).trim();
    return path.isAbsolute(trimmed) ? trimmed : path.join(process.cwd(), trimmed);
  }
  return path.join(process.cwd(), DEFAULT_CATALOG_REL);
}

/**
 * @param {string} [sourcePath]
 */
export function loadWafProductCatalogDocument(sourcePath) {
  const resolved = resolveWafProductCatalogPath(sourcePath);
  if (cachedDocument && cachedCatalogPath === resolved) {
    return cachedDocument;
  }
  const raw = readFileSync(resolved, 'utf8');
  const document = JSON.parse(raw);
  cachedDocument = document;
  cachedCatalogPath = resolved;
  return document;
}

function resetWafProductCatalogCacheForTests() {
  cachedDocument = null;
  cachedCatalogPath = null;
}

function normalizeStringList(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((item) => String(item).trim()).filter(Boolean))];
}

function collectForbiddenKeys(value, keyPath = '') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return [];
  }
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenKeys(entry, `${keyPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const nextPath = keyPath ? `${keyPath}.${key}` : key;
    if (FORBIDDEN_CATALOG_KEYS.has(key.toLowerCase())) {
      findings.push(nextPath);
    }
    findings.push(...collectForbiddenKeys(nested, nextPath));
  }
  return findings;
}

function assertSafeRegexPattern(pattern, fieldPath) {
  const text = String(pattern ?? '').trim();
  if (!text) {
    const err = new Error(`${fieldPath} must be a non-empty regex pattern.`);
    err.code = 'invalid_catalog_pattern';
    throw err;
  }
  for (const unsafe of UNSAFE_PATTERN_TERMS) {
    if (unsafe.test(text)) {
      const err = new Error(`${fieldPath} contains unsafe exploit-like content.`);
      err.code = 'unsafe_catalog_pattern';
      throw err;
    }
  }
  try {
    // eslint-disable-next-line no-new
    new RegExp(text);
  } catch (cause) {
    const err = new Error(`${fieldPath} is not a valid regex: ${cause instanceof Error ? cause.message : String(cause)}`);
    err.code = 'invalid_catalog_pattern';
    throw err;
  }
}

function assertSafeDnsPattern(pattern, fieldPath) {
  const text = String(pattern ?? '').trim();
  if (!text) {
    const err = new Error(`${fieldPath} must be a non-empty DNS suffix pattern.`);
    err.code = 'invalid_catalog_dns_pattern';
    throw err;
  }
  if (/^https?:\/\//i.test(text) || text.includes(' ')) {
    const err = new Error(`${fieldPath} must be a DNS suffix, not a URL.`);
    err.code = 'invalid_catalog_dns_pattern';
    throw err;
  }
  for (const unsafe of UNSAFE_PATTERN_TERMS) {
    if (unsafe.test(text)) {
      const err = new Error(`${fieldPath} contains unsafe exploit-like content.`);
      err.code = 'unsafe_catalog_dns_pattern';
      throw err;
    }
  }
}

/**
 * @param {Record<string, unknown>} entry
 * @param {number} index
 * @param {{ fingerprint_version?: string }} [defaults]
 */
export function validateWafProductCatalogEntry(entry, index, defaults = {}) {
  const errors = [];
  const prefix = `entries[${index}]`;

  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return [`${prefix} must be an object.`];
  }

  for (const field of REQUIRED_ENTRY_FIELDS) {
    if (entry[field] === undefined || entry[field] === null) {
      errors.push(`${prefix}.${field} is required.`);
    }
  }

  const forbidden = collectForbiddenKeys(entry, prefix);
  if (forbidden.length > 0) {
    errors.push(`${prefix} contains forbidden key: ${forbidden[0]}.`);
  }

  const vendor = String(entry.vendor ?? '').trim();
  if (!vendor || !/^[a-z][a-z0-9_]*$/.test(vendor)) {
    errors.push(`${prefix}.vendor must be a normalized lowercase id.`);
  }

  const product = String(entry.product ?? '').trim();
  if (!product) {
    errors.push(`${prefix}.product is required.`);
  }

  const deploymentType = String(entry.deployment_type ?? '').trim();
  if (!DEPLOYMENT_TYPE_SET.has(deploymentType)) {
    errors.push(`${prefix}.deployment_type must be one of: ${WAF_CATALOG_DEPLOYMENT_TYPES.join(', ')}.`);
  }

  if (typeof entry.enabled !== 'boolean') {
    errors.push(`${prefix}.enabled must be a boolean.`);
  }

  const fingerprintVersion = String(entry.fingerprint_version ?? defaults.fingerprint_version ?? '').trim();
  if (!fingerprintVersion) {
    errors.push(`${prefix}.fingerprint_version is required.`);
  }

  const headerPatterns = normalizeStringList(entry.header_name_patterns);
  const cookiePatterns = normalizeStringList(entry.cookie_name_patterns);
  const dnsPatterns = normalizeStringList(entry.dns_patterns);
  const blockPageIds = normalizeStringList(entry.block_page_signature_ids);
  const connectorIds = normalizeStringList(entry.connector_provider_ids);

  if (!Array.isArray(entry.header_name_patterns)) {
    errors.push(`${prefix}.header_name_patterns must be an array.`);
  }
  if (!Array.isArray(entry.cookie_name_patterns)) {
    errors.push(`${prefix}.cookie_name_patterns must be an array.`);
  }
  if (!Array.isArray(entry.dns_patterns)) {
    errors.push(`${prefix}.dns_patterns must be an array.`);
  }
  if (!Array.isArray(entry.block_page_signature_ids)) {
    errors.push(`${prefix}.block_page_signature_ids must be an array.`);
  }
  if (!Array.isArray(entry.connector_provider_ids)) {
    errors.push(`${prefix}.connector_provider_ids must be an array.`);
  }

  if (errors.length === 0) {
    for (const pattern of headerPatterns) {
      try {
        assertSafeRegexPattern(pattern, `${prefix}.header_name_patterns`);
      } catch (err) {
        errors.push(err.message);
      }
    }
    for (const pattern of cookiePatterns) {
      try {
        assertSafeRegexPattern(pattern, `${prefix}.cookie_name_patterns`);
      } catch (err) {
        errors.push(err.message);
      }
    }
    for (const pattern of dnsPatterns) {
      try {
        assertSafeDnsPattern(pattern, `${prefix}.dns_patterns`);
      } catch (err) {
        errors.push(err.message);
      }
    }
    for (const signatureId of blockPageIds) {
      if (!/^block_sig_[a-z0-9_]+_v\d+$/i.test(signatureId)) {
        errors.push(`${prefix}.block_page_signature_ids contains invalid id: ${signatureId}.`);
      }
    }
    for (const providerId of connectorIds) {
      if (!/^[a-z][a-z0-9_]*$/.test(providerId)) {
        errors.push(`${prefix}.connector_provider_ids contains invalid id: ${providerId}.`);
      }
    }
  }

  return errors;
}

/**
 * @param {unknown} document
 */
export function validateWafProductCatalogDocument(document) {
  const errors = [];

  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    return { ok: false, errors: ['Catalog document must be a JSON object.'] };
  }

  const root = /** @type {Record<string, unknown>} */ (document);
  const manifest = root.manifest;
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    errors.push('manifest is required.');
  } else {
    const manifestObj = /** @type {Record<string, unknown>} */ (manifest);
    if (!String(manifestObj.catalog_version ?? '').trim()) {
      errors.push('manifest.catalog_version is required.');
    }
    if (!String(manifestObj.fingerprint_version ?? '').trim()) {
      errors.push('manifest.fingerprint_version is required.');
    }
  }

  const entries = root.entries;
  if (!Array.isArray(entries)) {
    errors.push('entries must be an array.');
    return { ok: false, errors };
  }

  if (entries.length < WAF_PRODUCT_CATALOG_MIN_ENTRIES) {
    errors.push(`entries must contain at least ${WAF_PRODUCT_CATALOG_MIN_ENTRIES} rows (got ${entries.length}).`);
  }

  const manifestDefaults = manifest && typeof manifest === 'object' && !Array.isArray(manifest)
    ? { fingerprint_version: String(/** @type {Record<string, unknown>} */ (manifest).fingerprint_version ?? '') }
    : {};

  const seenIds = new Set();
  entries.forEach((entry, index) => {
    const entryErrors = validateWafProductCatalogEntry(entry, index, manifestDefaults);
    errors.push(...entryErrors);
    if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
      const id = String(/** @type {Record<string, unknown>} */ (entry).id ?? '').trim();
      if (!id) {
        errors.push(`entries[${index}].id is required.`);
      } else if (seenIds.has(id)) {
        errors.push(`entries[${index}].id duplicates earlier id: ${id}.`);
      } else {
        seenIds.add(id);
      }
    }
  });

  if (manifest && typeof manifest === 'object' && !Array.isArray(manifest) && errors.length === 0) {
    const manifestObj = /** @type {Record<string, unknown>} */ (manifest);
    const expectedCount = Number(manifestObj.entry_count);
    if (Number.isInteger(expectedCount) && expectedCount !== entries.length) {
      errors.push(`manifest.entry_count (${expectedCount}) does not match entries length (${entries.length}).`);
    }
    const checksum = String(manifestObj.checksum_sha256 ?? '').trim();
    if (checksum) {
      const actual = createHash('sha256').update(JSON.stringify(entries)).digest('hex');
      if (checksum !== actual) {
        errors.push('manifest.checksum_sha256 does not match entries payload.');
      }
    }
  }

  return { ok: errors.length === 0, errors };
}

/**
 * @param {Record<string, unknown>} entry
 * @param {{ fingerprint_version?: string }} [defaults]
 */
export function mapCatalogEntryToWafProduct(entry, defaults = {}) {
  const id = String(entry.id ?? '').trim();
  const fingerprintVersion = String(entry.fingerprint_version ?? defaults.fingerprint_version ?? '1').trim();
  return {
    id,
    vendor: String(entry.vendor ?? '').trim(),
    product: String(entry.product ?? '').trim(),
    deployment_type: String(entry.deployment_type ?? 'unknown').trim(),
    fingerprint_version: fingerprintVersion,
    confidence_rules_json: {
      header_name_patterns: normalizeStringList(entry.header_name_patterns),
      cookie_name_patterns: normalizeStringList(entry.cookie_name_patterns),
      dns_patterns: normalizeStringList(entry.dns_patterns),
      block_page_signature_ids: normalizeStringList(entry.block_page_signature_ids),
      connector_provider_ids: normalizeStringList(entry.connector_provider_ids),
    },
    enabled: entry.enabled !== false,
  };
}

/**
 * @param {string} [sourcePath]
 */
export function getWafProductCatalogManifest(sourcePath) {
  const document = loadWafProductCatalogDocument(sourcePath);
  const manifest = document.manifest ?? {};
  const entries = Array.isArray(document.entries) ? document.entries : [];
  return {
    catalog_version: String(manifest.catalog_version ?? manifest.fingerprint_version ?? '1').trim(),
    fingerprint_version: String(manifest.fingerprint_version ?? '1').trim(),
    entry_count: entries.length,
    checksum_sha256: String(manifest.checksum_sha256 ?? '').trim() || null,
  };
}

/**
 * @param {string} [sourcePath]
 */
export function getWafProductCatalogEntries(sourcePath) {
  const document = loadWafProductCatalogDocument(sourcePath);
  const manifest = document.manifest ?? {};
  const defaults = { fingerprint_version: String(manifest.fingerprint_version ?? '1') };
  const entries = Array.isArray(document.entries) ? document.entries : [];
  return entries.map((entry) => mapCatalogEntryToWafProduct(entry, defaults));
}

/**
 * Runtime catalog rows for API reads when DB seed has not run yet.
 */
export function listWafProductCatalogEntries(sourcePath) {
  return getWafProductCatalogEntries(sourcePath).filter((entry) => entry.enabled !== false);
}

/**
 * Rows ready for `waf_products` seeding from the bundled catalog artifact.
 */
export function buildWafProductCatalogSeedRows(sourcePath) {
  return getWafProductCatalogEntries(sourcePath).sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * @param {ReturnType<typeof mapCatalogEntryToWafProduct>[]} products
 */
export function summarizeWafProductCatalog(products = []) {
  const items = Array.isArray(products) ? products : [];
  const manifest = getWafProductCatalogManifest();
  const deploymentTypeCounts = {};
  const vendorCounts = {};
  const vendorSet = new Set();
  for (const product of items) {
    const deploymentType = String(product.deployment_type ?? 'unknown');
    deploymentTypeCounts[deploymentType] = (deploymentTypeCounts[deploymentType] ?? 0) + 1;
    const vendor = String(product.vendor ?? 'unknown');
    vendorCounts[vendor] = (vendorCounts[vendor] ?? 0) + 1;
    vendorSet.add(vendor);
  }
  return {
    catalog_version: manifest.catalog_version,
    fingerprint_version: manifest.fingerprint_version,
    checksum_sha256: manifest.checksum_sha256,
    entry_count: items.length,
    total_products: items.length,
    enabled_entry_count: items.filter((product) => product.enabled !== false).length,
    min_entries_met: items.length >= WAF_PRODUCT_CATALOG_MIN_ENTRIES,
    breadth_target_met: items.length >= WAF_PRODUCT_CATALOG_MIN_ENTRIES,
    unique_vendors: vendorSet.size,
    deployment_type_counts: deploymentTypeCounts,
    vendor_counts: vendorCounts,
  };
}

/**
 * Seed dev-json `wafProducts` from the bundled catalog when the store is empty.
 * @param {{ wafProducts?: object[] }} store
 * @returns {boolean} whether the store was modified
 */
export function seedWafProductsIfEmpty(store) {
  if (!store || typeof store !== 'object') return false;
  if (!Array.isArray(store.wafProducts)) {
    store.wafProducts = [];
  }
  if (store.wafProducts.length > 0) return false;

  store.wafProducts = buildWafProductCatalogSeedRows();
  return store.wafProducts.length > 0;
}

function nameMatchesPatterns(name, patterns) {
  const normalized = String(name ?? '').trim();
  if (!normalized) return 0;
  let hits = 0;
  for (const pattern of patterns) {
    try {
      if (new RegExp(pattern, 'i').test(normalized)) {
        hits += 1;
      }
    } catch {
      /* ignore invalid runtime regex */
    }
  }
  return hits;
}

function dnsMatchesPatterns(chain, patterns) {
  const normalized = String(chain ?? '').trim().toLowerCase();
  if (!normalized) return 0;
  let hits = 0;
  for (const suffix of patterns) {
    const needle = String(suffix).trim().toLowerCase();
    if (needle && normalized.includes(needle.replace(/^\./, ''))) {
      hits += 1;
    }
  }
  return hits;
}

/**
 * Metadata-only classifier for regression tests and probe hint reconciliation.
 *
 * @param {{
 *   header_names?: string[],
 *   cookie_names?: string[],
 *   dns_chain?: string,
 *   block_page_signature_id?: string,
 *   connector_provider_id?: string,
 *   customer_vendor_hint?: string,
 *   cdn_detected?: boolean,
 *   waf_validated?: boolean,
 * }} signals
 * @param {{ entries?: ReturnType<typeof getWafProductCatalogEntries>, catalogPath?: string }} [options]
 */
export function classifyWafProductFromSignals(signals = {}, options = {}) {
  const entries = options.entries ?? getWafProductCatalogEntries(options.catalogPath);
  const enabledEntries = entries.filter((entry) => entry.enabled);

  const headerNames = normalizeStringList(signals.header_names);
  const cookieNames = normalizeStringList(signals.cookie_names);
  const dnsChain = String(signals.dns_chain ?? '');
  const blockPageId = String(signals.block_page_signature_id ?? '').trim();
  const connectorProvider = String(signals.connector_provider_id ?? '').trim();
  const customerHint = String(signals.customer_vendor_hint ?? '').trim().toLowerCase();

  const candidates = enabledEntries.map((entry) => {
    const rules = entry.confidence_rules_json ?? {};
    let score = 0;
    const matched_signals = [];

    const headerHits = headerNames.reduce(
      (sum, name) => sum + nameMatchesPatterns(name, rules.header_name_patterns ?? []),
      0,
    );
    if (headerHits > 0) {
      score += Math.min(0.2, headerHits * 0.07);
      matched_signals.push('header_names');
    }

    const cookieHits = cookieNames.reduce(
      (sum, name) => sum + nameMatchesPatterns(name, rules.cookie_name_patterns ?? []),
      0,
    );
    if (cookieHits > 0) {
      score += Math.min(0.2, cookieHits * 0.07);
      matched_signals.push('cookie_names');
    }

    if (headerHits + cookieHits >= 2) {
      score += 0.05;
      matched_signals.push('multiple_http_signals');
    }

    if (dnsMatchesPatterns(dnsChain, rules.dns_patterns ?? []) > 0) {
      score += 0.25;
      matched_signals.push('dns_chain');
    }

    if (blockPageId && (rules.block_page_signature_ids ?? []).includes(blockPageId)) {
      score += 0.25;
      matched_signals.push('block_page_signature_id');
    }

    if (connectorProvider && (rules.connector_provider_ids ?? []).includes(connectorProvider)) {
      score += 0.35;
      matched_signals.push('connector_provider_id');
    }

    if (customerHint && entry.vendor === customerHint) {
      score += 0.1;
      matched_signals.push('customer_vendor_hint');
    }

    return {
      id: entry.id,
      vendor: entry.vendor,
      product: entry.product,
      deployment_type: entry.deployment_type,
      confidence: Math.min(1, Number(score.toFixed(3))),
      matched_signals,
    };
  }).filter((candidate) => candidate.confidence > 0)
    .sort((a, b) => b.confidence - a.confidence);

  let best = candidates[0] ?? null;
  let conflicting_vendor_signals = false;
  if (candidates.length >= 2 && best) {
    const rival = candidates.find((candidate) => candidate.vendor !== best.vendor);
    if (rival && best.confidence - rival.confidence <= 0.2) {
      conflicting_vendor_signals = true;
      best = {
        ...best,
        confidence: Math.max(0, Number((best.confidence - 0.2).toFixed(3))),
      };
    }
  }

  const cdnDetected = signals.cdn_detected === true
    || candidates.some((candidate) => candidate.deployment_type === 'cdn' && candidate.confidence >= 0.25);
  const wafValidated = signals.waf_validated === true;
  const wafPresent = Boolean(best) || signals.waf_present === true;

  return {
    candidates,
    best,
    waf_present: wafPresent,
    cdn_detected: cdnDetected,
    waf_validated: wafValidated,
    conflicting_vendor_signals,
    unknown_vendor_confidence_cap: best ? null : 0.45,
  };
}

/**
 * @param {string | null | undefined} checkId
 */
export function wafFingerprintProbeEvidenceFields(checkId) {
  if (checkId !== WAF_FINGERPRINT_PROBE_CHECK_ID) {
    return {};
  }
  const manifest = getWafProductCatalogManifest();
  return {
    waf_fingerprint_catalog_version: manifest.catalog_version,
    waf_fingerprint_catalog_entry_count: manifest.entry_count,
  };
}

/**
 * @param {Record<string, unknown>} metadata
 * @param {string | null | undefined} checkId
 */
export function enrichProbeMetadataWithWafCatalog(metadata, checkId) {
  const fields = wafFingerprintProbeEvidenceFields(checkId);
  if (!Object.keys(fields).length) {
    return metadata;
  }
  return { ...metadata, ...fields };
}

export const WAF_CATALOG_REGRESSION_FIXTURES = Object.freeze({
  metadata_only_signals: Object.freeze({
    header_names: ['cf-ray', 'cf-cache-status'],
    cookie_names: ['__cf_bm'],
    dns_chain: 'edge.example.cloudflare.net',
    block_page_signature_id: 'block_sig_cloudflare_generic_v1',
  }),
  conflicting_vendor_signals: Object.freeze({
    header_names: ['cf-ray', 'x-akamai-request-id'],
    cookie_names: ['__cf_bm', 'ak_bmsc'],
    dns_chain: 'dual-vendor.edge.example.net',
  }),
  cdn_without_waf: Object.freeze({
    header_names: ['x-cdn-edge'],
    dns_chain: 'static.cdn.example.net',
    cdn_detected: true,
    waf_validated: false,
  }),
});

export const __testOnly = {
  resetWafProductCatalogCacheForTests,
};