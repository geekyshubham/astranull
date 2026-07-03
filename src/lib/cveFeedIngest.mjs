import { validateCvePipelineItem } from '../contracts/cvePipeline.mjs';

export const CVE_FEED_DEFAULT_TIMEOUT_MS = 10_000;
export const CVE_FEED_MAX_ITEMS = 500;
export const CVE_FEED_MAX_DESCRIPTION_SUMMARY_LENGTH = 2000;
export const CVE_FEED_MAX_BODY_BYTES = 2 * 1024 * 1024;

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/i;
const SEVERITY_LEVELS = new Set(['critical', 'high', 'medium', 'low', 'none', 'unknown']);

const FORBIDDEN_FEED_KEYS = new Set([
  'exploit_code',
  'exploit_payload',
  'poc_code',
  'attack_script',
  'raw_response',
  'credentials',
  'tokens',
  'secrets',
  'payload',
  'shellcode',
  'exploit_url',
]);

function normalizeKey(key) {
  return String(key)
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function collectForbiddenKeys(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return [];
  }
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenKeys(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeKey(key);
    if (FORBIDDEN_FEED_KEYS.has(normalized)) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenKeys(nested, keyPath));
  }
  return findings;
}

function normalizeStringList(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((v) => String(v).trim()).filter(Boolean))];
}

function parseBooleanDefault(value, fallback = false) {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'boolean') return value;
  if (value === '1' || value === 1 || value === 'true') return true;
  if (value === '0' || value === 0 || value === 'false') return false;
  return fallback;
}

function normalizePublishedDate(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const parsed = Date.parse(value.trim());
  if (Number.isNaN(parsed)) return null;
  return new Date(parsed).toISOString();
}

function truncateSummary(value) {
  const text = String(value ?? '').trim();
  if (!text) return '';
  if (text.length <= CVE_FEED_MAX_DESCRIPTION_SUMMARY_LENGTH) return text;
  return `${text.slice(0, CVE_FEED_MAX_DESCRIPTION_SUMMARY_LENGTH - 3)}...`;
}

export function assertSafeCveFeedPayload(value, path = '') {
  const forbidden = collectForbiddenKeys(value, path);
  if (forbidden.length > 0) {
    const err = new Error(`Forbidden CVE feed field: ${forbidden[0]}`);
    err.code = 'unsafe_cve_feed_item';
    err.forbidden_paths = forbidden;
    throw err;
  }
  return true;
}

/**
 * Normalize a metadata-only CVE feed document into an array of feed items.
 * Accepts `[{...}]` or `{ items: [{...}] }`.
 */
export function extractCveFeedItems(document) {
  if (document === null || document === undefined) {
    const err = new Error('CVE feed document is required.');
    err.code = 'invalid_cve_feed_document';
    throw err;
  }
  if (Array.isArray(document)) {
    return document;
  }
  if (typeof document === 'object' && Array.isArray(document.items)) {
    return document.items;
  }
  const err = new Error('CVE feed document must be an array or { items: [...] }.');
  err.code = 'invalid_cve_feed_document';
  throw err;
}

/**
 * Parse one metadata-only CVE feed item into pipeline-ready fields.
 * Required: cve_id. Optional: severity, published_date, description_summary,
 * affected_products, known_exploited, poc_indicator, vendor_advisories.
 */
export function parseCveFeedItem(rawItem) {
  if (rawItem === null || rawItem === undefined || typeof rawItem !== 'object' || Array.isArray(rawItem)) {
    const err = new Error('CVE feed item must be a plain object.');
    err.code = 'invalid_cve_feed_item';
    throw err;
  }

  assertSafeCveFeedPayload(rawItem);

  const cve_id = typeof rawItem.cve_id === 'string' ? rawItem.cve_id.trim().toUpperCase() : '';
  if (!CVE_ID_PATTERN.test(cve_id)) {
    const err = new Error('cve_id must match CVE-YYYY-NNNN format.');
    err.code = 'invalid_cve_feed_item';
    throw err;
  }

  const severityRaw = typeof rawItem.severity === 'string' ? rawItem.severity.trim().toLowerCase() : 'unknown';
  const severity = SEVERITY_LEVELS.has(severityRaw) ? severityRaw : 'unknown';

  const published_at =
    normalizePublishedDate(rawItem.published_date)
    ?? normalizePublishedDate(rawItem.published_at)
    ?? null;

  const description_summary = truncateSummary(rawItem.description_summary ?? rawItem.summary ?? '');

  const affected_products = normalizeStringList(rawItem.affected_products ?? rawItem.products);
  const resolvedProducts = affected_products.length > 0 ? affected_products : ['unspecified'];

  const vendor_advisories = normalizeStringList(rawItem.vendor_advisories);

  const pipelineFields = {
    cve_id,
    severity,
    affected_products: resolvedProducts,
    known_exploited: parseBooleanDefault(rawItem.known_exploited, false),
    poc_indicator: parseBooleanDefault(rawItem.poc_indicator ?? rawItem.public_poc_signal, false),
    vendor_advisories,
    stage: 'ingest',
    created_at: published_at ?? new Date().toISOString(),
    published_at,
    description_summary,
  };

  validateCvePipelineItem(pipelineFields);
  return pipelineFields;
}

/**
 * Parse a CVE feed document into normalized pipeline field objects.
 */
export function parseCveFeedDocument(document) {
  assertSafeCveFeedPayload(document);
  const items = extractCveFeedItems(document);
  if (items.length > CVE_FEED_MAX_ITEMS) {
    const err = new Error(`CVE feed exceeds maximum item count (${CVE_FEED_MAX_ITEMS}).`);
    err.code = 'invalid_cve_feed_document';
    throw err;
  }
  return items.map((item, index) => {
    try {
      return parseCveFeedItem(item);
    } catch (err) {
      if (!err.index) err.index = index;
      throw err;
    }
  });
}

export function assertHttpsFeedUrl(feedUrl) {
  let parsed;
  try {
    parsed = new URL(String(feedUrl ?? '').trim());
  } catch {
    const err = new Error('feed_url must be a valid URL.');
    err.code = 'invalid_cve_feed_url';
    throw err;
  }
  if (parsed.protocol !== 'https:') {
    const err = new Error('feed_url must use HTTPS.');
    err.code = 'invalid_cve_feed_url';
    throw err;
  }
  return parsed.toString();
}

/**
 * Fetch a metadata-only CVE feed over HTTPS with a bounded timeout.
 */
export async function fetchCveFeedDocument(feedUrl, options = {}) {
  const url = assertHttpsFeedUrl(feedUrl);
  const timeoutMs = Number.isFinite(options.timeoutMs) ? options.timeoutMs : CVE_FEED_DEFAULT_TIMEOUT_MS;
  const fetchFn = options.fetchFn ?? fetch;
  const maxBytes = Number.isFinite(options.maxBytes) ? options.maxBytes : CVE_FEED_MAX_BODY_BYTES;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetchFn(url, { signal: controller.signal, redirect: 'manual' });
  } catch (cause) {
    const err = new Error('Failed to fetch CVE feed URL within the bounded timeout.');
    err.code = 'cve_feed_fetch_failed';
    err.cause = cause;
    throw err;
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    const err = new Error(`CVE feed fetch returned HTTP ${response.status}.`);
    err.code = 'cve_feed_fetch_failed';
    throw err;
  }

  const contentType = String(response.headers.get('content-type') ?? '').toLowerCase();
  if (contentType && !contentType.includes('json') && !contentType.includes('text')) {
    const err = new Error('CVE feed response must be JSON.');
    err.code = 'invalid_cve_feed_document';
    throw err;
  }

  const raw = await response.text();
  if (raw.length > maxBytes) {
    const err = new Error('CVE feed response exceeds the maximum allowed size.');
    err.code = 'invalid_cve_feed_document';
    throw err;
  }

  let document;
  try {
    document = JSON.parse(raw);
  } catch {
    const err = new Error('CVE feed response is not valid JSON.');
    err.code = 'invalid_cve_feed_document';
    throw err;
  }

  return document;
}

/**
 * Resolve feed items from inline items or a remote HTTPS feed URL.
 */
export async function resolveCveFeedItems(body = {}, options = {}) {
  assertSafeCveFeedPayload(body);

  const inlineItems = Array.isArray(body.items) ? body.items : null;
  const feedUrl = typeof body.feed_url === 'string' ? body.feed_url.trim() : '';

  if (inlineItems && feedUrl) {
    const err = new Error('Provide either items or feed_url, not both.');
    err.code = 'invalid_cve_feed_request';
    throw err;
  }
  if (!inlineItems && !feedUrl) {
    const err = new Error('CVE feed ingest requires items or feed_url.');
    err.code = 'invalid_cve_feed_request';
    throw err;
  }

  const document = inlineItems ? { items: inlineItems } : await fetchCveFeedDocument(feedUrl, options);
  return parseCveFeedDocument(document);
}