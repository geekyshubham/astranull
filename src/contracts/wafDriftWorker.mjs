import { createHash } from 'node:crypto';
import { assertNoRawWafEvidence } from './wafPosture.mjs';

export const DRIFT_CHECK_TYPES = Object.freeze([
  'connector_config_change',
  'mode_downgrade',
  'fingerprint_loss',
  'rule_removal',
  'origin_bypass_new',
  'policy_weakening',
  'certificate_expiry_risk',
]);

export const DRIFT_SCAN_STATES = Object.freeze([
  'idle',
  'scanning',
  'completed',
  'failed',
]);

export const CONNECTOR_DRIFT_SIGNALS = Object.freeze([
  'waf_mode_changed',
  'rule_count_decreased',
  'custom_rule_removed',
  'ip_allowlist_expanded',
  'rate_limit_increased',
  'security_level_lowered',
  'certificate_near_expiry',
]);

const DRIFT_CHECK_TYPE_SET = new Set(DRIFT_CHECK_TYPES);
const DRIFT_SCAN_STATE_SET = new Set(DRIFT_SCAN_STATES);
const CONNECTOR_SIGNAL_SET = new Set(CONNECTOR_DRIFT_SIGNALS);

const SCAN_RESULT_FORBIDDEN_KEYS = new Set([
  'raw_config',
  'config_body',
  'api_response',
  'credentials',
  'tokens',
  'secrets',
  'token',
  'secret',
  'credential',
  'password',
  'api_key',
  'api_token',
]);

const BLOCKING_POLICY_MODES = new Set([
  'blocking',
  'block',
  'prevention',
  'on',
  'enabled',
]);

const MONITOR_POLICY_MODES = new Set([
  'monitor',
  'detect',
  'log',
  'log_only',
  'simulate',
  'count',
]);

const SECURITY_LEVEL_ORDER = new Map([
  ['off', 0],
  ['disabled', 0],
  ['essentially_off', 1],
  ['low', 2],
  ['medium', 3],
  ['high', 4],
  ['under_attack', 5],
]);

const CERTIFICATE_EXPIRY_WARNING_DAYS = 30;

function normalizeKey(key) {
  return String(key)
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function collectForbiddenScanKeys(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return [];
  }
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenScanKeys(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeKey(key);
    if (SCAN_RESULT_FORBIDDEN_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenScanKeys(nested, keyPath));
  }
  return findings;
}

export function hashDriftValue(value) {
  const serialized = value === null || value === undefined
    ? 'null'
    : typeof value === 'object'
      ? JSON.stringify(value)
      : String(value);
  const digest = createHash('sha256').update(serialized, 'utf8').digest('hex');
  return `sha256:${digest}`;
}

function snapshotSummary(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') return {};
  return snapshot.summary_json ?? snapshot.summary ?? {};
}

function normalizePolicyMode(value) {
  return String(value ?? '').trim().toLowerCase();
}

function isModeDowngrade(previousMode, currentMode) {
  const prev = normalizePolicyMode(previousMode);
  const curr = normalizePolicyMode(currentMode);
  if (!prev || !curr || prev === curr) return false;
  if (BLOCKING_POLICY_MODES.has(prev) && MONITOR_POLICY_MODES.has(curr)) return true;
  if (BLOCKING_POLICY_MODES.has(prev) && (curr === 'off' || curr === 'disabled')) return true;
  return false;
}

function securityLevelRank(value) {
  const key = normalizePolicyMode(value);
  if (SECURITY_LEVEL_ORDER.has(key)) return SECURITY_LEVEL_ORDER.get(key);
  if (BLOCKING_POLICY_MODES.has(key)) return 4;
  if (MONITOR_POLICY_MODES.has(key)) return 2;
  return null;
}

function isSecurityLevelLowered(previousLevel, currentLevel) {
  const prevRank = securityLevelRank(previousLevel);
  const currRank = securityLevelRank(currentLevel);
  if (prevRank === null || currRank === null) return false;
  return currRank < prevRank;
}

function isAllowlistExpansion(previousSummary, currentSummary) {
  const prev = String(previousSummary ?? '').toLowerCase();
  const curr = String(currentSummary ?? '').toLowerCase();
  if (!prev || !curr || prev === curr) return false;
  const expansionHints = ['expanded', 'permissive', 'open', 'allowlist_growth', 'relaxed'];
  return expansionHints.some((hint) => curr.includes(hint) && !prev.includes(hint));
}

function parseRateLimitThreshold(summary) {
  const text = String(summary ?? '');
  const match = text.match(/(\d+)/);
  if (!match) return null;
  const n = Number(match[1]);
  return Number.isFinite(n) ? n : null;
}

function isRateLimitIncreased(previousSummary, currentSummary) {
  const prev = parseRateLimitThreshold(previousSummary);
  const curr = parseRateLimitThreshold(currentSummary);
  if (prev !== null && curr !== null) return curr > prev;
  const prevText = String(previousSummary ?? '');
  const currText = String(currentSummary ?? '');
  return Boolean(prevText && currText && prevText !== currText && /increased|raised|relaxed/i.test(currText));
}

function daysUntilCertificateExpiry(summary) {
  const expiresAt = summary.certificate_expires_at
    ?? summary.cert_expires_at
    ?? summary.certificate_expiry_at
    ?? null;
  if (typeof expiresAt !== 'string' || !expiresAt.trim()) {
    const daysRemaining = Number(summary.cert_expiry_days ?? summary.certificate_days_remaining);
    return Number.isFinite(daysRemaining) ? daysRemaining : null;
  }
  const expiryMs = Date.parse(expiresAt);
  if (!Number.isFinite(expiryMs)) return null;
  const diffMs = expiryMs - Date.now();
  return Math.ceil(diffMs / (24 * 60 * 60 * 1000));
}

function pushDrift(drifts, { signal, field, oldValue, newValue }) {
  if (!CONNECTOR_SIGNAL_SET.has(signal)) return;
  drifts.push({
    signal,
    field,
    old_value_hash: hashDriftValue(oldValue),
    new_value_hash: hashDriftValue(newValue),
  });
}

export function detectConnectorConfigDrift(currentSnapshot, previousSnapshot) {
  const current = snapshotSummary(currentSnapshot);
  const previous = snapshotSummary(previousSnapshot);
  const drifts = [];

  const previousMode = previous.policy_mode ?? previous.mode_summary ?? null;
  const currentMode = current.policy_mode ?? current.mode_summary ?? null;
  if (previousMode !== undefined && currentMode !== undefined && previousMode !== currentMode) {
    pushDrift(drifts, {
      signal: 'waf_mode_changed',
      field: 'policy_mode',
      oldValue: previousMode,
      newValue: currentMode,
    });
  }

  const previousRuleCount = previous.rule_count;
  const currentRuleCount = current.rule_count;
  if (
    Number.isFinite(Number(previousRuleCount))
    && Number.isFinite(Number(currentRuleCount))
    && Number(currentRuleCount) < Number(previousRuleCount)
  ) {
    pushDrift(drifts, {
      signal: 'rule_count_decreased',
      field: 'rule_count',
      oldValue: previousRuleCount,
      newValue: currentRuleCount,
    });
  }

  const previousVersions = Array.isArray(previous.managed_rule_versions)
    ? previous.managed_rule_versions.map(String)
    : [];
  const currentVersions = Array.isArray(current.managed_rule_versions)
    ? current.managed_rule_versions.map(String)
    : [];
  if (previousVersions.length > 0) {
    const removed = previousVersions.filter((v) => !currentVersions.includes(v));
    if (removed.length > 0) {
      pushDrift(drifts, {
        signal: 'custom_rule_removed',
        field: 'managed_rule_versions',
        oldValue: previousVersions,
        newValue: currentVersions,
      });
    }
  }

  const previousOrigin = previous.origin_protection_summary ?? null;
  const currentOrigin = current.origin_protection_summary ?? null;
  if (isAllowlistExpansion(previousOrigin, currentOrigin)) {
    pushDrift(drifts, {
      signal: 'ip_allowlist_expanded',
      field: 'origin_protection_summary',
      oldValue: previousOrigin,
      newValue: currentOrigin,
    });
  }

  const previousRateLimit = previous.rate_limit_summary ?? null;
  const currentRateLimit = current.rate_limit_summary ?? null;
  if (isRateLimitIncreased(previousRateLimit, currentRateLimit)) {
    pushDrift(drifts, {
      signal: 'rate_limit_increased',
      field: 'rate_limit_summary',
      oldValue: previousRateLimit,
      newValue: currentRateLimit,
    });
  }

  const previousSecurity = previous.security_level ?? previousMode;
  const currentSecurity = current.security_level ?? currentMode;
  if (isSecurityLevelLowered(previousSecurity, currentSecurity)) {
    pushDrift(drifts, {
      signal: 'security_level_lowered',
      field: 'security_level',
      oldValue: previousSecurity,
      newValue: currentSecurity,
    });
  }

  const previousCertDays = daysUntilCertificateExpiry(previous);
  const currentCertDays = daysUntilCertificateExpiry(current);
  const certDays = currentCertDays ?? previousCertDays;
  if (certDays !== null && certDays <= CERTIFICATE_EXPIRY_WARNING_DAYS) {
    pushDrift(drifts, {
      signal: 'certificate_near_expiry',
      field: 'certificate_expires_at',
      oldValue: previousCertDays ?? previous.certificate_expires_at ?? null,
      newValue: currentCertDays ?? current.certificate_expires_at ?? null,
    });
  }

  const previousConfigHash = previous.config_hash ?? previousSnapshot?.config_hash ?? null;
  const currentConfigHash = current.config_hash ?? currentSnapshot?.config_hash ?? null;
  if (
    previousConfigHash
    && currentConfigHash
    && previousConfigHash !== currentConfigHash
    && drifts.length === 0
  ) {
    pushDrift(drifts, {
      signal: 'waf_mode_changed',
      field: 'config_hash',
      oldValue: previousConfigHash,
      newValue: currentConfigHash,
    });
  }

  return drifts;
}

export function mapConnectorSignalsToCheckTypes(signals) {
  const checkTypes = new Set();
  for (const entry of signals) {
    const signal = typeof entry === 'string' ? entry : entry.signal;
    switch (signal) {
      case 'waf_mode_changed':
        if (
          entry?.old_value_hash
          && entry?.new_value_hash
          && entry.field === 'policy_mode'
        ) {
          /* downgrade evaluated by worker using snapshot summaries */
        }
        checkTypes.add('connector_config_change');
        break;
      case 'rule_count_decreased':
      case 'custom_rule_removed':
        checkTypes.add('rule_removal');
        break;
      case 'ip_allowlist_expanded':
        checkTypes.add('origin_bypass_new');
        checkTypes.add('policy_weakening');
        break;
      case 'rate_limit_increased':
      case 'security_level_lowered':
        checkTypes.add('policy_weakening');
        break;
      case 'certificate_near_expiry':
        checkTypes.add('certificate_expiry_risk');
        break;
      default:
        break;
    }
  }
  return [...checkTypes];
}

export function mapConnectorSignalToDriftType(signal, { modeDowngrade = false } = {}) {
  switch (signal) {
    case 'waf_mode_changed':
      return modeDowngrade ? 'mode_downgrade' : 'connector_config_change';
    case 'rule_count_decreased':
    case 'custom_rule_removed':
      return 'rule_removal';
    case 'ip_allowlist_expanded':
      return 'origin_bypass_new';
    case 'rate_limit_increased':
    case 'security_level_lowered':
      return 'policy_weakening';
    case 'certificate_near_expiry':
      return 'certificate_expiry_risk';
    default:
      return 'connector_config_change';
  }
}

export function computeDriftSeverity(driftSignals) {
  const signals = new Set(
    (driftSignals ?? []).map((entry) => (typeof entry === 'string' ? entry : entry.signal)).filter(Boolean),
  );
  const checkTypes = new Set(
    (driftSignals ?? []).flatMap((entry) => {
      if (typeof entry === 'string') {
        return DRIFT_CHECK_TYPE_SET.has(entry) ? [entry] : mapConnectorSignalsToCheckTypes([entry]);
      }
      if (entry?.check_type && DRIFT_CHECK_TYPE_SET.has(entry.check_type)) {
        return [entry.check_type];
      }
      return mapConnectorSignalsToCheckTypes([entry]);
    }),
  );

  const hasModeDowngrade = checkTypes.has('mode_downgrade')
    || (signals.has('waf_mode_changed') && signals.has('security_level_lowered'));
  const hasRuleRemoval = checkTypes.has('rule_removal')
    || signals.has('rule_count_decreased')
    || signals.has('custom_rule_removed');

  if (hasModeDowngrade && hasRuleRemoval) return 'critical';
  if (checkTypes.has('certificate_expiry_risk') || signals.has('certificate_near_expiry')) return 'high';
  if (checkTypes.has('fingerprint_loss') || checkTypes.has('origin_bypass_new')) return 'critical';
  if (checkTypes.has('mode_downgrade')) return 'critical';

  const policySignals = [
    'ip_allowlist_expanded',
    'rate_limit_increased',
    'security_level_lowered',
  ];
  const activePolicySignals = policySignals.filter((s) => signals.has(s));
  const policyWeakeningCount = activePolicySignals.length > 0
    ? activePolicySignals.length
    : (checkTypes.has('policy_weakening') ? 1 : 0);

  if (policyWeakeningCount === 1) return 'medium';
  if (policyWeakeningCount > 1) return 'high';
  if (checkTypes.has('connector_config_change') && checkTypes.size === 1) return 'medium';
  if (hasRuleRemoval) return 'high';
  return 'medium';
}

export function validateDriftScanResult(result) {
  if (result === null || result === undefined || typeof result !== 'object' || Array.isArray(result)) {
    const err = new Error('Drift scan result must be a plain object.');
    err.code = 'invalid_drift_scan_result';
    throw err;
  }

  const forbidden = collectForbiddenScanKeys(result);
  if (forbidden.length > 0) {
    const err = new Error(`Forbidden drift scan result field: ${forbidden[0]}`);
    err.code = 'unsafe_drift_scan_result';
    err.forbidden_paths = forbidden;
    throw err;
  }
  assertNoRawWafEvidence(result);

  const tenantId = typeof result.tenant_id === 'string' ? result.tenant_id.trim() : '';
  if (!tenantId) {
    const err = new Error('tenant_id is required.');
    err.code = 'invalid_drift_scan_result';
    throw err;
  }

  const scanType = typeof result.scan_type === 'string' ? result.scan_type.trim() : '';
  if (!scanType) {
    const err = new Error('scan_type is required.');
    err.code = 'invalid_drift_scan_result';
    throw err;
  }

  const assetsScanned = Number(result.assets_scanned);
  if (!Number.isInteger(assetsScanned) || assetsScanned < 0) {
    const err = new Error('assets_scanned must be a non-negative integer.');
    err.code = 'invalid_drift_scan_result';
    throw err;
  }

  const driftsDetected = Number(result.drifts_detected);
  if (!Number.isInteger(driftsDetected) || driftsDetected < 0) {
    const err = new Error('drifts_detected must be a non-negative integer.');
    err.code = 'invalid_drift_scan_result';
    throw err;
  }

  const scanDurationMs = Number(result.scan_duration_ms);
  if (!Number.isInteger(scanDurationMs) || scanDurationMs < 0) {
    const err = new Error('scan_duration_ms must be a non-negative integer.');
    err.code = 'invalid_drift_scan_result';
    throw err;
  }

  const completedAt = typeof result.completed_at === 'string' ? result.completed_at.trim() : '';
  if (!completedAt) {
    const err = new Error('completed_at is required.');
    err.code = 'invalid_drift_scan_result';
    throw err;
  }

  if (result.state !== undefined && result.state !== null) {
    const state = String(result.state).trim();
    if (!DRIFT_SCAN_STATE_SET.has(state)) {
      const err = new Error(`state must be one of: ${DRIFT_SCAN_STATES.join(', ')}.`);
      err.code = 'invalid_drift_scan_result';
      throw err;
    }
  }

  return true;
}

export function createDriftScanResult(fields = {}) {
  if (fields === null || fields === undefined || typeof fields !== 'object' || Array.isArray(fields)) {
    const err = new Error('Drift scan result fields must be a plain object.');
    err.code = 'invalid_drift_scan_result';
    throw err;
  }
  const forbiddenInput = collectForbiddenScanKeys(fields);
  if (forbiddenInput.length > 0) {
    const err = new Error(`Forbidden drift scan result field: ${forbiddenInput[0]}`);
    err.code = 'unsafe_drift_scan_result';
    err.forbidden_paths = forbiddenInput;
    throw err;
  }
  assertNoRawWafEvidence(fields);

  const result = {
    tenant_id: typeof fields.tenant_id === 'string' ? fields.tenant_id.trim() : '',
    scan_type: typeof fields.scan_type === 'string' ? fields.scan_type.trim() : 'connector_config_change',
    assets_scanned: Number(fields.assets_scanned ?? 0),
    drifts_detected: Number(fields.drifts_detected ?? 0),
    scan_duration_ms: Number(fields.scan_duration_ms ?? 0),
    completed_at: typeof fields.completed_at === 'string' && fields.completed_at.trim()
      ? fields.completed_at.trim()
      : new Date().toISOString(),
    state: typeof fields.state === 'string' && DRIFT_SCAN_STATE_SET.has(fields.state)
      ? fields.state
      : 'completed',
    ...(Number.isInteger(Number(fields.assets_with_connector_snapshots))
      ? { assets_with_connector_snapshots: Number(fields.assets_with_connector_snapshots) }
      : {}),
    ...(Array.isArray(fields.drift_check_types)
      ? {
          drift_check_types: fields.drift_check_types
            .map((t) => String(t).trim())
            .filter((t) => DRIFT_CHECK_TYPE_SET.has(t)),
        }
      : {}),
  };

  validateDriftScanResult(result);
  return result;
}