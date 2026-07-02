export const DEFAULT_PRIVACY = {
  store_packet_payloads: false,
  metadata_retention_days: 90,
  redact_headers_by_default: true,
};

export const DEFAULT_EVIDENCE_RETENTION = {
  audit_log_days: 2555,
  high_scale_artifact_days: 2555,
  report_days: 365,
  legal_hold: false,
};

export const METADATA_RETENTION_MIN_DAYS = 1;
export const METADATA_RETENTION_MAX_DAYS = 3650;

export const EVIDENCE_RETENTION_BOUNDS = {
  audit_log_days: { min: 365, max: 3650 },
  high_scale_artifact_days: { min: 365, max: 3650 },
  report_days: { min: 30, max: 3650 },
};

function clampRetentionDays(value, fallback, { min, max }) {
  let days = value;
  if (typeof days !== 'number' || !Number.isFinite(days)) {
    days = fallback;
  } else {
    days = Math.trunc(days);
    if (days < min) days = min;
    if (days > max) days = max;
  }
  return days;
}

export function normalizeEvidenceRetention(input = {}) {
  const source = input && typeof input === 'object' ? input : {};
  return {
    audit_log_days: clampRetentionDays(
      source.audit_log_days,
      DEFAULT_EVIDENCE_RETENTION.audit_log_days,
      EVIDENCE_RETENTION_BOUNDS.audit_log_days,
    ),
    high_scale_artifact_days: clampRetentionDays(
      source.high_scale_artifact_days,
      DEFAULT_EVIDENCE_RETENTION.high_scale_artifact_days,
      EVIDENCE_RETENTION_BOUNDS.high_scale_artifact_days,
    ),
    report_days: clampRetentionDays(
      source.report_days,
      DEFAULT_EVIDENCE_RETENTION.report_days,
      EVIDENCE_RETENTION_BOUNDS.report_days,
    ),
    legal_hold: Boolean(source.legal_hold),
  };
}

export function normalizePrivacySettings(input = {}) {
  const merged = { ...DEFAULT_PRIVACY, ...(input && typeof input === 'object' ? input : {}) };
  let days = merged.metadata_retention_days;
  if (typeof days !== 'number' || !Number.isFinite(days)) {
    days = DEFAULT_PRIVACY.metadata_retention_days;
  } else {
    days = Math.trunc(days);
    if (days < METADATA_RETENTION_MIN_DAYS) days = METADATA_RETENTION_MIN_DAYS;
    if (days > METADATA_RETENTION_MAX_DAYS) days = METADATA_RETENTION_MAX_DAYS;
  }
  merged.metadata_retention_days = days;
  merged.store_packet_payloads = Boolean(merged.store_packet_payloads);
  merged.redact_headers_by_default = merged.redact_headers_by_default !== false;
  merged.evidence_retention = normalizeEvidenceRetention(merged.evidence_retention);
  return merged;
}