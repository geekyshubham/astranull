import { audit } from '../audit.mjs';
import { normalizePrivacySettings } from '../lib/privacySettings.mjs';
import { getStore, persistStore } from '../store.mjs';

export const PROTECTED_GOVERNANCE_COLLECTIONS = [
  'auditLog',
  'highScaleRequests',
  'highScaleAuthorizationArtifacts',
  'socNotes',
  'socReports',
  'findings',
  'testRuns',
];

export function getEffectiveReportRetentionDays(privacy) {
  return Math.max(privacy.metadata_retention_days, privacy.evidence_retention.report_days);
}

export function buildMetadataRetentionCutoffs(privacy, now = new Date()) {
  const nowMs = now instanceof Date ? now.getTime() : new Date(now).getTime();
  const reportRetentionDays = getEffectiveReportRetentionDays(privacy);
  return {
    metadataCutoffMs: nowMs - privacy.metadata_retention_days * 24 * 60 * 60 * 1000,
    reportRetentionDays,
    reportCutoffMs: nowMs - reportRetentionDays * 24 * 60 * 60 * 1000,
  };
}

function parseValidTimestamp(value) {
  if (value == null || value === '') return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed;
}

function purgeTenantMetadataByField(items, tenantId, field, cutoffMs) {
  let removed = 0;
  const kept = [];
  for (const item of items) {
    if (item.tenant_id !== tenantId) {
      kept.push(item);
      continue;
    }
    const ts = parseValidTimestamp(item[field]);
    if (!ts) {
      kept.push(item);
      continue;
    }
    if (ts.getTime() < cutoffMs) {
      removed += 1;
      continue;
    }
    kept.push(item);
  }
  return { kept, removed };
}

function countWouldDelete(store, tenantId, privacy) {
  const { metadataCutoffMs, reportCutoffMs } = buildMetadataRetentionCutoffs(privacy);

  return {
    events: purgeTenantMetadataByField(store.events, tenantId, 'timestamp', metadataCutoffMs).removed,
    evidenceVault: purgeTenantMetadataByField(store.evidenceVault, tenantId, 'created_at', metadataCutoffMs)
      .removed,
    reports: purgeTenantMetadataByField(store.reports, tenantId, 'created_at', reportCutoffMs).removed,
    notificationEvents: purgeTenantMetadataByField(
      store.notificationEvents,
      tenantId,
      'created_at',
      metadataCutoffMs,
    ).removed,
  };
}

/**
 * Redacted, auditable retention policy manifest for a tenant (no document bodies or secrets).
 */
export function buildRetentionPolicySnapshot(tenant) {
  const privacy = normalizePrivacySettings(tenant.privacy_settings ?? {});
  const reportRetentionDays = getEffectiveReportRetentionDays(privacy);
  return {
    tenant_id: tenant.id,
    metadata_retention_days: privacy.metadata_retention_days,
    evidence_retention: { ...privacy.evidence_retention },
    protected_collections: [...PROTECTED_GOVERNANCE_COLLECTIONS],
    deletion_collections: [
      { collection: 'events', effective_retention_days: privacy.metadata_retention_days },
      { collection: 'evidenceVault', effective_retention_days: privacy.metadata_retention_days },
      { collection: 'reports', effective_retention_days: reportRetentionDays },
      { collection: 'notificationEvents', effective_retention_days: privacy.metadata_retention_days },
    ],
  };
}

function emptyDeletedCounts() {
  return { events: 0, evidenceVault: 0, reports: 0, notificationEvents: 0 };
}

/**
 * Purges tenant-owned metadata older than metadata_retention_days (reports use the larger of
 * metadata and evidence_retention.report_days). Honors legal hold on deletable metadata collections.
 * Does not touch audit logs, findings, test runs, or other identity/governance records.
 */
export function enforceMetadataRetentionForTenant(tenantId, auditContext = {}) {
  const store = getStore();
  const tenant = store.tenants.find((t) => t.id === tenantId);
  if (!tenant) return null;

  const privacyBefore = JSON.stringify(tenant.privacy_settings);
  const privacy = normalizePrivacySettings(tenant.privacy_settings);
  tenant.privacy_settings = privacy;
  const privacyNormalized = privacyBefore !== JSON.stringify(privacy);
  const policySnapshot = buildRetentionPolicySnapshot(tenant);

  const { metadataCutoffMs, reportCutoffMs } = buildMetadataRetentionCutoffs(privacy);

  if (privacy.evidence_retention.legal_hold) {
    const blocked = countWouldDelete(store, tenantId, privacy);
    const blockedTotal =
      blocked.events + blocked.evidenceVault + blocked.reports + blocked.notificationEvents;
    const deleted = emptyDeletedCounts();

    if (blockedTotal > 0) {
      audit({
        tenant_id: tenantId,
        actor_user_id: auditContext.userId ?? null,
        actor_role: auditContext.role ?? 'system',
        action: 'privacy.retention_legal_hold',
        resource_type: 'tenant',
        resource_id: tenantId,
        metadata: {
          deleted,
          blocked_deletions: blocked,
          policy_snapshot: policySnapshot,
        },
      });
    } else if (privacyNormalized) {
      persistStore();
    }

    return {
      tenant_id: tenantId,
      deleted,
      metadata_retention_days: privacy.metadata_retention_days,
      evidence_retention: privacy.evidence_retention,
      policy_snapshot: policySnapshot,
      legal_hold: true,
    };
  }

  const eventsResult = purgeTenantMetadataByField(store.events, tenantId, 'timestamp', metadataCutoffMs);
  const evidenceResult = purgeTenantMetadataByField(store.evidenceVault, tenantId, 'created_at', metadataCutoffMs);
  const reportsResult = purgeTenantMetadataByField(store.reports, tenantId, 'created_at', reportCutoffMs);
  const notificationsResult = purgeTenantMetadataByField(
    store.notificationEvents,
    tenantId,
    'created_at',
    metadataCutoffMs,
  );

  const deleted = {
    events: eventsResult.removed,
    evidenceVault: evidenceResult.removed,
    reports: reportsResult.removed,
    notificationEvents: notificationsResult.removed,
  };
  const totalRemoved = deleted.events + deleted.evidenceVault + deleted.reports + deleted.notificationEvents;

  if (totalRemoved > 0) {
    store.events = eventsResult.kept;
    store.evidenceVault = evidenceResult.kept;
    store.reports = reportsResult.kept;
    store.notificationEvents = notificationsResult.kept;

    audit({
      tenant_id: tenantId,
      actor_user_id: auditContext.userId ?? null,
      actor_role: auditContext.role ?? 'system',
      action: 'privacy.retention_purged',
      resource_type: 'tenant',
      resource_id: tenantId,
      metadata: {
        deleted,
        metadata_retention_days: privacy.metadata_retention_days,
        policy_snapshot: policySnapshot,
      },
    });
    persistStore();
  } else if (privacyNormalized) {
    persistStore();
  }

  return {
    tenant_id: tenantId,
    deleted,
    metadata_retention_days: privacy.metadata_retention_days,
    evidence_retention: privacy.evidence_retention,
    policy_snapshot: policySnapshot,
    legal_hold: false,
  };
}
