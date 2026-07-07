import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { emitNotification } from './notifications.mjs';

export function upsertFindingFromVerdict(ctx, verdict, run, target) {
  const store = getStore();
  const existing = store.findings.find(
    (f) =>
      f.tenant_id === ctx.tenantId &&
      f.target_group_id === run.target_group_id &&
      f.target_id === target.id &&
      f.check_id === run.check_id &&
      f.status === 'open',
  );
  if (existing) {
    existing.last_verdict_id = verdict.id;
    existing.updated_at = new Date().toISOString();
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'finding.updated',
      resource_type: 'finding',
      resource_id: existing.id,
    });
    persistStore();
    return existing;
  }
  const finding = {
    id: newId('finding'),
    tenant_id: ctx.tenantId,
    target_group_id: run.target_group_id,
    target_id: target.id,
    check_id: run.check_id,
    test_run_id: run.id,
    verdict_id: verdict.id,
    title: `Finding: ${verdict.verdict} on ${target.value}`,
    severity: verdict.severity ?? 'medium',
    status: 'open',
    assignee: null,
    notes: verdict.explanation,
    evidence_ids: verdict.evidence_ids,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
  store.findings.push(finding);
  if (['high', 'critical'].includes(finding.severity)) {
    emitNotification(ctx, {
      trigger: 'finding.high_severity',
      subject: finding.title,
      metadata: { finding_id: finding.id, severity: finding.severity },
    });
  }
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'finding.created',
    resource_type: 'finding',
    resource_id: finding.id,
  });
  persistStore();
  return finding;
}

export function listFindings(ctx, options = {}) {
  let rows = getStore().findings.filter((f) => f.tenant_id === ctx.tenantId);
  if (options.target_group_id) {
    rows = rows.filter((f) => f.target_group_id === options.target_group_id);
  }
  if (options.target_id) {
    rows = rows.filter((f) => f.target_id === options.target_id);
  }
  const limit = Number(options.limit);
  if (Number.isFinite(limit) && limit > 0) rows = rows.slice(0, limit);
  return rows;
}

export function listFindingsEnvelope(ctx, options = {}) {
  const items = listFindings(ctx, options);
  return {
    items,
    count: items.length,
    meta: {
      empty_reason: items.length
        ? null
        : options.target_group_id
          ? 'No findings match this target group filter.'
          : options.target_id
            ? 'No findings match this target filter.'
            : 'No findings have been published for this tenant yet.',
    },
  };
}

export function getFinding(ctx, id) {
  return getStore().findings.find((f) => f.id === id && f.tenant_id === ctx.tenantId) ?? null;
}

export function patchFinding(ctx, id, body) {
  const f = getFinding(ctx, id);
  if (!f) return null;
  if (body.status) f.status = body.status;
  if (body.assignee !== undefined) f.assignee = body.assignee;
  if (body.notes !== undefined) f.notes = body.notes;
  f.updated_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'finding.updated',
    resource_type: 'finding',
    resource_id: id,
    metadata: body,
  });
  persistStore();
  return f;
}

/**
 * Evidence bundle hydrator stub (portal revamp §4.2).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} findingId
 */
export function getEvidenceBundle(ctx, findingId) {
  const finding = getFinding(ctx, findingId);
  if (!finding) {
    return {
      finding: null,
      bundle: null,
      artifacts: [],
      custody_chain: [],
      verify_url: '/v1/custody/verify',
      meta: { empty_reason: 'finding_not_found', finding_id: findingId },
    };
  }

  const vault = (getStore().evidenceVault ?? []).filter(
    (row) => row.tenant_id === ctx.tenantId && row.test_run_id === finding.test_run_id,
  );
  const bundles = (getStore().evidenceBundles ?? []).filter(
    (row) => row.tenant_id === ctx.tenantId && (row.finding_id === findingId || row.test_run_id === finding.test_run_id),
  );
  const bundle = bundles[0] ?? null;

  if (!bundle && vault.length === 0) {
    return {
      finding: { id: finding.id, title: finding.title ?? null, run_id: finding.test_run_id ?? null },
      bundle: null,
      artifacts: [],
      custody_chain: [],
      verify_url: '/v1/custody/verify',
      meta: { empty_reason: 'no_evidence_bundle_sealed_for_finding', finding_id: findingId },
    };
  }

  const artifacts = vault.map((row) => ({
    id: row.id,
    kind: row.label ?? row.kind ?? 'metadata_evidence',
    run_id: row.test_run_id ?? finding.test_run_id ?? null,
    sha256: row.sha256 ?? row.content_sha256 ?? row.metadata?.sha256 ?? null,
    sealed_at: row.sealed_at ?? row.created_at ?? null,
    size_bytes: row.size_bytes ?? row.metadata?.size_bytes ?? null,
  }));

  const custody_chain = artifacts
    .filter((art) => art.sha256)
    .map((art, index) => ({
      step: index + 1,
      kind: `${art.kind}_sealed`,
      sha256: art.sha256,
      at: art.sealed_at,
    }));

  const response = {
    finding: { id: finding.id, title: finding.title ?? null, run_id: finding.test_run_id ?? null },
    bundle: bundle
      ? {
          id: bundle.id,
          sha256: bundle.sha256,
          sealed_at: bundle.sealed_at,
          size_bytes: bundle.size_bytes,
          custody_schema_version: bundle.custody_schema_version ?? 'astranull.custody.v1',
        }
      : null,
    artifacts,
    custody_chain,
    verify_url: '/v1/custody/verify',
  };
  if (!bundle && artifacts.length === 0) {
    response.meta = { empty_reason: 'no_evidence_bundle_sealed_for_finding', finding_id: findingId };
  }
  return response;
}