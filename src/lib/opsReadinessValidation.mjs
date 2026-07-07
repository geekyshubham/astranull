/**
 * Control-plane ops readiness probes — no outbound attack traffic; validates governance artifacts.
 */

import { validateSupportReadinessEvidence } from '../../scripts/support-readiness-evidence.mjs';
import { generateNonce, hashNonce } from './crypto.mjs';
import { newId } from './ids.mjs';
import { enrichProbeMetadataWithWafCatalog } from './wafProductCatalog.mjs';
import { getStore } from '../store.mjs';

export const OPS_READINESS_SCENARIOS = Object.freeze(['runbook_contacts', 'kill_switch_readiness']);

const ACCEPTED_EVIDENCE_STATUSES = new Set(['accepted', 'approved']);
export const SOC_KILL_SWITCH_ACTIONS = new Set([
  'soc.kill_switch.activated',
  'soc.kill_switch.cleared',
]);

export function isOpsReadinessProbeKind(check) {
  return check?.probe_profile?.kind === 'ops_readiness';
}

/**
 * Newest accepted/approved release-evidence record of a kind for a tenant.
 * Works for both the dev in-memory ledger (all tenants) and Postgres
 * tenant-scoped ledgers because it always filters by tenant_id.
 *
 * @param {Array<Record<string, unknown>>} ledger
 * @param {string} kind
 * @param {string} tenantId
 */
export function pickLatestAcceptedEvidence(ledger, kind, tenantId) {
  const matches = (Array.isArray(ledger) ? ledger : []).filter(
    (record) =>
      record
      && record.kind === kind
      && (tenantId == null || record.tenant_id === tenantId)
      && ACCEPTED_EVIDENCE_STATUSES.has(String(record.status ?? 'accepted').toLowerCase()),
  );
  if (matches.length === 0) return null;
  return matches.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
}

export function resolveOpsReadinessScenario(check) {
  const scenario = check?.probe_profile?.scenario;
  if (typeof scenario === 'string' && OPS_READINESS_SCENARIOS.includes(scenario)) {
    return scenario;
  }
  if (check?.check_id?.includes('kill_switch')) return 'kill_switch_readiness';
  return 'runbook_contacts';
}

/**
 * Normalize gathered records into the readiness-data shape consumed by the
 * scenario evaluators. Persistence-agnostic: callers pass whatever they have.
 *
 * @param {{
 *   scenario: string,
 *   tenantId: string,
 *   releaseEvidenceLedger?: Array<Record<string, unknown>>,
 *   killSwitchRecord?: { updated_at?: unknown } | null,
 *   auditEntries?: Array<{ action?: string }>,
 * }} params
 */
export function buildOpsReadinessData({
  scenario,
  tenantId,
  releaseEvidenceLedger = [],
  killSwitchRecord = null,
  auditEntries = [],
}) {
  if (scenario === 'kill_switch_readiness') {
    return {
      hasKillSwitchState: Boolean(killSwitchRecord && killSwitchRecord.updated_at != null),
      auditHit:
        (Array.isArray(auditEntries) ? auditEntries : []).find((entry) =>
          SOC_KILL_SWITCH_ACTIONS.has(entry?.action),
        ) ?? null,
      drillRecord: pickLatestAcceptedEvidence(releaseEvidenceLedger, 'kill_switch_drill', tenantId),
    };
  }
  return {
    evidenceRecord: pickLatestAcceptedEvidence(releaseEvidenceLedger, 'support_readiness', tenantId),
  };
}

function evaluateRunbookContacts({ evidenceRecord } = {}) {
  if (!evidenceRecord?.evidence) {
    return {
      ok: false,
      external_result: 'error',
      detail: 'No accepted support_readiness evidence recorded for tenant.',
      missing_fields: ['support_readiness_evidence'],
    };
  }
  const validation = validateSupportReadinessEvidence(evidenceRecord.evidence);
  return {
    ok: validation.ok,
    external_result: validation.ok ? 'connected' : 'error',
    detail: validation.ok
      ? 'Support runbook and emergency contact evidence validated.'
      : 'Support readiness evidence incomplete or contains forbidden fields.',
    validation,
    evidence_id: evidenceRecord.id,
  };
}

function evaluateKillSwitchReadiness({ hasKillSwitchState, auditHit, drillRecord } = {}) {
  const signals = [];
  if (hasKillSwitchState) signals.push('kill_switch_state');
  if (auditHit) signals.push('kill_switch_audit');
  if (drillRecord) signals.push('kill_switch_drill_evidence');

  const ok = signals.length > 0;
  return {
    ok,
    external_result: ok ? 'connected' : 'error',
    detail: ok
      ? `Kill-switch readiness dry-run passed (${signals.join(', ')}).`
      : 'No kill-switch state, audit trail, or drill evidence recorded for tenant.',
    signals,
    drill_evidence_id: drillRecord?.id ?? null,
    dry_run: true,
    kill_switch_activated: false,
  };
}

/**
 * Developer-validation gathering path: reads the in-memory dev store. The
 * Postgres path passes explicit `readinessData` and never touches getStore().
 */
function gatherOpsReadinessDataFromStore(tenantId, scenario) {
  const store = getStore();
  const releaseEvidenceLedger = store.productionReleaseEvidence ?? [];
  let killSwitchRecord = null;
  let auditEntries = [];
  if (scenario === 'kill_switch_readiness') {
    const ks = store.socKillSwitch ?? {};
    const ksTenant = ks.tenant_id ?? null;
    const tenantScoped =
      ksTenant === tenantId
      || (ks.tenants && typeof ks.tenants === 'object' && ks.tenants[tenantId]);
    killSwitchRecord = tenantScoped ? { updated_at: ks.updated_at ?? null } : null;
    auditEntries = (store.auditLog ?? []).filter((entry) => entry.tenant_id === tenantId);
  }
  return buildOpsReadinessData({
    scenario,
    tenantId,
    releaseEvidenceLedger,
    killSwitchRecord,
    auditEntries,
  });
}

/**
 * @param {{ tenantId: string }} ctx
 * @param {Record<string, unknown>} check
 * @param {Record<string, unknown>} target
 * @param {Record<string, unknown>} [readinessData] Pre-gathered records (Postgres path).
 *   When omitted, the dev in-memory store is read.
 */
export function executeOpsReadinessProbe(ctx, check, target, readinessData) {
  const nonce = generateNonce();
  const nonce_hash = hashNonce(nonce);
  const scenario = resolveOpsReadinessScenario(check);
  const data = readinessData ?? gatherOpsReadinessDataFromStore(ctx.tenantId, scenario);
  const outcome =
    scenario === 'kill_switch_readiness'
      ? evaluateKillSwitchReadiness(data)
      : evaluateRunbookContacts(data);

  return {
    event_id: newId('event'),
    source: 'ops_readiness_probe',
    signal_type: 'probe_result',
    external_result: outcome.external_result,
    nonce,
    nonce_hash,
    target_id: target.id,
    check_id: check.check_id,
    metadata: enrichProbeMetadataWithWafCatalog(
      {
        probe_kind: 'ops_readiness',
        scenario,
        ops_validation_ok: outcome.ok,
        ops_detail: outcome.detail,
        dry_run: scenario === 'kill_switch_readiness',
        target_value: target.value,
        ...(outcome.validation ? { validation_missing_fields: outcome.validation.missing_fields } : {}),
        ...(outcome.signals ? { readiness_signals: outcome.signals } : {}),
        ...(outcome.evidence_id ? { evidence_id: outcome.evidence_id } : {}),
        ...(outcome.drill_evidence_id ? { drill_evidence_id: outcome.drill_evidence_id } : {}),
      },
      check.check_id,
    ),
  };
}
