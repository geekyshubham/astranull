import { requestJson } from './api';
import type { DataItem, PortalConfig, Session } from './types';

export type TargetDetailPayload = {
  target: DataItem | null;
  verification: DataItem | null;
  waf_posture: DataItem | null;
  checks_applied: DataItem[];
  runs_recent: DataItem[];
  findings: DataItem[];
  loa: DataItem | null;
  counts: DataItem | null;
  meta?: DataItem | null;
  sectionMeta?: {
    runs: DataItem | null;
    findings: DataItem | null;
    checks: DataItem | null;
    waf: DataItem | null;
  };
  error?: string;
  loading: boolean;
};

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function readSectionEmptyMeta(meta: DataItem | null, key: string): DataItem | null {
  const reason = getString(meta, [key]);
  return reason ? { empty_reason: reason } : null;
}

export async function populateTargetDetail(
  config: PortalConfig,
  session: Session,
  entityId: string
): Promise<TargetDetailPayload> {
  if (!entityId) {
    return {
      target: null,
      verification: null,
      waf_posture: null,
      checks_applied: [],
      runs_recent: [],
      findings: [],
      loa: null,
      counts: null,
      meta: null,
      loading: false
    };
  }

  try {
    const payload = await requestJson(config, session, `/v1/targets/${encodeURIComponent(entityId)}`) as DataItem;
    const target = payload.target && typeof payload.target === 'object' && !Array.isArray(payload.target)
      ? payload.target as DataItem
      : null;
    const verification = payload.verification && typeof payload.verification === 'object' && !Array.isArray(payload.verification)
      ? payload.verification as DataItem
      : null;
    const wafPosture = payload.waf_posture && typeof payload.waf_posture === 'object' && !Array.isArray(payload.waf_posture)
      ? payload.waf_posture as DataItem
      : null;
    const checksApplied = Array.isArray(payload.checks_applied) ? payload.checks_applied as DataItem[] : [];
    const runsRecent = Array.isArray(payload.runs_recent) ? payload.runs_recent as DataItem[] : [];
    const findings = Array.isArray(payload.findings) ? payload.findings as DataItem[] : [];
    const loa = payload.loa && typeof payload.loa === 'object' && !Array.isArray(payload.loa)
      ? payload.loa as DataItem
      : null;
    const counts = payload.counts && typeof payload.counts === 'object' && !Array.isArray(payload.counts)
      ? payload.counts as DataItem
      : null;
    const meta = payload.meta && typeof payload.meta === 'object' && !Array.isArray(payload.meta)
      ? payload.meta as DataItem
      : null;
    const sectionMeta = {
      runs: readSectionEmptyMeta(meta, 'runs_empty_reason'),
      findings: readSectionEmptyMeta(meta, 'findings_empty_reason'),
      checks: readSectionEmptyMeta(meta, 'checks_empty_reason'),
      waf: readSectionEmptyMeta(meta, 'waf_empty_reason'),
    };

    if (!target) {
      return {
        target: null,
        verification,
        waf_posture: wafPosture,
        checks_applied: checksApplied,
        runs_recent: runsRecent,
        findings,
        loa,
        counts,
        meta: meta ?? (payload.error ? { empty_reason: getString(payload, ['error']) } : null),
        sectionMeta,
        loading: false
      };
    }

    return {
      target,
      verification,
      waf_posture: wafPosture,
      checks_applied: checksApplied,
      runs_recent: runsRecent,
      findings,
      loa,
      counts,
      meta,
      sectionMeta,
      loading: false
    };
  } catch (err) {
    const apiErr = err as Error & { payload?: DataItem };
    const payload = apiErr.payload && typeof apiErr.payload === 'object' && !Array.isArray(apiErr.payload)
      ? apiErr.payload as DataItem
      : null;
    const payloadMeta = payload?.meta && typeof payload.meta === 'object' && !Array.isArray(payload.meta)
      ? payload.meta as DataItem
      : null;
    const emptyReason = getString(payloadMeta, ['empty_reason'])
      || getString(payload, ['error'])
      || (err instanceof Error ? err.message : '');
    return {
      target: null,
      verification: null,
      waf_posture: null,
      checks_applied: [],
      runs_recent: [],
      findings: [],
      loa: null,
      counts: null,
      meta: emptyReason ? { empty_reason: emptyReason } : null,
      error: emptyReason,
      loading: false
    };
  }
}