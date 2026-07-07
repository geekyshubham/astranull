import type { DataItem } from './types';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

export type HeartbeatTraceSegment = {
  id: string;
  latencyMs: number | null;
  at: string;
  tone: 'ok' | 'slow' | 'miss' | 'now';
  title: string;
};

export function formatRelativeAge(iso: string, nowMs = Date.now()) {
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return '—';
  const deltaMs = Math.max(0, nowMs - ts);
  const seconds = Math.round(deltaMs / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 120) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  return `${days}d ago`;
}

export function buildHeartbeatTraceFromAudit(
  audit: DataItem[],
  agentId: string,
  opts: { limit?: number; cadenceTargetMs?: number; nowMs?: number } = {}
): HeartbeatTraceSegment[] {
  const limit = opts.limit ?? 30;
  const cadenceTargetMs = opts.cadenceTargetMs ?? 5000;
  const nowMs = opts.nowMs ?? Date.now();
  const entries = audit
    .filter((entry) => {
      const action = getString(entry, ['action']);
      const resourceId = getString(entry, ['resource_id']);
      return action === 'agent.heartbeat' && resourceId === agentId;
    })
    .sort((a, b) => Date.parse(String(b.created_at ?? b.timestamp ?? '')) - Date.parse(String(a.created_at ?? a.timestamp ?? '')))
    .slice(0, limit);

  if (entries.length === 0) return [];

  const segments: HeartbeatTraceSegment[] = [];
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const at = getString(entry, ['created_at', 'timestamp']);
    const prev = entries[index + 1];
    let latencyMs: number | null = null;
    if (prev) {
      const gap = Date.parse(at) - Date.parse(getString(prev, ['created_at', 'timestamp']));
      if (Number.isFinite(gap) && gap > 0) latencyMs = gap;
    }
    const slow = latencyMs != null && latencyMs > cadenceTargetMs * 1.2;
    const tone: HeartbeatTraceSegment['tone'] = index === 0 ? 'now' : slow ? 'slow' : 'ok';
    const title = latencyMs != null
      ? `${(latencyMs / 1000).toFixed(1)}s`
      : formatRelativeAge(at, nowMs);
    segments.push({
      id: getString(entry, ['id', 'audit_id'], `${agentId}-${index}`),
      latencyMs,
      at,
      tone,
      title
    });
  }
  return segments;
}

export function computeCadenceP50(segments: HeartbeatTraceSegment[]) {
  const gaps = segments.map((segment) => segment.latencyMs).filter((value): value is number => value != null && value > 0);
  if (!gaps.length) return null;
  const sorted = [...gaps].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const p50 = sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
  const spread = sorted.length > 1 ? Math.abs(sorted[sorted.length - 1] - sorted[0]) / 2 : 0;
  return { p50Ms: p50, spreadMs: spread };
}

export function resolveInstallNonceStatus(agent: DataItem | null | undefined) {
  if (!agent) return { label: '—', provenance: 'No agent record.' };
  const bootstrapId = getString(agent, ['bootstrap_token_id']);
  const validation = getString(agent, ['last_token_validation_status']);
  if (validation === 'valid' && bootstrapId) {
    return {
      label: 'match',
      provenance: `Bootstrap token ${bootstrapId} exchanged; last validation ${getString(agent, ['last_token_validation_at']) || 'recorded'}.`
    };
  }
  if (getString(agent, ['status']) === 'online' && agent.created_at) {
    return {
      label: 'match',
      provenance: `Agent registered ${formatRelativeAge(String(agent.created_at))}; heartbeat credentials active.`
    };
  }
  return { label: 'pending', provenance: 'Awaiting bootstrap exchange and first heartbeat correlation.' };
}