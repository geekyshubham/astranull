import { useMemo, useState, type CSSProperties, type ReactNode } from 'react';
import { Activity } from 'lucide-react';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { VerifyChip } from '../../lib/verify-chip';
import {
  buildHeartbeatTraceFromAudit,
  computeCadenceP50,
  formatRelativeAge,
  resolveInstallNonceStatus,
  type HeartbeatTraceSegment
} from '../../lib/agent-heartbeat';
import { agentHeartbeatFreshness } from '../../lib/agent-helpers';
import type { DataItem } from '../../lib/types';
import { formatDate } from '../../lib/utils';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function nonceValueStyle(label: string): CSSProperties | undefined {
  if (label === 'match') return { color: 'var(--success)' };
  if (label === 'pending') return { color: 'var(--warn)' };
  return undefined;
}

function heartbeatDotClass(tone: HeartbeatTraceSegment['tone']) {
  if (tone === 'slow') return 'hb-dot is-slow';
  if (tone === 'now') return 'hb-dot is-now';
  if (tone === 'ok') return 'hb-dot is-ok';
  return 'hb-dot';
}

function heartbeatDotStyle(tone: HeartbeatTraceSegment['tone']): CSSProperties | undefined {
  if (tone !== 'miss') return undefined;
  return {
    background: 'color-mix(in oklab, var(--danger), transparent 35%)',
    borderColor: 'color-mix(in oklab, var(--danger), transparent 45%)'
  };
}

function HbMetricCell({
  label,
  value,
  note,
  valueTitle,
  valueStyle
}: {
  label: string;
  value: ReactNode;
  note?: string;
  valueTitle?: string;
  valueStyle?: CSSProperties;
}) {
  return (
    <div className="hb-cell">
      <div className="hb-label">{label}</div>
      <div className="hb-value mono" title={valueTitle} style={valueStyle}>
        {value}
      </div>
      {note ? <div className="hb-note muted">{note}</div> : null}
    </div>
  );
}

function HeartbeatTraceDot({ segment }: { segment: HeartbeatTraceSegment }) {
  return (
    <span
      className={heartbeatDotClass(segment.tone)}
      style={heartbeatDotStyle(segment.tone)}
      title={segment.title}
      role="img"
      aria-label={segment.title}
    />
  );
}

export function AgentHeartbeatPanel({
  agent,
  agentId,
  audit,
  onRefresh,
  refreshing
}: {
  agent: DataItem;
  agentId: string;
  audit: DataItem[];
  onRefresh: () => void;
  refreshing?: boolean;
}) {
  const [nowMs, setNowMs] = useState(Date.now());
  const segments = useMemo(
    () => buildHeartbeatTraceFromAudit(audit, agentId, { nowMs }),
    [audit, agentId, nowMs]
  );
  const cadence = computeCadenceP50(segments);
  const nonce = resolveInstallNonceStatus(agent);
  const verified = getString(agent, ['status']) === 'online' && agent.last_heartbeat_at;
  const provenance = verified
    ? `Agent ${agentId} heartbeat at ${formatDate(agent.last_heartbeat_at)}; cadence from audit trail.`
    : 'Awaiting correlated heartbeat from agent API.';

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Heartbeat verification</CardTitle>
          <CardDescription>Outbound-only cadence trace from agent record and audit heartbeats.</CardDescription>
        </div>
        <div className="row-actions">
          <VerifyChip state={verified ? 'agent_verified' : 'awaiting_heartbeat'} provenance={provenance} />
        </div>
      </CardHeader>
      <CardContent className="stack-tight">
        <div className="hb-grid">
          <HbMetricCell
            label="First heartbeat"
            value={formatRelativeAge(getString(agent, ['created_at'], ''), nowMs)}
            note="install completed"
          />
          <HbMetricCell
            label="Last heartbeat"
            value={agentHeartbeatFreshness(agent, nowMs)}
            note={formatDate(agent.last_heartbeat_at)}
          />
          <HbMetricCell
            label="Cadence (p50)"
            value={
              cadence
                ? `${(cadence.p50Ms / 1000).toFixed(1)}s ± ${(cadence.spreadMs / 1000).toFixed(1)}s`
                : '—'
            }
            note={segments.length > 0 ? `from ${segments.length} audit heartbeats` : 'awaiting trace'}
          />
          <HbMetricCell
            label="Install nonce"
            value={nonce.label}
            note="correlated with bootstrap"
            valueTitle={nonce.provenance}
            valueStyle={nonceValueStyle(nonce.label)}
          />
        </div>
        <div className="hb-trace-wrap">
          <div className="hb-trace-head">
            <span className="eyebrow">Last 30 heartbeats</span>
            <span className="muted mono">newest →</span>
          </div>
          {segments.length === 0 ? (
            <p className="muted hb-trace-empty" role="status" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Activity size={16} aria-hidden="true" />
              <span>No heartbeat audit segments yet. Trace fills after agent heartbeats are recorded.</span>
            </p>
          ) : (
            <div className="hb-trace" aria-label="Heartbeat trace, last 30 pings">
              {segments.map((segment) => (
                <HeartbeatTraceDot key={segment.id} segment={segment} />
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}