import { useMemo, useState } from 'react';
import { Activity } from 'lucide-react';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { VerifyChip } from '../../lib/verify-chip';
import {
  buildHeartbeatTraceFromAudit,
  computeCadenceP50,
  formatRelativeAge,
  resolveInstallNonceStatus
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
          <Button size="sm" variant="ghost" loading={refreshing} onClick={() => {
            setNowMs(Date.now());
            onRefresh();
          }}>Refresh</Button>
        </div>
      </CardHeader>
      <CardContent className="stack-tight">
        <div className="hb-grid">
          <div className="hb-cell">
            <div className="hb-label">First heartbeat</div>
            <div className="hb-value mono">{formatRelativeAge(getString(agent, ['created_at'], ''), nowMs)}</div>
            <div className="hb-note muted">install completed</div>
          </div>
          <div className="hb-cell">
            <div className="hb-label">Last heartbeat</div>
            <div className="hb-value mono">{agentHeartbeatFreshness(agent, nowMs)}</div>
            <div className="hb-note muted">{formatDate(agent.last_heartbeat_at)}</div>
          </div>
          <div className="hb-cell">
            <div className="hb-label">Cadence (p50)</div>
            <div className="hb-value mono">
              {cadence ? `${(cadence.p50Ms / 1000).toFixed(1)}s ± ${(cadence.spreadMs / 1000).toFixed(1)}s` : '—'}
            </div>
            <div className="hb-note muted">{segments.length > 0 ? `from ${segments.length} audit heartbeats` : 'awaiting trace'}</div>
          </div>
          <div className="hb-cell">
            <div className="hb-label">Install nonce</div>
            <div className="hb-value mono" style={{ color: nonce.label === 'match' ? 'var(--success)' : undefined }} title={nonce.provenance}>
              {nonce.label}
            </div>
            <div className="hb-note muted">correlated with bootstrap</div>
          </div>
        </div>
        <div className="hb-trace-wrap">
          <div className="hb-trace-head">
            <span className="eyebrow">Last 30 heartbeats</span>
            <span className="muted mono">newest →</span>
          </div>
          {segments.length === 0 ? (
            <p className="muted" role="status"><Activity size={16} aria-hidden="true" /> No heartbeat audit segments yet. Trace fills after agent heartbeats are recorded.</p>
          ) : (
            <div className="hb-trace" aria-label="Heartbeat trace, last 30 pings">
              {segments.map((segment) => (
                <span
                  key={segment.id}
                  className={`hb-dot${segment.tone === 'slow' ? ' is-slow' : ''}${segment.tone === 'now' ? ' is-now' : ''}${segment.tone === 'ok' ? ' is-ok' : ''}`}
                  title={segment.title}
                />
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}