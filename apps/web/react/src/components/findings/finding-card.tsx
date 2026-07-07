import { buildDetailHref } from '../../lib/route-params';
import type { DataItem } from '../../lib/types';
import { formatDate } from '../../lib/utils';
import { findingSlaDueAt, isFindingSlaBreach } from '../../lib/findings-helpers';
import { Badge } from '../ui/badge';

function getString(item: DataItem, keys: string[], fallback = '') {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function slaClass(finding: DataItem) {
  const status = getString(finding, ['status', 'state'], 'open');
  if (status !== 'open') return '';
  if (isFindingSlaBreach(finding)) return 'is-danger';
  const dueAt = findingSlaDueAt(finding);
  if (!dueAt) return '';
  const hoursLeft = (dueAt - Date.now()) / (60 * 60 * 1000);
  return hoursLeft <= 24 ? 'is-warn' : '';
}

function slaLabel(finding: DataItem) {
  const status = getString(finding, ['status', 'state'], 'open');
  const remSla = getString(finding, ['rem_sla', 'remSla', 'sla'], '');
  if (remSla) return remSla;
  if (status !== 'open') {
    const closedAt = finding.updated_at ?? finding.closed_at;
    if (closedAt) return `closed ${formatDate(closedAt)}`;
    return getString(finding, ['closed'], 'closed');
  }
  const dueAt = findingSlaDueAt(finding);
  if (!dueAt) return 'SLA pending';
  if (isFindingSlaBreach(finding)) return 'overdue';
  const hoursLeft = Math.max(0, Math.round((dueAt - Date.now()) / (60 * 60 * 1000)));
  return `${hoursLeft}h remaining`;
}

function severityTone(severity: string) {
  const key = severity.toLowerCase();
  if (key === 'critical' || key === 'high' || key === 's2' || key === 's1') return 'danger' as const;
  if (key === 'medium' || key === 's3') return 'warn' as const;
  return 'muted' as const;
}

export function FindingCard({
  finding,
  checks,
  targetGroups,
  active = false,
  onOpen
}: {
  finding: DataItem;
  checks: DataItem[];
  targetGroups: DataItem[];
  active?: boolean;
  onOpen?: (id: string) => void;
}) {
  const id = getString(finding, ['id'], '');
  const title = getString(finding, ['title', 'summary'], id);
  const severity = getString(finding, ['severity'], 'unknown');
  const verdict = getString(finding, ['verdict'], '');
  const state = getString(finding, ['status', 'state'], 'open');
  const owner = getString(finding, ['assignee', 'owner', 'rem_owner', 'remOwner'], 'unassigned');
  const checkId = getString(finding, ['check_id'], '');
  const check = checks.find((entry) => getString(entry, ['check_id']) === checkId);
  const checkLabel = getString(check ?? {}, ['name', 'title'], checkId || 'check');
  const groupId = getString(finding, ['target_group_id'], '');
  const group = targetGroups.find((entry) => getString(entry, ['id']) === groupId);
  const groupLabel = getString(group ?? {}, ['name', 'id'], groupId || 'ungrouped');
  const openedAt = finding.created_at ?? finding.opened_at;
  const href = id ? buildDetailHref('finding-detail', id) : '#findings';

  return (
    <article
      className={`finding-card${active ? ' is-active' : ''}`}
      role="link"
      tabIndex={0}
      onClick={() => onOpen?.(id)}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onOpen?.(id);
        }
      }}
    >
      <div className="fc-top">
        <Badge tone={severityTone(severity)} title={`Severity ${severity} from finding API`}>{severity}</Badge>
        {verdict ? <Badge tone="info" title={`Verdict ${verdict} from finding API`}>{verdict}</Badge> : null}
        <span className="fc-meta mono">{id}</span>
      </div>
      <div className="fc-body">
        <div className="fc-headline">
          <h4>{title}</h4>
          <span className="fc-state" title={`State ${state} from finding API`}>{state}</span>
        </div>
        <div className="fc-facets">
          <span><span className="fc-key">owner:</span> {owner}</span>
          <span className="fc-sep">·</span>
          <span><span className="fc-key">check:</span> {checkLabel}</span>
          <span className="fc-sep">·</span>
          <span><span className="fc-key">group:</span> {groupLabel}</span>
          <span className="fc-sep">·</span>
          <span><span className="fc-key">opened:</span> {formatDate(openedAt)}</span>
        </div>
        <div className={`fc-sla ${slaClass(finding)}`} title="SLA window derived from severity hours and opened timestamp">
          {slaLabel(finding)}
        </div>
      </div>
      <a className="sr-only" href={href}>Open finding {title}</a>
    </article>
  );
}