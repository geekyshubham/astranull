import { useEffect, useMemo, useState } from 'react';
import { TriangleAlert } from 'lucide-react';
import { FindingCard } from './finding-card';
import { Button } from '../ui/button';
import { EmptyState } from '../ui/empty-state';
import { Select } from '../ui/select';
import type { DataItem } from '../../lib/types';
import { buildDetailHref } from '../../lib/route-params';

type StatusFilter = 'open' | 'closed' | 'accepted' | 'all';
type SortKey = 'severity' | 'recent' | 'oldest' | 'sla' | 'title';

const PAGE_SIZES = [6, 12, 24] as const;

function getString(item: DataItem, keys: string[], fallback = '') {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  s1: 0,
  high: 1,
  s2: 1,
  medium: 2,
  s3: 2,
  low: 3,
  s4: 3,
  info: 4
};

function statusMatches(finding: DataItem, filter: StatusFilter) {
  const status = getString(finding, ['status', 'state'], 'open').toLowerCase();
  if (filter === 'all') return true;
  if (filter === 'open') return status === 'open';
  if (filter === 'closed') return status === 'closed';
  if (filter === 'accepted') return status === 'accepted' || status === 'accepted_risk';
  return true;
}

function sortFindings(items: DataItem[], sort: SortKey) {
  const copy = [...items];
  copy.sort((left, right) => {
    if (sort === 'severity') {
      const leftRank = SEVERITY_RANK[getString(left, ['severity'], 'low').toLowerCase()] ?? 9;
      const rightRank = SEVERITY_RANK[getString(right, ['severity'], 'low').toLowerCase()] ?? 9;
      return leftRank - rightRank;
    }
    if (sort === 'title') {
      return getString(left, ['title'], '').localeCompare(getString(right, ['title'], ''));
    }
    const leftTs = String(left.created_at ?? left.opened_at ?? '');
    const rightTs = String(right.created_at ?? right.opened_at ?? '');
    if (sort === 'oldest') return leftTs.localeCompare(rightTs);
    if (sort === 'recent') return rightTs.localeCompare(leftTs);
    const leftSla = String(left.sla_due_at ?? left.rem_sla ?? left.remSla ?? '');
    const rightSla = String(right.sla_due_at ?? right.rem_sla ?? right.remSla ?? '');
    return leftSla.localeCompare(rightSla);
  });
  return copy;
}

export function FindingsListView({
  findings,
  checks,
  targetGroups
}: {
  findings: DataItem[];
  checks: DataItem[];
  targetGroups: DataItem[];
}) {
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('open');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [ownerFilter, setOwnerFilter] = useState('all');
  const [groupFilter, setGroupFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [sort, setSort] = useState<SortKey>('severity');
  const [pageSize, setPageSize] = useState<(typeof PAGE_SIZES)[number]>(6);
  const [page, setPage] = useState(0);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebouncedSearch(search.trim().toLowerCase()), 250);
    return () => window.clearTimeout(timer);
  }, [search]);

  useEffect(() => {
    setPage(0);
  }, [statusFilter, severityFilter, ownerFilter, groupFilter, debouncedSearch, sort, pageSize]);

  const owners = useMemo(() => [...new Set(findings.map((finding) => getString(finding, ['assignee', 'owner'], 'unassigned')))].sort(), [findings]);
  const severities = useMemo(() => [...new Set(findings.map((finding) => getString(finding, ['severity'], 'unknown')))].sort(), [findings]);

  const statusCounts = useMemo(() => ({
    open: findings.filter((finding) => statusMatches(finding, 'open')).length,
    closed: findings.filter((finding) => statusMatches(finding, 'closed')).length,
    accepted: findings.filter((finding) => statusMatches(finding, 'accepted')).length,
    all: findings.length
  }), [findings]);

  const filtered = useMemo(() => {
    return sortFindings(
      findings.filter((finding) => {
        if (!statusMatches(finding, statusFilter)) return false;
        const severity = getString(finding, ['severity'], 'unknown');
        const owner = getString(finding, ['assignee', 'owner'], 'unassigned');
        const groupId = getString(finding, ['target_group_id'], '');
        if (severityFilter !== 'all' && severity !== severityFilter) return false;
        if (ownerFilter !== 'all' && owner !== ownerFilter) return false;
        if (groupFilter !== 'all' && groupId !== groupFilter) return false;
        if (!debouncedSearch) return true;
        const haystack = [
          getString(finding, ['id']),
          getString(finding, ['title', 'summary']),
          getString(finding, ['check_id']),
          owner,
          groupId
        ].join(' ').toLowerCase();
        return haystack.includes(debouncedSearch);
      }),
      sort
    );
  }, [findings, statusFilter, severityFilter, ownerFilter, groupFilter, debouncedSearch, sort]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const pageItems = filtered.slice(currentPage * pageSize, currentPage * pageSize + pageSize);
  const rangeStart = filtered.length === 0 ? 0 : currentPage * pageSize + 1;
  const rangeEnd = Math.min(filtered.length, (currentPage + 1) * pageSize);

  function openFinding(id: string) {
    if (!id) return;
    window.location.hash = buildDetailHref('finding-detail', id).replace(/^#/, '');
  }

  return (
    <div className="findings-surface">
      <div className="findings-toolbar">
        <div className="ft-status" role="tablist" aria-label="Finding status filters">
          {(['open', 'closed', 'accepted', 'all'] as StatusFilter[]).map((filter) => (
            <button
              key={filter}
              type="button"
              className={`ft-tab btn${statusFilter === filter ? ' is-active' : ''}`}
              role="tab"
              aria-selected={statusFilter === filter}
              onClick={() => setStatusFilter(filter)}
            >
              {filter === 'accepted' ? 'Accepted' : filter.charAt(0).toUpperCase() + filter.slice(1)}
              <span className="ft-count">{statusCounts[filter]}</span>
            </button>
          ))}
        </div>
        <div className="ft-controls">
          <label className="ft-field ft-search">
            <span className="ft-label">Search</span>
            <input className="input" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Filter findings" />
          </label>
          <label className="ft-field">
            <span className="ft-label">Severity</span>
            <select className="select" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
              <option value="all">All severities</option>
              {severities.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
            </select>
          </label>
          <label className="ft-field">
            <span className="ft-label">Owner</span>
            <select className="select" value={ownerFilter} onChange={(event) => setOwnerFilter(event.target.value)}>
              <option value="all">All owners</option>
              {owners.map((owner) => <option key={owner} value={owner}>{owner}</option>)}
            </select>
          </label>
          <label className="ft-field">
            <span className="ft-label">Target group</span>
            <select className="select" value={groupFilter} onChange={(event) => setGroupFilter(event.target.value)}>
              <option value="all">All groups</option>
              {targetGroups.map((group) => {
                const id = getString(group, ['id'], '');
                return <option key={id} value={id}>{getString(group, ['name', 'id'], id)}</option>;
              })}
            </select>
          </label>
          <label className="ft-field">
            <span className="ft-label">Sort</span>
            <select className="select" value={sort} onChange={(event) => setSort(event.target.value as SortKey)}>
              <option value="severity">Severity</option>
              <option value="recent">Recently opened</option>
              <option value="oldest">Oldest first</option>
              <option value="sla">SLA remaining</option>
              <option value="title">Title A to Z</option>
            </select>
          </label>
        </div>
      </div>

      {pageItems.length === 0 ? (
        <div className="findings-empty">
          <EmptyState
            icon={TriangleAlert}
            title="No matching findings."
            body="Findings appear after validation runs publish evidence-backed gaps."
            actionLabel="Open test runs"
            actionHref="#runs"
          />
        </div>
      ) : (
        <div className="findings-list findings-grid">
          {pageItems.map((finding) => (
            <FindingCard
              key={getString(finding, ['id'], Math.random().toString(36))}
              finding={finding}
              checks={checks}
              targetGroups={targetGroups}
              onOpen={openFinding}
            />
          ))}
        </div>
      )}

      <div className="findings-pager">
        <p className="fp-info">
          Showing <span>{rangeStart}</span> to <span>{rangeEnd}</span> of <span>{filtered.length}</span>
        </p>
        <div className="fp-controls">
          <Select
            label="Page size"
            value={String(pageSize)}
            options={PAGE_SIZES.map((size) => ({ value: String(size), label: String(size) }))}
            onChange={(value) => setPageSize(Number(value) as (typeof PAGE_SIZES)[number])}
          />
          <Button className="btn btn-ghost btn-sm" disabled={currentPage <= 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>Previous</Button>
          <Button className="btn btn-ghost btn-sm" disabled={currentPage >= pageCount - 1} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>Next</Button>
          <span className="fp-info">Page <span>{currentPage + 1}</span> of <span>{pageCount}</span></span>
        </div>
      </div>
    </div>
  );
}