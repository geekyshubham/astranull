import type { LucideIcon } from 'lucide-react';
import { EmptyState } from '../components/ui/empty-state';
import type { DataItem } from './types';

export function readMetaAction(meta: DataItem | null | undefined, key: string) {
  if (!meta) return undefined;
  const value = meta[key];
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text || undefined;
}

function readEmptyReason(meta: DataItem | null | undefined, keys: string[] = ['empty_reason']) {
  if (!meta) return '';
  for (const key of keys) {
    const value = meta[key];
    if (value !== undefined && value !== null && String(value).trim()) return String(value);
  }
  return '';
}

export function PortalLoadingSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="content stack-tight" aria-busy="true" aria-live="polite">
      {Array.from({ length: rows }, (_, index) => (
        <div key={index} className="skeleton skeleton-row" />
      ))}
    </div>
  );
}

export function emptyStateFromApi({
  icon,
  meta,
  actionHref,
  actionLabel,
  loading = false
}: {
  icon: LucideIcon;
  meta?: DataItem | null;
  actionHref?: string;
  actionLabel?: string;
  loading?: boolean;
}) {
  const reason = readEmptyReason(meta);
  if (!reason) return loading ? <PortalLoadingSkeleton /> : null;

  const title = readEmptyReason(meta, ['empty_title', 'title']) || reason.split('.')[0] || reason;
  const body = readEmptyReason(meta, ['empty_body', 'body', 'empty_reason']) || reason;
  return (
    <EmptyState
      icon={icon}
      title={title}
      body={body}
      actionHref={actionHref}
      actionLabel={actionLabel}
    />
  );
}