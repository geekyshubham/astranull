import { useCallback, useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { EmptyState } from '../components/ui/empty-state';
import { Button } from '../components/ui/button';
import type { DataItem } from './types';

export type FriendlyEmptyStateProps = {
  icon: LucideIcon;
  title: string;
  body: string;
  actionLabel?: string;
  actionHref?: string;
  onAction?: () => void;
};

/** Friendly empty state with optional Create CTA for CRUD list surfaces. */
export function renderFriendlyEmptyState(props: FriendlyEmptyStateProps) {
  return <EmptyState {...props} />;
}

export function extractAuditEntryId(payload: unknown): string {
  if (!payload || typeof payload !== 'object') return '';
  const item = payload as DataItem;
  const direct = item.audit_entry_id ?? item.audit_id ?? item.entry_id;
  if (direct != null && String(direct).trim()) return String(direct);
  const audit = item.audit;
  if (audit && typeof audit === 'object' && !Array.isArray(audit)) {
    const nested = (audit as DataItem).id ?? (audit as DataItem).entry_id;
    if (nested != null && String(nested).trim()) return String(nested);
  }
  return '';
}

export function formatMutationSuccessMessage(success: string, payload: unknown) {
  const auditId = extractAuditEntryId(payload);
  return auditId ? `${success} Audit entry: ${auditId}.` : success;
}

type ConfirmModalProps = {
  open: boolean;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  confirmTone?: 'danger' | 'default';
  requireTypedId?: string;
  typedPlaceholder?: string;
  busy?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
};

export function ConfirmModal({
  open,
  title,
  description,
  confirmLabel,
  confirmTone = 'danger',
  requireTypedId,
  typedPlaceholder,
  busy = false,
  onCancel,
  onConfirm
}: ConfirmModalProps) {
  const titleId = useId();
  const [typed, setTyped] = useState('');
  const dialogRef = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  useEffect(() => {
    if (!open) setTyped('');
  }, [open]);

  const needsTyped = Boolean(requireTypedId?.trim());
  const typedOk = !needsTyped || typed.trim() === requireTypedId?.trim();

  if (!open) return null;

  return (
    <dialog ref={dialogRef} className="modal-confirm" aria-labelledby={titleId} onCancel={(event) => {
      event.preventDefault();
      onCancel();
    }}>
      <form
        method="dialog"
        className="modal-confirm-body"
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          if (!typedOk || busy) return;
          onConfirm();
        }}
      >
        <h3 id={titleId}>{title}</h3>
        <div className="modal-confirm-desc">{description}</div>
        {needsTyped ? (
          <label className="full">
            <span>Type <code>{requireTypedId}</code> to confirm</span>
            <input
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              placeholder={typedPlaceholder ?? requireTypedId}
              autoComplete="off"
              disabled={busy}
            />
          </label>
        ) : null}
        <div className="modal-confirm-actions">
          <Button type="button" variant="ghost" disabled={busy} onClick={onCancel}>Cancel</Button>
          <Button type="submit" variant={confirmTone === 'danger' ? 'danger' : 'default'} loading={busy} disabled={!typedOk || busy}>
            {confirmLabel}
          </Button>
        </div>
      </form>
    </dialog>
  );
}

export function useConfirmModal() {
  const [state, setState] = useState<{
    open: boolean;
    title: string;
    description: ReactNode;
    confirmLabel: string;
    requireTypedId?: string;
    onConfirm?: () => void | Promise<void>;
  }>({ open: false, title: '', description: '', confirmLabel: 'Confirm' });

  const requestConfirm = useCallback((opts: {
    title: string;
    description: ReactNode;
    confirmLabel?: string;
    requireTypedId?: string;
    onConfirm: () => void | Promise<void>;
  }) => {
    setState({
      open: true,
      title: opts.title,
      description: opts.description,
      confirmLabel: opts.confirmLabel ?? 'Confirm',
      requireTypedId: opts.requireTypedId,
      onConfirm: opts.onConfirm
    });
  }, []);

  const close = useCallback(() => {
    setState((prev) => ({ ...prev, open: false, onConfirm: undefined }));
  }, []);

  return { state, requestConfirm, close };
}