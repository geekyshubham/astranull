import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type HTMLAttributes,
  type KeyboardEvent,
  type ReactNode
} from 'react';
import { Activity, Bot, Check, Globe, ShieldHalf, Target, TriangleAlert } from 'lucide-react';
import { requestJson } from '../lib/api';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { formatDate } from '../lib/utils';
import { VerifyChip, resolveVerifyChipState, resolveTargetVerificationProvenance } from '../lib/verify-chip';
import { emptyStateFromApi, PortalLoadingSkeleton } from '../lib/empty-from-api';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Badge } from '../components/ui/badge';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Tabs, type TabOption } from '../components/ui/tabs';

type OnboardTab = 'fqdn' | 'ip' | 'cloud';

const ONBOARD_TAB_OPTIONS: TabOption<OnboardTab>[] = [
  { id: 'fqdn', label: 'Domain · DNS TXT' },
  { id: 'ip', label: 'IP address · Agent callback' },
  { id: 'cloud', label: 'Cloud provider · pull inventory' }
];

/** §7.1 verification states that unlock the per-row Run test action. */
const RUN_ENABLED_STATES = new Set(['dns_verified', 'agent_verified', 'user_confirmed']);
const DNS_POLL_INTERVAL_MS = 30_000;
const DNS_POLL_MAX_MS = 15 * 60 * 1000;

const DETAIL_MODAL_STYLES_ID = 'detail-modal-primitive-styles';
const detailModalStyles = `
.detail-modal.modal-confirm {
  padding: 0;
  max-width: min(560px, calc(100% - 32px));
  width: min(560px, calc(100% - 32px));
  max-height: min(88vh, 920px);
  display: flex;
  flex-direction: column;
}
.detail-modal.detail-modal-wide.modal-confirm {
  max-width: min(920px, calc(100% - 32px));
  width: min(920px, calc(100% - 32px));
}
.detail-modal .detail-modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
  padding: 16px 20px;
  border-bottom: 1px solid var(--border-soft);
}
.detail-modal .detail-modal-head h3 {
  margin: 0;
  font-family: var(--font-display);
  font-size: 16px;
  font-weight: 600;
  color: var(--fg);
}
.detail-modal .detail-modal-body {
  padding: 18px 20px;
  overflow-y: auto;
}
.detail-modal .detail-modal-body .tabs {
  margin-bottom: var(--space-4);
}
`;

const TG_DETAIL_STYLES_ID = 'tg-detail-view-styles';
// Token-only styling for the prototype's DNS/link-button primitives, scoped to this page so it
// cannot collide with styles injected by sibling detail pages. No literal colors (tokens only).
const tgDetailStyles = `
.tg-detail-view .vl-num svg { display: block; color: var(--success); }
.tg-detail-view .dns-field { display: flex; flex-direction: column; gap: 4px; align-items: flex-start; }
.tg-detail-view .dns-key { font-family: var(--font-mono); font-size: 10.5px; letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--fg-2); }
.tg-detail-view .dns-val { color: var(--fg); font-size: var(--text-sm); word-break: break-all; }
.tg-detail-view .dns-head { display: flex; align-items: center; gap: 10px; }
.tg-detail-view .dns-head .spacer { flex: 1 1 auto; }
.tg-detail-view .dns-footer { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.tg-detail-view .dns-history { margin-top: 16px; }
.tg-detail-view .dns-history-title { font-family: var(--font-mono); font-size: 10.5px; letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--fg-2); margin: 0 0 8px; }
.tg-detail-view .link-btn { background: none; border: 0; padding: 0; font: inherit; color: var(--accent); cursor: pointer; font-size: var(--text-xs); text-decoration: underline; text-underline-offset: 2px; }
.tg-detail-view .link-btn:hover { color: var(--fg); }
.tg-detail-view .link-btn:focus-visible { outline: none; box-shadow: var(--focus-ring); border-radius: var(--radius-sm); }
/* Light theme: brand orange (--accent) resolves to ~2.5:1 on the white surface and fails WCAG AA
   4.5:1 for this small link text. Scope an AA-safe ink token to light only; dark theme keeps the
   orange link (~9:1 on black). The underline carries the affordance in both themes. */
:root[data-theme="light"] .tg-detail-view .link-btn { color: var(--fg-2); }
:root[data-theme="light"] .tg-detail-view .link-btn:hover { color: var(--fg); }
/* A signed LOA is a success state: realize the documented "green when signed" intent so the
   callout no longer wears the unsigned warn border. Border + icon tone only, token-driven. */
.tg-detail-view .callout-loa[data-loa-state="signed"] { border-color: color-mix(in oklab, var(--success), transparent 55%); }
.tg-detail-view .callout-loa[data-loa-state="signed"] .callout-icon { color: var(--success); border-color: color-mix(in oklab, var(--success), transparent 55%); }
`;

function ensureStyles(id: string, css: string) {
  if (typeof document === 'undefined') return;
  if (document.getElementById(id)) return;
  const node = document.createElement('style');
  node.id = id;
  node.textContent = css;
  document.head.appendChild(node);
}

function ensureDetailModalStyles() {
  ensureStyles(DETAIL_MODAL_STYLES_ID, detailModalStyles);
}

function ensureTgDetailStyles() {
  ensureStyles(TG_DETAIL_STYLES_ID, tgDetailStyles);
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

/** Nested verification envelope (Postgres target payload) when present. */
function targetVerificationEnvelope(item: DataItem): DataItem | null {
  const nested = item.verification;
  return nested && typeof nested === 'object' && !Array.isArray(nested) ? (nested as DataItem) : null;
}

/** Authoritative verification state across dev (flat) and Postgres (nested) target shapes. */
function targetVerificationState(item: DataItem) {
  const nested = targetVerificationEnvelope(item);
  if (nested) {
    const state = getString(nested, ['state'], '');
    if (state !== '—' && state) return state;
  }
  return getString(item, ['verification_state', 'verify_state', 'state'], 'unverified');
}

function canRunTest(state: string) {
  return RUN_ENABLED_STATES.has(state.trim().toLowerCase());
}

/** Map a DNS challenge record onto a §7.1 verification-chip state. */
function challengeChipState(challenge: DataItem | null, verified?: boolean) {
  if (!challenge) return 'unverified';
  const state = getString(challenge, ['state'], '').toLowerCase();
  if (verified === true || state === 'resolved') return 'dns_verified';
  if (state === 'pending') return 'pending';
  if (state === 'expired' || state === '—' || !state) return 'unverified';
  return state;
}

function pickActiveChallenge(list: DataItem[]): DataItem | null {
  if (list.length === 0) return null;
  const pending = list.find((row) => getString(row, ['state'], '').toLowerCase() === 'pending');
  if (pending) return pending;
  return [...list].sort((a, b) =>
    String(getString(b, ['issued_at'], '')).localeCompare(String(getString(a, ['issued_at'], '')))
  )[0] ?? null;
}

function DetailStatusBanners({ loadError, message, error }: { loadError: string; message: string; error: string }) {
  return (
    <>
      {loadError ? <div className="form-banner error" role="alert">{loadError}</div> : null}
      {(message || error) && !loadError ? (
        <div className={error ? 'form-banner error' : 'form-banner'} role={error ? 'alert' : 'status'}>
          {error || message}
        </div>
      ) : null}
    </>
  );
}

function DetailModal({
  title,
  onClose,
  children,
  wide = true
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  const titleId = useId();
  const dialogRef = useRef<HTMLDialogElement>(null);
  ensureDetailModalStyles();

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog && !dialog.open) dialog.showModal();
    return () => {
      if (dialog?.open) dialog.close();
    };
  }, []);

  return (
    <dialog
      ref={dialogRef}
      className={`modal-confirm detail-modal${wide ? ' detail-modal-wide' : ''}`}
      aria-labelledby={titleId}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <div className="detail-modal-head">
        <h3 id={titleId}>{title}</h3>
        <Button size="sm" variant="ghost" onClick={onClose} aria-label="Close dialog">
          Close
        </Button>
      </div>
      <div className="detail-modal-body">{children}</div>
    </dialog>
  );
}

export function TargetGroupDetailView({
  entity,
  entityId,
  data,
  config,
  session,
  onRefresh,
  loading,
  loadError
}: {
  entity: DataItem;
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  loading: boolean;
  loadError: string;
}) {
  ensureTgDetailStyles();

  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [dnsChallenge, setDnsChallenge] = useState<DataItem | null>(null);
  const [dnsVerifyResult, setDnsVerifyResult] = useState<DataItem | null>(null);
  const [dnsChallenges, setDnsChallenges] = useState<DataItem[]>([]);
  const [copiedField, setCopiedField] = useState('');
  const [ladder, setLadder] = useState<DataItem | null>(null);
  const [ladderLoading, setLadderLoading] = useState(true);
  const [connectors, setConnectors] = useState<DataItem[]>([]);
  const [connectorsMeta, setConnectorsMeta] = useState<DataItem | null>(null);
  const [inventoryProvider, setInventoryProvider] = useState<string | null>(null);
  const [inventoryRows, setInventoryRows] = useState<DataItem[]>([]);
  const [inventoryMeta, setInventoryMeta] = useState<DataItem | null>(null);
  const [selectedInventory, setSelectedInventory] = useState<Set<string>>(new Set());
  const [showLoaModal, setShowLoaModal] = useState(false);
  const [showOnboardModal, setShowOnboardModal] = useState(false);
  const [onboardTab, setOnboardTab] = useState<OnboardTab>('fqdn');

  const onRefreshRef = useRef(onRefresh);
  useEffect(() => { onRefreshRef.current = onRefresh; }, [onRefresh]);

  const targets = Array.isArray(entity.targets) ? entity.targets as DataItem[] : [];
  const agents = Array.isArray(data.agents) ? data.agents as DataItem[] : [];
  const checks = Array.isArray(data.checks) ? data.checks as DataItem[] : [];
  const relatedRuns = Array.isArray(entity.runs_recent) ? entity.runs_recent as DataItem[] : [];
  const relatedFindings = Array.isArray(entity.findings_on_group) ? entity.findings_on_group as DataItem[] : [];
  const groupMeta = entity.meta && typeof entity.meta === 'object' && !Array.isArray(entity.meta) ? entity.meta as DataItem : null;
  const targetCount = String(entity.target_count ?? targets.length);
  const loaState = getString(entity, ['loa_state', 'loa_status'], getString(entity.loa as DataItem | undefined, ['state'], 'required'));
  const loaSigned = loaState.toLowerCase() === 'signed';
  // KPI row (matches prototype screen-target-group-detail): ownership + validation mode read
  // straight off the target-group API entity (both fields exist in the dev store and Postgres,
  // defaulting to 'unverified'/'agent_assisted').
  const ownershipStatus = getString(entity, ['ownership_status'], 'unverified');
  const ownershipTone = ['agent_verified', 'dns_verified', 'user_confirmed', 'verified'].includes(ownershipStatus.trim().toLowerCase())
    ? 'success'
    : ownershipStatus.trim().toLowerCase().includes('pending')
      ? 'warn'
      : 'muted';
  const validationMode = getString(entity, ['validation_mode'], 'agent_assisted');
  const ladderSteps = Array.isArray(ladder?.steps) ? ladder.steps as DataItem[] : [];

  // First customer-runnable safe check — the concrete check a bounded Run test executes.
  const safeCheck = checks.find((check) => getString(check, ['safety_class'], '') === 'safe') ?? null;
  const safeCheckId = getString(safeCheck, ['check_id'], '');
  const verifiedTargetCount = targets.filter((target) => canRunTest(targetVerificationState(target))).length;

  // Active DNS challenge shown in the panel: freshest verify result, then freshly issued, then list.
  const activeChallenge = (dnsVerifyResult?.challenge as DataItem | undefined) ?? dnsChallenge ?? pickActiveChallenge(dnsChallenges);
  const dnsVerified = dnsVerifyResult?.verified === true || getString(activeChallenge, ['state'], '').toLowerCase() === 'resolved';
  const dnsChipState = challengeChipState(activeChallenge, dnsVerified);
  const activeChallengeId = getString(activeChallenge, ['id', 'challenge_id'], '');
  const activeChallengeState = getString(activeChallenge, ['state'], '').toLowerCase();
  // §7.2 cycle: surface the transient "checking…" chip while a verify request is in flight.
  const displayedDnsChipState = busy === `dns-verify-${entityId}` && dnsChipState === 'pending' ? 'checking' : dnsChipState;

  const loadDnsChallenges = useCallback(() => {
    return requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/dns-ownership`)
      .then((payload) => {
        const envelope = payload as DataItem;
        setDnsChallenges(Array.isArray(envelope.items) ? envelope.items as DataItem[] : []);
      })
      .catch(() => setDnsChallenges([]));
  }, [config, session, entityId]);

  useEffect(() => {
    let cancelled = false;
    setLadderLoading(true);
    requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/verification-ladder`)
      .then((payload) => { if (!cancelled) setLadder(payload as DataItem); })
      .catch(() => { if (!cancelled) setLadder(null); })
      .finally(() => { if (!cancelled) setLadderLoading(false); });
    return () => { cancelled = true; };
  }, [config, session, entityId]);

  useEffect(() => { void loadDnsChallenges(); }, [loadDnsChallenges]);

  useEffect(() => {
    // Use connectors already loaded by fetchPortalData (gated on the connectorsEnabled
    // deployment feature). Avoids an unconditional GET /v1/connectors that 404s when the
    // connector add-on is disabled for the tenant.
    setConnectors(Array.isArray(data.connectors) ? (data.connectors as DataItem[]) : []);
    setConnectorsMeta(null);
  }, [data.connectors]);

  // §7.2 optional background polling: re-check a pending challenge every 30s until resolved.
  // Disabled under prefers-reduced-motion and capped at 15 minutes.
  useEffect(() => {
    if (activeChallengeState !== 'pending' || !activeChallengeId) return undefined;
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return undefined;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return undefined;

    const startedAt = Date.now();
    const timer = window.setInterval(() => {
      if (Date.now() - startedAt > DNS_POLL_MAX_MS) {
        window.clearInterval(timer);
        return;
      }
      requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/dns-ownership/verify`, {
        method: 'POST',
        body: { challenge_id: activeChallengeId }
      })
        .then(async (payload) => {
          const result = payload as DataItem;
          setDnsVerifyResult(result);
          if (result.verified === true) {
            window.clearInterval(timer);
            await loadDnsChallenges();
            await onRefreshRef.current();
          }
        })
        .catch(() => undefined);
    }, DNS_POLL_INTERVAL_MS);

    return () => window.clearInterval(timer);
  }, [config, session, entityId, activeChallengeId, activeChallengeState, loadDnsChallenges]);

  async function runAction(label: string, action: () => Promise<void>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      await action();
      setMessage(success);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy('');
    }
  }

  function openOnboardModal(tab: OnboardTab = 'fqdn') {
    setOnboardTab(tab);
    setError('');
    setMessage('');
    setShowOnboardModal(true);
  }

  async function addTarget(kind: string, value: string, expectedBehavior: string) {
    const trimmed = value.trim();
    if (!trimmed) {
      setError('A target value is required.');
      setMessage('');
      return;
    }
    setBusy(`add-target-${kind}`);
    setError('');
    setMessage('');
    try {
      await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/targets`, {
        method: 'POST',
        body: { kind, value: trimmed, expected_behavior: expectedBehavior || null }
      });
      setMessage('Target declared.');
      setShowOnboardModal(false);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to declare target.');
    } finally {
      setBusy('');
    }
  }

  function submitFqdnTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    void addTarget('fqdn', String(form.get('value') ?? ''), String(form.get('expected_behavior') ?? ''));
  }

  function submitIpTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const ip = String(form.get('value') ?? '').trim();
    const port = String(form.get('port') ?? '').trim();
    void addTarget('ip', port ? `${ip}:${port}` : ip, String(form.get('expected_behavior') ?? ''));
  }

  async function issueDnsChallenge(targetId?: string) {
    await runAction(`dns-issue-${entityId}`, async () => {
      const result = await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/dns-ownership/issue`, {
        method: 'POST',
        body: targetId ? { target_id: targetId } : {}
      }) as DataItem;
      const challenge = result.challenge && typeof result.challenge === 'object' ? result.challenge as DataItem : result;
      setDnsChallenge(challenge);
      setDnsVerifyResult(null);
      await loadDnsChallenges();
    }, 'DNS TXT challenge issued. Publish the record, then run Check now.');
  }

  async function verifyDnsChallenge(explicitChallengeId?: string) {
    await runAction(`dns-verify-${entityId}`, async () => {
      const challengeId = explicitChallengeId
        || getString(activeChallenge, ['id', 'challenge_id'], '')
        || getString(dnsChallenge, ['id', 'challenge_id'], '');
      const result = await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/dns-ownership/verify`, {
        method: 'POST',
        body: challengeId ? { challenge_id: challengeId } : {}
      }) as DataItem;
      setDnsVerifyResult(result);
      await loadDnsChallenges();
    }, 'DNS ownership verification checked.');
  }

  function copyField(field: string, value: string) {
    if (!value || value === '—') return;
    const flash = () => {
      setCopiedField(field);
      window.setTimeout(() => setCopiedField((current) => (current === field ? '' : current)), 1600);
    };
    try {
      if (navigator?.clipboard?.writeText) {
        navigator.clipboard.writeText(value).then(flash).catch(() => undefined);
      } else {
        flash();
      }
    } catch {
      // Clipboard API unavailable — no-op.
    }
  }

  // Per-row Verify: for a domain, issue (or re-check) a scoped DNS TXT challenge in place; for an
  // IP/agent-bound target, jump to target detail where the agent-binding flow lives (§4.5).
  function verifyTarget(item: DataItem) {
    const id = getString(item, ['id'], '');
    if (!id) return;
    const kind = getString(item, ['kind'], '').toLowerCase();
    if (kind !== 'fqdn') {
      window.location.hash = `target-detail?id=${encodeURIComponent(id)}`;
      return;
    }
    const existing = dnsChallenges.find(
      (row) => getString(row, ['target_id'], '') === id && getString(row, ['state'], '').toLowerCase() === 'pending'
    );
    if (existing) {
      void verifyDnsChallenge(getString(existing, ['id'], ''));
    } else {
      void issueDnsChallenge(id);
    }
  }

  async function openInventory(connectorId: string) {
    setInventoryProvider(connectorId);
    setBusy(`inventory-${connectorId}`);
    try {
      const payload = await requestJson(config, session, `/v1/connectors/${encodeURIComponent(connectorId)}/inventory`) as DataItem;
      setInventoryRows(Array.isArray(payload.items) ? payload.items as DataItem[] : []);
      setInventoryMeta(payload.meta && typeof payload.meta === 'object' ? payload.meta as DataItem : null);
      setSelectedInventory(new Set());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Inventory request failed.');
      setInventoryRows([]);
      setInventoryMeta({ empty_reason: err instanceof Error ? err.message : 'Inventory request failed.' });
    } finally {
      setBusy('');
    }
  }

  async function importInventory() {
    if (!inventoryProvider || selectedInventory.size === 0) return;
    await runAction(`import-${inventoryProvider}`, async () => {
      for (const rowId of selectedInventory) {
        const row = inventoryRows.find((item) => getString(item, ['id', 'value'], '') === rowId);
        if (!row) continue;
        await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/targets`, {
          method: 'POST',
          body: {
            kind: getString(row, ['kind'], 'fqdn'),
            value: getString(row, ['value', 'name'], rowId),
            source: inventoryProvider
          }
        });
      }
      setInventoryProvider(null);
      setInventoryRows([]);
      setSelectedInventory(new Set());
    }, 'Selected inventory rows imported.');
  }

  async function runBoundedTest(targetId: string) {
    if (!safeCheckId) {
      setError('No customer-runnable safe check is available to run.');
      setMessage('');
      return;
    }
    await runAction(`run-test-${targetId}`, async () => {
      await requestJson(config, session, '/v1/test-runs', {
        method: 'POST',
        body: { check_id: safeCheckId, target_group_id: entityId, target_id: targetId }
      });
    }, 'Bounded safe test run started.');
  }

  async function submitLoa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (form.get('attested') !== 'on') {
      setError('Attestation is required before signing LOA.');
      return;
    }
    await runAction(`loa-${entityId}`, async () => {
      await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(entityId)}/loa`, {
        method: 'POST',
        body: {
          attested: true,
          signer_name: String(form.get('signer_name') ?? '').trim(),
          signer_title: String(form.get('signer_title') ?? '').trim(),
          signed_date: String(form.get('signed_date') ?? '').trim()
        }
      });
      setShowLoaModal(false);
    }, 'LOA signed and recorded in custody ledger.');
  }

  function targetRowNavProps(item: DataItem): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
    const id = getString(item, ['id'], '');
    if (!id) return {};
    const go = () => { window.location.hash = `target-detail?id=${encodeURIComponent(id)}`; };
    return {
      role: 'link',
      tabIndex: 0,
      style: { cursor: 'pointer' },
      'aria-label': `Open target ${getString(item, ['value'], id)}`,
      onClick: go,
      onKeyDown: (event: KeyboardEvent<HTMLTableRowElement>) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          go();
        }
      }
    };
  }

  const targetColumns: TableColumn<DataItem>[] = [
    { key: 'kind', label: 'Kind', render: (item) => <span className="mono">{getString(item, ['kind'], '—')}</span> },
    { key: 'value', label: 'Value', render: (item) => <span className="mono">{getString(item, ['value'], '—')}</span> },
    { key: 'expected', label: 'Expected behavior', render: (item) => <span className="mono">{getString(item, ['expected_behavior', 'expected'], '—')}</span> },
    {
      key: 'verification',
      label: 'Verification',
      render: (item) => {
        const state = targetVerificationState(item);
        const provenance = resolveTargetVerificationProvenance(item, targetVerificationEnvelope(item));
        const chip = resolveVerifyChipState(state, provenance);
        return <span className={chip.className} title={chip.title}><span className="vc-dot" aria-hidden="true" />{chip.label}</span>;
      }
    },
    {
      key: 'last_probe',
      label: 'Last probe',
      render: (item) => {
        // Prototype shows the last correlated verdict per target. The target-group API does not
        // expose a per-target probe verdict yet, so render it only when present and fall back to
        // an explicit em dash (empty is correct — never fabricate a verdict badge).
        const probe = getString(item, ['last_probe', 'last_verdict'], '');
        if (!probe) return <span className="muted">—</span>;
        const key = probe.trim().toLowerCase();
        const tone = key === 'pass' ? 'success' : key === 'gap' || key === 'fail' ? 'danger' : 'warn';
        return <Badge tone={tone} title={`Last probe verdict ${probe} from target API`}>{probe}</Badge>;
      }
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const runnable = canRunTest(targetVerificationState(item));
        const runReady = runnable && Boolean(safeCheckId);
        const runTitle = runnable
          ? (safeCheckId ? 'Run bounded safe test' : 'No customer-runnable safe check available')
          : 'Verify to enable testing';
        return (
          <div className="row-end-actions" onClick={(event) => event.stopPropagation()}>
            <Button
              size="sm"
              variant="ghost"
              onClick={(event) => { event.stopPropagation(); verifyTarget(item); }}
            >
              Verify
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className={runReady ? undefined : 'is-locked'}
              disabled={!runReady || busy === `run-test-${id}`}
              title={runTitle}
              loading={busy === `run-test-${id}`}
              onClick={(event) => { event.stopPropagation(); void runBoundedTest(id); }}
            >
              Run test
            </Button>
          </div>
        );
      }
    }
  ];

  const findingColumns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (item) => {
        const targetId = getString(item, ['target_id'], '');
        return targetId
          ? <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-detail', targetId)}>{targetId}</AnchorButton>
          : <span className="muted">group-level</span>;
      }
    },
    {
      key: 'finding',
      label: 'Finding',
      render: (item) => <AnchorButton size="sm" variant="ghost" href={buildDetailHref('finding-detail', getString(item, ['id'], ''))}>{getString(item, ['title', 'id'], '')}</AnchorButton>
    },
    { key: 'severity', label: 'Severity', render: (item) => getString(item, ['severity'], 'unknown') },
    { key: 'status', label: 'Status', render: (item) => getString(item, ['status'], 'open') }
  ];

  const runColumns: TableColumn<DataItem>[] = [
    { key: 'run', label: 'Run', render: (item) => <AnchorButton size="sm" variant="ghost" href={buildDetailHref('run-detail', getString(item, ['id'], ''))}>{getString(item, ['id'], '')}</AnchorButton> },
    { key: 'policy', label: 'Policy', render: (item) => getString(item, ['policy_id', 'test_policy_id'], '—') },
    { key: 'checks', label: 'Checks', render: (item) => String(item.check_count ?? getString(item, ['check_id'], '—')) },
    { key: 'verdict', label: 'Verdict', render: (item) => getString(item, ['verdict', 'status'], 'pending') },
    { key: 'started', label: 'Started', render: (item) => formatDate(item.started_at ?? item.created_at) },
    { key: 'agent', label: 'Agent', render: (item) => getString(item, ['agent_id'], '—') }
  ];

  const dnsHistoryColumns: TableColumn<DataItem>[] = [
    { key: 'record', label: 'Record name', render: (item) => <span className="mono">{getString(item, ['record_name', 'name'], '—')}</span> },
    {
      key: 'state',
      label: 'State',
      render: (item) => <VerifyChip state={challengeChipState(item)} provenance={`DNS challenge ${getString(item, ['id'], '')} · ${getString(item, ['state'], 'pending')} per ownership API`} />
    },
    { key: 'issued', label: 'Issued', render: (item) => formatDate(item.issued_at) },
    { key: 'checked', label: 'Last checked', render: (item) => (item.last_checked_at ? formatDate(item.last_checked_at) : '—') }
  ];

  const dnsProvenance = dnsVerified
    ? `TXT record resolved for ${getString(activeChallenge, ['record_name'], 'this domain')} per DNS ownership API`
    : `DNS ownership challenge ${activeChallengeId || 'pending'} awaiting TXT resolution`;

  return (
    <div className="content stack-tight tg-detail-view">
      <div className="page-head">
        <div>
          <p className="eyebrow">Declared business service</p>
          <h1 className="page-title">{getString(entity, ['name'], entityId)}</h1>
          <p className="muted mono">{entityId}</p>
        </div>
        <AnchorButton size="sm" variant="secondary" href="#target-groups">All groups</AnchorButton>
      </div>

      {loading ? <PortalLoadingSkeleton rows={2} /> : null}
      <DetailStatusBanners loadError={loadError} message={message} error={error} />

      {/* (1) Ownership ladder — Declared → DNS verified → Agent verified → User confirmed. */}
      {ladderLoading ? <PortalLoadingSkeleton rows={1} /> : null}
      {!ladderLoading && ladderSteps.length === 0 ? (
        emptyStateFromApi({
          loading: ladderLoading,
          icon: Target,
          meta: ladder?.meta && typeof ladder.meta === 'object' ? ladder.meta as DataItem : null,
        })
      ) : null}
      {!ladderLoading && ladderSteps.length > 0 ? (
      <ol className="verify-ladder" aria-label="Ownership verification ladder">
        {ladderSteps.map((step, index) => {
          const done = step.done === true;
          const now = !done && ladderSteps.slice(0, index).every((entry) => entry.done === true);
          return (
            <li key={getString(step, ['id'], String(index))} className={`vl-step${done ? ' is-done' : ''}${now ? ' is-now' : ''}`}>
              <span className="vl-num" aria-hidden="true">{done ? <Check size={13} strokeWidth={2.6} /> : index + 1}</span>
              <div className="vl-body">
                <strong>{getString(step, ['label'], 'Step')}</strong>
                <span className="vl-meta">{getString(step, ['count'], '0')} of {getString(step, ['total'], '0')}</span>
              </div>
            </li>
          );
        })}
      </ol>
      ) : null}

      {/* (2) KPI row — Targets · Ownership · LOA · Validation mode (matches prototype screen-target-group-detail). */}
      <div className="kpi-row">
        <div className="kpi-cell">
          <div className="kpi-label">Targets</div>
          <div className="kpi-value">{targetCount}</div>
          <div className="kpi-delta">{verifiedTargetCount} verified · {Math.max(0, targets.length - verifiedTargetCount)} unverified</div>
        </div>
        <div className="kpi-cell">
          <div className="kpi-label">Ownership</div>
          <div className="kpi-value" style={{ fontSize: '18px' }}>
            <Badge tone={ownershipTone} title={`Ownership status ${ownershipStatus} from target group API`}>{ownershipStatus}</Badge>
          </div>
        </div>
        <div className="kpi-cell">
          <div className="kpi-label">LOA</div>
          <div className="kpi-value" style={{ fontSize: '18px' }}>
            <Badge tone={loaSigned ? 'success' : 'warn'} title={`LOA state ${loaState} from target group API`}>{loaSigned ? 'Signed' : 'Required'}</Badge>
          </div>
        </div>
        <div className="kpi-cell">
          <div className="kpi-label">Validation mode</div>
          <div className="kpi-value" style={{ fontSize: '18px' }}>{validationMode}</div>
        </div>
      </div>

      {/* (3) LOA callout — orange warn when unsigned, green success (signer + digest + date) when signed. */}
      <div className="callout callout-loa" data-loa-state={loaSigned ? 'signed' : 'required'}>
        <span className="callout-icon" aria-hidden="true"><ShieldHalf size={16} /></span>
        <div className="callout-body">
          <p className="callout-title">{loaSigned ? 'LOA signed' : 'Letter of Authorization required'}</p>
          <p className="callout-desc">
            {loaSigned
              ? `${getString(entity.loa as DataItem | undefined, ['signer_name'], getString(entity, ['loa_signer'], '—'))} · ${getString(entity.loa as DataItem | undefined, ['custody_digest_sha256', 'digest'], getString(entity, ['loa_digest'], '—'))} · ${formatDate((entity.loa as DataItem | undefined)?.signed_at ?? entity.loa_signed_at)}`
              : 'AstraNull will not run checks against these targets until a scoped LOA is signed by an owner. Sign the authorization artifact before SOC-gated checks can execute on this group.'}
          </p>
        </div>
        <div className="callout-actions">
          {!loaSigned ? (
            <>
              <Button size="sm" onClick={() => setShowLoaModal(true)}>Open target group &amp; sign LOA</Button>
              <Button size="sm" variant="ghost" onClick={() => void verifyDnsChallenge()} loading={busy === `dns-verify-${entityId}`} disabled={!activeChallengeId}>Review DNS status</Button>
            </>
          ) : null}
        </div>
      </div>

      {/* (4) DNS TXT verification panel — §7.2 issue → publish → check now → dns_verified. */}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>DNS TXT verification</CardTitle>
            <CardDescription>Prove domain ownership by publishing a one-time <span className="mono">_astranull-challenge</span> TXT record. Required before external-only checks run.</CardDescription>
          </div>
          <Button size="sm" onClick={() => void issueDnsChallenge()} loading={busy === `dns-issue-${entityId}`}>
            {activeChallenge ? 'Re-issue challenge' : 'Issue DNS challenge'}
          </Button>
        </CardHeader>
        <CardContent>
          {activeChallenge ? (
            <div className="dns-challenge" data-state={dnsChipState}>
              <div className="dns-head">
                <span className="eyebrow">Publish this TXT record</span>
                <span className="spacer" />
                <VerifyChip state={displayedDnsChipState} provenance={dnsProvenance} />
              </div>
              <div className="dns-fields">
                <div className="dns-field">
                  <span className="dns-key">Record type</span>
                  <span className="dns-val mono">TXT</span>
                </div>
                <div className="dns-field">
                  <span className="dns-key">Record name</span>
                  <span className="dns-val mono">{getString(activeChallenge, ['record_name', 'name'], '—')}</span>
                  <button type="button" className="link-btn" onClick={() => copyField('dns-name', getString(activeChallenge, ['record_name', 'name'], ''))} aria-label="Copy record name">
                    {copiedField === 'dns-name' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <div className="dns-field">
                  <span className="dns-key">Record value</span>
                  <span className="dns-val mono">{getString(activeChallenge, ['record_value', 'value'], '—')}</span>
                  <button type="button" className="link-btn" onClick={() => copyField('dns-value', getString(activeChallenge, ['record_value', 'value'], ''))} aria-label="Copy record value">
                    {copiedField === 'dns-value' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <div className="dns-field">
                  <span className="dns-key">TTL</span>
                  <span className="dns-val mono">{getString(activeChallenge, ['ttl_seconds', 'ttl'], '—')} seconds</span>
                </div>
              </div>
              <div className="dns-footer">
                <Button size="sm" onClick={() => void verifyDnsChallenge()} loading={busy === `dns-verify-${entityId}`} disabled={!activeChallengeId || dnsChipState === 'dns_verified'}>
                  Check now
                </Button>
                <span className="muted small">
                  {dnsChipState === 'dns_verified'
                    ? `Resolved ${formatDate(getString(activeChallenge, ['resolved_at'], '') || undefined)}`
                    : getString(activeChallenge, ['last_checked_at'], '') !== '—' && getString(activeChallenge, ['last_checked_at'], '')
                      ? `Last checked ${formatDate(activeChallenge?.last_checked_at)}`
                      : 'Last checked: not yet'}
                </span>
                {dnsChipState === 'pending' ? <span className="muted small">Auto-rechecks every 30s until resolved.</span> : null}
              </div>
            </div>
          ) : (
            <EmptyState
              icon={Globe}
              title="No DNS challenge issued yet"
              body="Issue a challenge to generate the TXT record for this group's domain target, publish it at your DNS provider, then run Check now to prove ownership."
              actionLabel="Issue DNS challenge"
              onAction={() => void issueDnsChallenge()}
            />
          )}
          {dnsChallenges.length > 0 ? (
            <div className="dns-history">
              <p className="dns-history-title">Challenge history</p>
              <DataTable
                columns={dnsHistoryColumns}
                items={dnsChallenges}
                getRowId={(item, index) => getString(item, ['id'], String(index))}
                empty={<span className="muted small">No challenges recorded.</span>}
              />
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* (5) Declared targets — clickable rows deep-link to target detail; per-row Verify + Run test. */}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Declared targets</CardTitle>
            <CardDescription>Env <span className="mono">{getString(entity, ['environment_id'], '—')}</span> · expected behavior declared per row · unverified targets cannot be run against</CardDescription>
          </div>
          <Button size="sm" onClick={() => openOnboardModal()}>Edit targets</Button>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={targetColumns}
            items={targets}
            className="tg-targets-table"
            getRowId={(item, index) => getString(item, ['id'], String(index))}
            getRowProps={(item) => targetRowNavProps(item)}
            empty={
              <EmptyState
                icon={Target}
                title="No targets declared yet"
                body="Declare a domain, IP, or cloud inventory selection to start validating this group. Nothing runs until a target is verified."
                actionLabel="+ Add Target"
                onAction={() => openOnboardModal()}
              />
            }
          />
        </CardContent>
      </Card>

      {/* (6) Findings on this group — Target column deep-links target detail. */}
      <Card>
        <CardHeader><CardTitle>Findings on this group</CardTitle></CardHeader>
        <CardContent>
          <DataTable columns={findingColumns} items={relatedFindings} empty={emptyStateFromApi({ icon: TriangleAlert, meta: groupMeta ? { empty_reason: getString(groupMeta, ['findings_empty_reason'], '') } : null })} />
        </CardContent>
      </Card>

      {/* (7) Recent runs — 6-column run history. */}
      <Card>
        <CardHeader><CardTitle>Recent runs</CardTitle></CardHeader>
        <CardContent>
          <DataTable columns={runColumns} items={relatedRuns} empty={emptyStateFromApi({ icon: Activity, meta: groupMeta ? { empty_reason: getString(groupMeta, ['runs_empty_reason'], '') } : null, actionHref: '#runs', actionLabel: 'Open test runs' })} />
        </CardContent>
      </Card>

      {inventoryProvider ? (
        <DetailModal title={`Provider inventory · ${inventoryProvider}`} onClose={() => setInventoryProvider(null)}>
            <div className="inv-body">
              <DataTable
                columns={[
                  { key: 'select', label: 'Select', render: (item) => {
                    const id = getString(item, ['id', 'value'], '');
                    const label = getString(item, ['value', 'name'], id);
                    return (
                      <input
                        type="checkbox"
                        checked={selectedInventory.has(id)}
                        aria-label={`Select ${label}`}
                        onChange={(event) => {
                      setSelectedInventory((current) => {
                        const next = new Set(current);
                        if (event.target.checked) next.add(id);
                        else next.delete(id);
                        return next;
                      });
                    }}
                      />
                    );
                  } },
                  { key: 'kind', label: 'Kind', render: (item) => getString(item, ['kind'], '—') },
                  { key: 'value', label: 'Value', render: (item) => getString(item, ['value', 'name'], '—') }
                ]}
                items={inventoryRows}
                empty={emptyStateFromApi({ icon: Bot, meta: inventoryMeta })}
              />
              <div className="row-actions">
                <Button size="sm" disabled={selectedInventory.size === 0 || busy !== ''} loading={busy.startsWith('import-')} onClick={() => void importInventory()}>Import selected</Button>
              </div>
            </div>
        </DetailModal>
      ) : null}

      {showOnboardModal ? (
        <DetailModal title="Onboard a target" onClose={() => setShowOnboardModal(false)}>
          <Tabs
            value={onboardTab}
            options={ONBOARD_TAB_OPTIONS}
            onChange={(value) => setOnboardTab(value)}
            ariaLabel="Target onboarding method"
          />
          {onboardTab === 'fqdn' ? (
            <div className="stack-tight">
              <p className="muted">Prove you control the domain by publishing a one-time TXT record. Verification is required before any probe runs.</p>
              <form className="product-form" onSubmit={submitFqdnTarget}>
                <label className="full"><span>Domain</span><input name="value" className="mono" placeholder="origin.example.com" required /></label>
                <label>
                  <span>Expected behavior</span>
                  <select name="expected_behavior" defaultValue="block_at_edge">
                    <option value="block_at_edge">block_at_edge</option>
                    <option value="absorb_at_origin">absorb_at_origin</option>
                    <option value="rate_shape">rate_shape</option>
                  </select>
                </label>
                <label>
                  <span>Bind to agent (optional)</span>
                  <select name="agent_id" defaultValue="">
                    <option value="">any agent in {getString(entity, ['environment_id'], 'this environment')}</option>
                    {agents.map((agent) => {
                      const optId = getString(agent, ['id'], '');
                      return <option key={optId} value={optId}>{optId} · {getString(agent, ['hostname', 'name'], optId)}</option>;
                    })}
                  </select>
                </label>
                <div className="form-actions full">
                  <Button type="submit" loading={busy === 'add-target-fqdn'}>Add target</Button>
                  <Button type="button" variant="secondary" loading={busy === `dns-issue-${entityId}`} onClick={() => void issueDnsChallenge()}>Issue DNS challenge</Button>
                </div>
              </form>
              <div className="dns-challenge">
                <div className="dns-head">
                  <span className="eyebrow">Challenge state</span>
                  <span className="spacer" />
                  <VerifyChip
                    state={displayedDnsChipState}
                    provenance={dnsProvenance}
                  />
                </div>
                <div className="dns-fields">
                  <div className="dns-field"><span className="dns-key">Name</span><span className="dns-val mono">{getString(activeChallenge, ['record_name', 'name'], '—')}</span></div>
                  <div className="dns-field"><span className="dns-key">Value</span><span className="dns-val mono">{getString(activeChallenge, ['record_value', 'value'], '—')}</span></div>
                  <div className="dns-field"><span className="dns-key">TTL</span><span className="dns-val mono">{getString(activeChallenge, ['ttl_seconds', 'ttl'], '—')}</span></div>
                </div>
                <div className="dns-footer row-actions">
                  <Button size="sm" variant="ghost" loading={busy === `dns-verify-${entityId}`} disabled={!activeChallengeId} onClick={() => void verifyDnsChallenge()}>Check now</Button>
                  {dnsVerifyResult?.verified === false ? <span className="muted small">Last checked {formatDate(dnsVerifyResult.checked_at ?? dnsVerifyResult.updated_at)}</span> : null}
                </div>
              </div>
            </div>
          ) : null}
          {onboardTab === 'ip' ? (
            <div className="stack-tight">
              <p className="muted">You cannot prove control of an IP with DNS. Install an agent inside that instance. When the agent registers, its outbound call reveals the public IP and binds the target to a verified agent.</p>
              <form className="product-form" onSubmit={submitIpTarget}>
                <label><span>IP address</span><input name="value" className="mono" placeholder="203.0.113.10" required /></label>
                <label><span>Protocol / port</span><input name="port" className="mono" placeholder="443" /></label>
                <label>
                  <span>Expected behavior</span>
                  <select name="expected_behavior" defaultValue="absorb_at_origin">
                    <option value="absorb_at_origin">absorb_at_origin</option>
                    <option value="block_at_edge">block_at_edge</option>
                    <option value="rate_shape">rate_shape</option>
                  </select>
                </label>
                <label className="full"><span>Notes (optional)</span><input name="notes" placeholder="Origin behind CDN · single-AZ · IPv4 only" /></label>
                <div className="form-actions full">
                  <Button type="submit" loading={busy === 'add-target-ip'}>Register &amp; wait for agent</Button>
                  <AnchorButton size="sm" variant="secondary" href="#agents">Open agent install</AnchorButton>
                </div>
              </form>
              <div className="dns-challenge">
                <div className="dns-head">
                  <span className="eyebrow">Agent callback</span>
                  <span className="spacer" />
                  <VerifyChip state="awaiting_heartbeat" provenance="Awaiting agent heartbeat from this IP" />
                </div>
                <ol className="muted small">
                  <li>Install an agent on any host that can reach the target IP (container image, Helm chart, or native package from the Agents screen).</li>
                  <li>Bind it at deploy time with <span className="mono">ASTRANULL_TARGET_GROUP={entityId}</span>. No inbound port needed.</li>
                  <li>When the agent heartbeats, AstraNull records its <span className="mono">discovered_public_ip</span> and matches it against the IP you registered.</li>
                  <li>Verified after a probe + agent correlation on the same nonce.</li>
                </ol>
              </div>
            </div>
          ) : null}
          {onboardTab === 'cloud' ? (
            <div className="stack-tight">
              <p className="muted">Connect a provider once, then pick which zones or instances belong in this target group. AstraNull normalizes the inventory and files a DNS or agent challenge for each selection.</p>
              {connectors.length === 0 ? emptyStateFromApi({ icon: Bot, meta: connectorsMeta }) : null}
              <div className="provider-grid">
                {connectors.map((connector) => {
                  const connectorId = getString(connector, ['id'], '');
                  const providerLabel = getString(connector, ['name', 'provider'], connectorId);
                  const scope = getString(connector, ['scope', 'config_json.scope'], getString(connector.config_json as DataItem | undefined, ['scope'], '—'));
                  return (
                    <div className="provider-card" key={connectorId}>
                      <div className="pc-head">
                        <span className="pc-mark">{providerLabel.slice(0, 2).toUpperCase()}</span>
                        <h3>{providerLabel}</h3>
                      </div>
                      <p>Scope required: <span className="mono">{scope}</span></p>
                      <p className="muted small">Status: {getString(connector, ['status', 'state'], 'unknown')}</p>
                      <div className="pc-actions">
                        <Button size="sm" variant="ghost" loading={busy === `inventory-${connectorId}`} onClick={() => void openInventory(connectorId)}>Open inventory</Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : null}
        </DetailModal>
      ) : null}

      {showLoaModal ? (
        <DetailModal title={`Sign LOA · ${getString(entity, ['name'], entityId)}`} onClose={() => setShowLoaModal(false)}>
            <form className="loa-body product-form" onSubmit={(event) => void submitLoa(event)}>
              <div className="loa-doc">
                <h4>Authorization artifact</h4>
                <dl className="loa-meta">
                  <dt>Customer</dt><dd>{getString(data.tenant, ['name', 'display_name'], session.tenant_id ?? '—')}</dd>
                  <dt>Tenant</dt><dd className="mono">{session.tenant_id ?? getString(data.state, ['tenant_id'], '—')}</dd>
                  <dt>Target group</dt><dd>{getString(entity, ['name'], entityId)}</dd>
                </dl>
              </div>
              <label className="checkrow full"><input type="checkbox" name="attested" /><span>I attest that declared targets in scope are authorized for bounded validation.</span></label>
              <label><span>Signer name</span><input name="signer_name" required /></label>
              <label><span>Signer title</span><input name="signer_title" required /></label>
              <label><span>Signed date</span><input name="signed_date" type="date" required /></label>
              <div className="form-actions"><Button type="submit" loading={busy === `loa-${entityId}`}>Sign LOA</Button></div>
            </form>
        </DetailModal>
      ) : null}
    </div>
  );
}
