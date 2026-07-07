import type { DataItem } from './types';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

export type VerifyChipState = {
  label: string;
  className: string;
  title: string;
};

export function resolveVerifyChipState(
  verificationState: string,
  provenance?: string
): VerifyChipState {
  const state = verificationState.trim().toLowerCase();
  const title = provenance?.trim() || `Verification state ${state || 'unverified'} from API.`;

  if (state === 'user_confirmed') {
    return { label: 'user_confirmed', className: 'verify-chip is-verified verify-chip--strong', title };
  }
  if (state === 'agent_verified') {
    return { label: 'agent_verified', className: 'verify-chip is-verified', title };
  }
  if (state === 'dns_verified') {
    return { label: 'dns_verified', className: 'verify-chip is-dns', title };
  }
  if (['pending', 'dns_pending', 'awaiting_heartbeat', 'pending_agent'].includes(state)) {
    return { label: state.replace(/_/g, ' '), className: 'verify-chip is-pending', title };
  }
  if (['checking', 'checking…', 'checking...'].includes(state)) {
    return { label: 'checking…', className: 'verify-chip is-checking', title };
  }
  if (state === 'unverified' || !state) {
    return { label: 'unverified', className: 'verify-chip is-unverified', title };
  }
  return { label: state.replace(/_/g, ' '), className: 'verify-chip is-partial', title };
}

export function resolveTargetVerificationProvenance(target: DataItem | null, verification: DataItem | null) {
  const sourceRef = verification?.source_ref;
  const sourceKind = getString(verification, ['source_kind'], '');
  const state = getString(verification, ['state'], getString(target, ['verification_state'], 'unverified'));
  if (sourceRef && typeof sourceRef === 'object' && !Array.isArray(sourceRef)) {
    const ref = sourceRef as DataItem;
    if (getString(ref, ['dns_challenge_id'])) {
      return `DNS TXT challenge ${getString(ref, ['dns_challenge_id'])} resolved per verification API.`;
    }
    if (getString(ref, ['agent_id'])) {
      return `Probe and agent correlated on ${getString(ref, ['agent_id'])} per verification API.`;
    }
    if (getString(ref, ['correlated_at'])) {
      return `Verification correlated at ${getString(ref, ['correlated_at'])} (${sourceKind || 'api'}).`;
    }
  }
  return `Verification state ${state} from target verification API.`;
}

export function VerifyChip({
  state,
  provenance,
  strong
}: {
  state: string;
  provenance?: string;
  strong?: boolean;
}) {
  const chip = resolveVerifyChipState(state, provenance);
  const className = strong ? `${chip.className} verify-chip--strong` : chip.className;
  return (
    <span className={className} title={chip.title}>
      <span className="vc-dot" aria-hidden="true" />
      {chip.label}
    </span>
  );
}