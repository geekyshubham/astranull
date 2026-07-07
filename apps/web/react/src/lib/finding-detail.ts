import { requestJson } from './api';
import type { DataItem, PortalConfig, Session } from './types';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

export function populateFindingAffectedTargets(findingId: string, targets: DataItem[]) {
  return targets.filter((target) => {
    const directTargetId = getString(target, ['target_id'], '');
    const findingIds = Array.isArray(target.finding_ids) ? target.finding_ids.map(String) : [];
    const linkedFindingId = getString(target, ['linked_finding_id'], '');
    return findingIds.includes(findingId) || linkedFindingId === findingId || directTargetId === findingId;
  });
}

export function readFindingRemediationFields(finding: DataItem, actionItems: DataItem[] = []) {
  const findingId = getString(finding, ['id'], '');
  const linkedAction = actionItems.find((item) => getString(item, ['finding_id'], '') === findingId);
  const remediation = finding.remediation && typeof finding.remediation === 'object' && !Array.isArray(finding.remediation)
    ? finding.remediation as DataItem
    : null;

  return {
    remAction: getString(finding, ['rem_action', 'remAction'], getString(remediation ?? linkedAction ?? {}, ['action', 'rem_action'], '')),
    remOwner: getString(finding, ['rem_owner', 'remOwner', 'assignee'], getString(remediation ?? linkedAction ?? {}, ['owner', 'rem_owner'], '')),
    remState: getString(finding, ['rem_state', 'remState', 'status'], getString(remediation ?? linkedAction ?? {}, ['state', 'status'], '')),
    remStateClass: getString(finding, ['rem_state_class', 'remStateClass'], getString(remediation ?? linkedAction ?? {}, ['state_class'], '')),
    remSla: getString(finding, ['rem_sla', 'remSla', 'sla'], getString(remediation ?? linkedAction ?? {}, ['sla'], '')),
    remDescription: getString(finding, ['rem_description', 'remDescription'], getString(remediation ?? linkedAction ?? {}, ['description', 'summary'], '')),
    remSteps: getString(finding, ['rem_steps', 'remSteps'], getString(remediation ?? linkedAction ?? {}, ['steps'], '')),
    actionItemId: getString(linkedAction ?? {}, ['id'], getString(finding, ['waf_action_item_id', 'action_item_id'], ''))
  };
}

export type FindingEvidencePayload = {
  finding: DataItem | null;
  bundle: DataItem | null;
  artifacts: DataItem[];
  custody_chain: DataItem[];
  verify_url: string;
  meta?: DataItem | null;
  error?: string;
};

export async function populateFindingEvidence(
  config: PortalConfig,
  session: Session,
  findingId: string
): Promise<FindingEvidencePayload> {
  try {
    const payload = await requestJson(config, session, `/v1/findings/${encodeURIComponent(findingId)}/evidence`) as DataItem;
    return {
      finding: payload.finding && typeof payload.finding === 'object' ? payload.finding as DataItem : null,
      bundle: payload.bundle && typeof payload.bundle === 'object' ? payload.bundle as DataItem : null,
      artifacts: Array.isArray(payload.artifacts) ? payload.artifacts as DataItem[] : [],
      custody_chain: Array.isArray(payload.custody_chain) ? payload.custody_chain as DataItem[] : [],
      verify_url: getString(payload, ['verify_url'], '/v1/custody/verify'),
      meta: payload.meta && typeof payload.meta === 'object' ? payload.meta as DataItem : null
    };
  } catch (err) {
    return {
      finding: null,
      bundle: null,
      artifacts: [],
      custody_chain: [],
      verify_url: '/v1/custody/verify',
      meta: { empty_reason: 'Evidence bundle not available for this finding.' },
      error: err instanceof Error ? err.message : 'Evidence request failed.'
    };
  }
}