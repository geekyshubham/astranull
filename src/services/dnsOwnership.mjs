import { audit } from '../audit.mjs';
import { generateNonce } from '../lib/crypto.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';

function findActiveTargetGroup(ctx, targetGroupId) {
  return (
    getStore().targetGroups.find(
      (g) =>
        g.id === targetGroupId
        && g.tenant_id === ctx.tenantId
        && !g.archived_at,
    ) ?? null
  );
}

function firstFqdnDomain(ctx, targetGroupId) {
  const target = getStore().targets.find(
    (t) =>
      t.target_group_id === targetGroupId
      && t.tenant_id === ctx.tenantId
      && t.kind === 'fqdn',
  );
  if (!target?.value) return null;
  return String(target.value).trim().toLowerCase();
}

function flattenTxtRecords(records) {
  if (!Array.isArray(records)) return [];
  const out = [];
  for (const entry of records) {
    if (Array.isArray(entry)) {
      for (const chunk of entry) out.push(String(chunk));
    } else {
      out.push(String(entry));
    }
  }
  return out;
}

export function issueDnsOwnershipChallenge(ctx, { target_group_id }) {
  const group = findActiveTargetGroup(ctx, target_group_id);
  if (!group) return { error: 'target_group_not_found', status: 404 };

  const domain = firstFqdnDomain(ctx, target_group_id);
  if (!domain) return { error: 'no_fqdn_target', status: 409 };

  const token = `${newId('dnstxt')}_${generateNonce()}`;
  const issued_at = new Date().toISOString();
  group.dns_ownership = {
    token,
    record_name: `_astranull-challenge.${domain}`,
    record_value: token,
    status: 'pending',
    issued_at,
  };

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'dns_ownership.challenge_issued',
    resource_type: 'target_group',
    resource_id: target_group_id,
  });
  persistStore();

  return {
    target_group_id,
    record_name: group.dns_ownership.record_name,
    record_value: group.dns_ownership.record_value,
    status: 'pending',
  };
}

export async function verifyDnsOwnership(ctx, { target_group_id }, { resolveTxt } = {}) {
  const group = findActiveTargetGroup(ctx, target_group_id);
  if (!group) return { error: 'target_group_not_found', status: 404 };
  if (!group.dns_ownership) return { error: 'no_dns_challenge', status: 409 };

  let lookup;
  try {
    let resolveFn = resolveTxt;
    if (!resolveFn) {
      const dns = await import('node:dns/promises');
      resolveFn = dns.resolveTxt.bind(dns);
    }
    lookup = await resolveFn(group.dns_ownership.record_name);
  } catch {
    return { error: 'dns_lookup_failed', status: 502 };
  }

  const values = flattenTxtRecords(lookup);
  const matched = values.some((v) => v === group.dns_ownership.record_value);

  if (matched) {
    group.dns_ownership.status = 'verified';
    group.dns_ownership.verified_at = new Date().toISOString();
    group.ownership_status = 'dns_verified';
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'dns_ownership.verified',
      resource_type: 'target_group',
      resource_id: target_group_id,
    });
  } else {
    group.dns_ownership.status = 'failed';
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'dns_ownership.failed',
      resource_type: 'target_group',
      resource_id: target_group_id,
    });
  }

  persistStore();

  return {
    target_group_id,
    status: group.dns_ownership.status,
    ownership_status: group.ownership_status,
  };
}