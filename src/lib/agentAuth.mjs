import { audit } from '../audit.mjs';
import { parseAddressedSecret } from './addressedSecrets.mjs';
import { getStore, persistStore } from '../store.mjs';
import {
  extractAgentCredential,
  redactAgent,
  verifyAgentCredential,
  verifyAgentStrongIdentity,
} from './agentPolicy.mjs';

export {
  extractAgentCredential,
  redactAgent,
  verifyAgentCredential,
  verifyAgentStrongIdentity,
} from './agentPolicy.mjs';

function findAgentByTenantAndId(tenantId, agentId) {
  return getStore().agents.find((a) => a.id === agentId && a.tenant_id === tenantId);
}

function auditAgentAuthDenied(tenantId, resourceId, reason) {
  audit({
    tenant_id: tenantId,
    actor_user_id: 'unknown',
    actor_role: 'agent',
    action: 'agent.auth_denied',
    resource_type: 'agent',
    resource_id: resourceId,
    metadata: { reason },
  });
  persistStore();
}

function strongIdentityDenied(agent, headers, runtimeConfig) {
  const strong = verifyAgentStrongIdentity(agent, headers, runtimeConfig);
  if (strong.ok) return null;
  auditAgentAuthDenied(agent.tenant_id, agent.id, strong.reason);
  return { error: 'unauthorized', status: 401 };
}

function revokedDenied(agent) {
  if (agent.status !== 'revoked') return null;
  auditAgentAuthDenied(agent.tenant_id, agent.id, 'revoked');
  return { error: 'unauthorized', status: 401 };
}

export function requireAgentAuth(headers, agentId, runtimeConfig = {}) {
  const credential = extractAgentCredential(headers);
  const hints = credential ? parseAddressedSecret(credential, 'agc_') : null;

  if (hints) {
    const reason = credential ? 'invalid_credential' : 'missing_credential';
    if (hints.id !== agentId) {
      if (findAgentByTenantAndId(hints.tenantId, hints.id)) {
        auditAgentAuthDenied(hints.tenantId, hints.id, reason);
      }
      return { error: 'unauthorized', status: 401 };
    }
    const agent = findAgentByTenantAndId(hints.tenantId, hints.id);
    if (!agent || !verifyAgentCredential(agent, credential)) {
      if (agent) {
        auditAgentAuthDenied(hints.tenantId, hints.id, reason);
      }
      return { error: 'unauthorized', status: 401 };
    }
    const revoked = revokedDenied(agent);
    if (revoked) return revoked;
    const strongDenied = strongIdentityDenied(agent, headers, runtimeConfig);
    if (strongDenied) return strongDenied;
    return { agent, credential };
  }

  const agent = getStore().agents.find((a) => a.id === agentId);
  if (!agent) return { error: 'unauthorized', status: 401 };

  if (!credential || !verifyAgentCredential(agent, credential)) {
    auditAgentAuthDenied(agent.tenant_id, agentId, credential ? 'invalid_credential' : 'missing_credential');
    return { error: 'unauthorized', status: 401 };
  }

  const revoked = revokedDenied(agent);
  if (revoked) return revoked;

  const strongDenied = strongIdentityDenied(agent, headers, runtimeConfig);
  if (strongDenied) return strongDenied;

  return { agent, credential };
}
