import { createAddressedSecret, parseAddressedSecret } from '../../lib/addressedSecrets.mjs';
import {
  extractAgentCredential,
  redactAgent,
  verifyAgentCredential,
  verifyAgentStrongIdentity,
} from '../../lib/agentPolicy.mjs';
import { generateSalt, hashSecretWithSalt } from '../../lib/crypto.mjs';
import { newId } from '../../lib/ids.mjs';
import { checkProbeEndpointBinding, validateProbeEndpoint } from '../../lib/probeEndpoint.mjs';

/** @type {readonly string[]} */
export const AGENT_CONTROL_REPOSITORY_METHODS = Object.freeze([
  'createAgent',
  'listAgents',
  'findAgentByAddressedHint',
  'updateAgentHeartbeat',
  'createAgentJob',
  'listPendingAgentJobs',
  'ackAgentJob',
  'revokeAgent',
]);

/** @type {readonly string[]} */
export const AGENT_AUDIT_REPOSITORY_METHODS = Object.freeze(['appendAuditEvent']);

/** @type {readonly string[]} */
export const POSTGRES_AGENT_SERVICE_METHODS = Object.freeze([
  'registerAgent',
  'listAgents',
  'heartbeatAgent',
  'pollJobs',
  'ackJob',
  'revokeAgent',
]);

/** @type {readonly string[]} */
export const POSTGRES_AGENT_AUTH_SERVICE_METHODS = Object.freeze(['requireAgentAuth']);

function assertAgentServiceDependencies(repositories, tokens) {
  const agentControl = repositories?.agentControl;
  if (!agentControl || typeof agentControl !== 'object') {
    throw new Error('Postgres agent service adapter requires repositories.agentControl.');
  }
  for (const method of AGENT_CONTROL_REPOSITORY_METHODS) {
    if (typeof agentControl[method] !== 'function') {
      throw new Error(`Postgres agent service adapter requires agentControl.${method}().`);
    }
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit !== 'object') {
    throw new Error('Postgres agent service adapter requires repositories.audit.');
  }
  for (const method of AGENT_AUDIT_REPOSITORY_METHODS) {
    if (typeof audit[method] !== 'function') {
      throw new Error(`Postgres agent service adapter requires audit.${method}().`);
    }
  }

  if (!tokens || typeof tokens.consumeBootstrapToken !== 'function') {
    throw new Error('Postgres agent service adapter requires tokens.consumeBootstrapToken().');
  }
}

/**
 * @param {{
 *   agentControl?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 *   authTokens?: { getBootstrapTokenById?: (...args: unknown[]) => unknown },
 *   coreCatalog?: { getTargetGroup?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{
 *   tokens?: { consumeBootstrapToken?: (...args: unknown[]) => unknown },
 *   now?: () => Date,
 *   newId?: typeof newId,
 * }} [options]
 */
export function createPostgresAgentServices(repositories, options = {}) {
  const tokens = options.tokens;
  assertAgentServiceDependencies(repositories, tokens);
  const agentControl = repositories.agentControl;
  const audit = repositories.audit;
  const authTokens = repositories.authTokens;
  const coreCatalog = repositories.coreCatalog;

  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  async function appendAudit(entry) {
    await audit.appendAuditEvent(entry, { now: nowFn() });
  }

  async function auditAgentAuthDenied(tenantId, resourceId, reason) {
    await appendAudit({
      tenant_id: tenantId,
      actor_user_id: 'unknown',
      actor_role: 'agent',
      action: 'agent.auth_denied',
      resource_type: 'agent',
      resource_id: resourceId,
      metadata: { reason },
    });
  }

  const agents = {
    async registerAgent(body, tenantId) {
      const secret = body?.bootstrap_token;
      if (!secret) {
        return { error: 'missing_token', status: 400 };
      }
      const consumed = await tokens.consumeBootstrapToken(
        secret,
        { hostname: body.hostname, fingerprint: body.fingerprint },
        tenantId,
      );
      if (consumed?.error) {
        return { error: consumed.error, status: 401 };
      }
      const token = consumed.token;
      const id = newIdFn('agent');
      const agentCredential = createAddressedSecret('agc_', token.tenant_id, id);
      const credentialSalt = generateSalt();
      const createdAt = nowFn().toISOString();
      const record = {
        id,
        tenant_id: token.tenant_id,
        name: body.name ?? body.hostname ?? 'agent',
        hostname: body.hostname ?? 'unknown',
        fingerprint: body.fingerprint ?? null,
        target_group_id: token.target_group_id,
        environment_id: token.environment_id,
        status: 'online',
        capabilities: body.capabilities ?? ['heartbeat', 'canary'],
        last_heartbeat_at: createdAt,
        created_at: createdAt,
        bootstrap_token_id: token.id,
        credential_salt: credentialSalt,
        credential_hash: hashSecretWithSalt(agentCredential, credentialSalt),
      };
      const agent = await agentControl.createAgent(record);
      await appendAudit({
        tenant_id: agent.tenant_id,
        actor_user_id: 'agent',
        actor_role: 'agent',
        action: 'agent.registered',
        resource_type: 'agent',
        resource_id: id,
      });
      return { agent: redactAgent(agent), agent_credential: agentCredential };
    },

    async listAgents(ctx) {
      const rows = await agentControl.listAgents(ctx);
      return rows.map(redactAgent);
    },

    async heartbeatAgent(agent, body) {
      const lastHeartbeatAt = nowFn().toISOString();
      const lastTokenValidationAt = lastHeartbeatAt;
      const lastTokenValidationStatus = 'valid';

      let probeEndpointAccepted = false;
      const heartbeatFields = {
        version: body?.version,
        capabilities: body?.capabilities,
        last_heartbeat_at: lastHeartbeatAt,
        last_token_validation_at: lastTokenValidationAt,
        last_token_validation_status: lastTokenValidationStatus,
      };

      if (body?.probe_endpoint !== undefined) {
        const result = validateProbeEndpoint(body.probe_endpoint);
        if (result.ok) {
          let prebindFqdn = null;
          let targetGroupFqdns = [];

          if (
            authTokens
            && typeof authTokens.getBootstrapTokenById === 'function'
            && agent.bootstrap_token_id
          ) {
            const token = await authTokens.getBootstrapTokenById(
              { tenantId: agent.tenant_id },
              agent.bootstrap_token_id,
            );
            prebindFqdn = token?.prebind_fqdn ?? null;
          }

          if (
            coreCatalog
            && typeof coreCatalog.getTargetGroup === 'function'
            && agent.target_group_id
          ) {
            const targetGroup = await coreCatalog.getTargetGroup(
              { tenantId: agent.tenant_id },
              agent.target_group_id,
            );
            targetGroupFqdns = (targetGroup?.targets ?? [])
              .filter((t) => t.kind === 'fqdn')
              .map((t) => String(t.value).trim().toLowerCase());
          }

          const binding = checkProbeEndpointBinding(result.normalized, {
            prebindFqdn,
            targetGroupFqdns,
          });
          if (!binding.ok) {
            heartbeatFields.probe_endpoint_status = 'rejected';
            heartbeatFields.probe_endpoint_error = binding.error;
            probeEndpointAccepted = false;
          } else {
            heartbeatFields.probe_endpoint = result.normalized;
            heartbeatFields.probe_endpoint_status = 'reported';
            heartbeatFields.probe_endpoint_error = null;
            probeEndpointAccepted = true;
          }
        } else {
          heartbeatFields.probe_endpoint_status = 'rejected';
          heartbeatFields.probe_endpoint_error = result.error;
          probeEndpointAccepted = false;
        }
      }

      const updated = await agentControl.updateAgentHeartbeat(
        { tenantId: agent.tenant_id, id: agent.id },
        heartbeatFields,
      );
      await appendAudit({
        tenant_id: agent.tenant_id,
        actor_user_id: 'agent',
        actor_role: 'agent',
        action: 'agent.heartbeat',
        resource_type: 'agent',
        resource_id: agent.id,
        metadata: {
          version: body?.version,
          token_valid: true,
          probe_endpoint_accepted: probeEndpointAccepted,
        },
      });
      return { agent: redactAgent(updated), probe_endpoint_accepted: probeEndpointAccepted };
    },

    async pollJobs(agent, _timeoutMs = 25_000) {
      const jobs = await agentControl.listPendingAgentJobs({
        tenantId: agent.tenant_id,
        agentId: agent.id,
      });
      return { jobs };
    },

    async ackJob(agent, jobId) {
      const ackedAt = nowFn().toISOString();
      const job = await agentControl.ackAgentJob(
        { tenantId: agent.tenant_id, agentId: agent.id, jobId },
        ackedAt,
      );
      if (!job) return null;
      await appendAudit({
        tenant_id: agent.tenant_id,
        actor_user_id: 'agent',
        actor_role: 'agent',
        action: 'agent.job_acked',
        resource_type: 'agent_job',
        resource_id: jobId,
      });
      return job;
    },

    async revokeAgent(ctx, id) {
      const revokedAt = nowFn().toISOString();
      const agent = await agentControl.revokeAgent(ctx, id, revokedAt);
      if (!agent) return null;
      await appendAudit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'agent.revoked',
        resource_type: 'agent',
        resource_id: id,
      });
      return { agent: redactAgent(agent) };
    },
  };

  const agentAuth = {
    async requireAgentAuth(headers, agentId, runtimeConfig = {}) {
      const credential = extractAgentCredential(headers);
      const hints = credential ? parseAddressedSecret(credential, 'agc_') : null;

      if (!hints) {
        return { error: 'unauthorized', status: 401 };
      }

      const reason = credential ? 'invalid_credential' : 'missing_credential';

      if (hints.id !== agentId) {
        const hintedAgent = await agentControl.findAgentByAddressedHint({
          tenantId: hints.tenantId,
          id: hints.id,
        });
        if (hintedAgent) {
          await auditAgentAuthDenied(hints.tenantId, hints.id, reason);
        }
        return { error: 'unauthorized', status: 401 };
      }

      const agent = await agentControl.findAgentByAddressedHint({
        tenantId: hints.tenantId,
        id: hints.id,
      });
      if (!agent || !verifyAgentCredential(agent, credential)) {
        if (agent) {
          await auditAgentAuthDenied(hints.tenantId, hints.id, reason);
        }
        return { error: 'unauthorized', status: 401 };
      }

      if (agent.status === 'revoked') {
        await auditAgentAuthDenied(hints.tenantId, hints.id, 'revoked');
        return { error: 'unauthorized', status: 401 };
      }

      const strong = verifyAgentStrongIdentity(agent, headers, runtimeConfig);
      if (!strong.ok) {
        await auditAgentAuthDenied(hints.tenantId, hints.id, strong.reason);
        return { error: 'unauthorized', status: 401 };
      }

      return { agent, credential };
    },
  };

  return { agents, agentAuth };
}
