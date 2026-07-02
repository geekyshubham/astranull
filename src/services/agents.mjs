import { audit } from '../audit.mjs';
import { redactAgent } from '../lib/agentAuth.mjs';
import { createAddressedSecret } from '../lib/addressedSecrets.mjs';
import { generateSalt, hashSecretWithSalt } from '../lib/crypto.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { consumeBootstrapToken } from './tokens.mjs';

export function registerAgent(body, tenantId) {
  const secret = body.bootstrap_token;
  if (!secret) return { error: 'missing_token', status: 400 };
  const consumed = consumeBootstrapToken(
    secret,
    { hostname: body.hostname, fingerprint: body.fingerprint },
    tenantId,
  );
  if (consumed.error) {
    return { error: consumed.error, status: 401 };
  }
  const token = consumed.token;
  const id = newId('agent');
  const agentCredential = createAddressedSecret('agc_', token.tenant_id, id);
  const credentialSalt = generateSalt();
  const agent = {
    id,
    tenant_id: token.tenant_id,
    name: body.name ?? body.hostname ?? 'agent',
    hostname: body.hostname ?? 'unknown',
    fingerprint: body.fingerprint ?? null,
    target_group_id: token.target_group_id,
    environment_id: token.environment_id,
    status: 'online',
    capabilities: body.capabilities ?? ['heartbeat', 'canary'],
    last_heartbeat_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    bootstrap_token_id: token.id,
    credential_salt: credentialSalt,
    credential_hash: hashSecretWithSalt(agentCredential, credentialSalt),
  };
  getStore().agents.push(agent);
  audit({
    tenant_id: agent.tenant_id,
    actor_user_id: 'agent',
    actor_role: 'agent',
    action: 'agent.registered',
    resource_type: 'agent',
    resource_id: id,
  });
  persistStore();
  return { agent: redactAgent(agent), agent_credential: agentCredential };
}

export function listAgents(ctx) {
  return getStore()
    .agents.filter((a) => a.tenant_id === ctx.tenantId)
    .map(redactAgent);
}

export function revokeAgent(ctx, id) {
  const agent = getStore().agents.find((a) => a.id === id && a.tenant_id === ctx.tenantId);
  if (!agent) return null;
  agent.status = 'revoked';
  agent.revoked_at = new Date().toISOString();
  audit({
    tenant_id: agent.tenant_id,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'agent.revoked',
    resource_type: 'agent',
    resource_id: id,
  });
  persistStore();
  return { agent: redactAgent(agent) };
}

export function heartbeatAgent(agent, body) {
  agent.last_heartbeat_at = new Date().toISOString();
  agent.status = 'online';
  if (body.version) agent.version = body.version;
  audit({
    tenant_id: agent.tenant_id,
    actor_user_id: 'agent',
    actor_role: 'agent',
    action: 'agent.heartbeat',
    resource_type: 'agent',
    resource_id: agent.id,
    metadata: { version: body.version },
  });
  persistStore();
  return { agent: redactAgent(agent) };
}

export function pollJobs(agent, timeoutMs = 25_000) {
  const store = getStore();
  const pending = store.agentJobs.filter(
    (j) => j.agent_id === agent.id && j.status === 'pending',
  );

  if (pending.length > 0) {
    return Promise.resolve({ jobs: pending });
  }

  return new Promise((resolve) => {
    const start = Date.now();
    const tick = () => {
      const jobs = getStore().agentJobs.filter(
        (j) => j.agent_id === agent.id && j.status === 'pending',
      );
      if (jobs.length > 0) {
        resolve({ jobs });
        return;
      }
      if (Date.now() - start >= timeoutMs) {
        resolve({ jobs: [] });
        return;
      }
      setTimeout(tick, 500);
    };
    setTimeout(tick, 500);
  });
}

export function ackJob(agent, jobId) {
  const job = getStore().agentJobs.find(
    (j) => j.id === jobId && j.agent_id === agent.id && j.tenant_id === agent.tenant_id,
  );
  if (!job) return null;
  job.status = 'acked';
  job.acked_at = new Date().toISOString();
  audit({
    tenant_id: agent.tenant_id,
    actor_user_id: 'agent',
    actor_role: 'agent',
    action: 'agent.job_acked',
    resource_type: 'agent_job',
    resource_id: jobId,
  });
  persistStore();
  return job;
}

export { pollAgentUpdate, recordAgentUpdateStatus } from './agentUpdates.mjs';

export function enqueueAgentJob({ tenantId, agentId, testRunId, checkId, targetId, nonce_hash, nonce }) {
  const job = {
    id: newId('job'),
    tenant_id: tenantId,
    agent_id: agentId,
    test_run_id: testRunId,
    check_id: checkId,
    target_id: targetId,
    nonce_hash,
    nonce_for_agent: nonce,
    type: 'observe_window',
    status: 'pending',
    created_at: new Date().toISOString(),
  };
  getStore().agentJobs.push(job);
  persistStore();
  return job;
}
