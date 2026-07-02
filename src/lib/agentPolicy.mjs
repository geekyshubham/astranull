import { verifySecretWithSalt } from './crypto.mjs';

export function extractAgentCredential(headers) {
  const auth = headers.authorization ?? headers.Authorization;
  if (typeof auth === 'string' && auth.toLowerCase().startsWith('bearer ')) {
    return auth.slice(7).trim();
  }
  const headerCred = headers['x-agent-credential'] ?? headers['X-Agent-Credential'];
  return typeof headerCred === 'string' ? headerCred.trim() : null;
}

export function verifyAgentCredential(agent, credential) {
  if (!agent?.credential_hash || !agent?.credential_salt) return false;
  return verifySecretWithSalt(credential, agent.credential_salt, agent.credential_hash);
}

export function extractGatewayMtlsFingerprint(headers) {
  const direct =
    headers['x-client-cert-fingerprint']
    ?? headers['X-Client-Cert-Fingerprint']
    ?? headers['x-astranull-client-cert-fingerprint']
    ?? headers['X-Astranull-Client-Cert-Fingerprint'];
  if (typeof direct === 'string' && direct.trim()) return direct.trim();
  const forwarded =
    headers['x-forwarded-client-cert-sha256'] ?? headers['X-Forwarded-Client-Cert-Sha256'];
  return typeof forwarded === 'string' && forwarded.trim() ? forwarded.trim() : null;
}

export function normalizeCertificateFingerprint(value) {
  if (typeof value !== 'string') return '';
  return value
    .trim()
    .toLowerCase()
    .replace(/^sha256[:=]/, '')
    .replace(/[^a-f0-9]/g, '');
}

export function verifyAgentStrongIdentity(agent, headers, runtimeConfig = {}) {
  if (runtimeConfig.agentIdentityMode !== 'gateway-mtls') {
    return { ok: true };
  }
  const expected = normalizeCertificateFingerprint(agent?.fingerprint);
  const actual = normalizeCertificateFingerprint(extractGatewayMtlsFingerprint(headers));
  if (!expected) return { ok: false, reason: 'strong_identity_not_registered' };
  if (!actual) return { ok: false, reason: 'strong_identity_missing' };
  if (expected !== actual) return { ok: false, reason: 'strong_identity_mismatch' };
  return { ok: true };
}

export function redactAgent(agent) {
  if (!agent) return agent;
  const { credential_hash, credential_salt, ...rest } = agent;
  return rest;
}
