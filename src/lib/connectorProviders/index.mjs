import { awsWafProvider } from './awsWaf.mjs';
import { cloudflareProvider } from './cloudflare.mjs';

const PROVIDERS = new Map([
  ['cloudflare', cloudflareProvider],
  ['aws_waf', awsWafProvider],
]);

export const OUTBOUND_POLL_PROVIDERS = new Set(['cloudflare', 'aws_waf']);

export function getConnectorProvider(provider) {
  const key = String(provider ?? '').trim().toLowerCase();
  return PROVIDERS.get(key) ?? null;
}

export function supportsOutboundProviderPoll(provider) {
  return OUTBOUND_POLL_PROVIDERS.has(String(provider ?? '').trim().toLowerCase());
}

export function listConnectorProviders() {
  return [...PROVIDERS.values()].map((entry) => ({
    provider: entry.provider,
    required_scopes: entry.required_scopes,
    snapshot_kinds: entry.snapshot_kinds,
    read_only: true,
  }));
}