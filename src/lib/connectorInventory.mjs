/**
 * Maps provider-specific inventory payloads to the common InventoryItem shape (§3.5).
 */

const SECRET_PATTERNS = [
  /api[_-]?token/i,
  /secret[_-]?access[_-]?key/i,
  /password/i,
  /bearer\s+[a-z0-9._~+/=-]+/i,
  /sk_live_/i,
  /AKIA[0-9A-Z]{16}/,
];

function assertNoSecrets(value) {
  const text = JSON.stringify(value);
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(text)) {
      throw new Error('connector_inventory_contains_secret');
    }
  }
}

function normalizeItem(entry) {
  const kind = String(entry.kind ?? entry.type ?? 'fqdn').trim().toLowerCase();
  const value = String(entry.value ?? entry.name ?? entry.hostname ?? '').trim();
  if (!value) return null;
  return {
    kind: kind === 'zone' ? 'fqdn' : kind,
    value,
    label: entry.label ?? entry.display_name ?? value,
    resource_ref: entry.resource_ref ?? entry.id ?? null,
    importable: entry.importable !== false,
  };
}

export function mapCloudflareInventory(raw) {
  const zones = raw?.result ?? raw?.zones ?? raw ?? [];
  const items = [];
  for (const zone of zones) {
    const name = zone?.name ?? zone?.zone ?? null;
    if (!name) continue;
    items.push({
      kind: 'fqdn',
      value: String(name).trim().toLowerCase(),
      label: zone?.name ?? name,
      resource_ref: zone?.id ?? `cloudflare:zone:${name}`,
      importable: zone?.status !== 'inactive',
    });
  }
  return items;
}

export function mapRoute53Inventory(raw) {
  const zones = raw?.HostedZones ?? raw?.zones ?? [];
  return zones.map((zone) => ({
    kind: 'fqdn',
    value: String(zone.Name ?? '').replace(/\.$/, '').toLowerCase(),
    label: zone.Name ?? zone.Id,
    resource_ref: zone.Id ?? null,
    importable: true,
  })).filter((item) => item.value);
}

export function mapGodaddyInventory(raw) {
  const domains = raw?.domains ?? raw ?? [];
  return domains.map((domain) => ({
    kind: 'fqdn',
    value: String(domain.domain ?? domain).trim().toLowerCase(),
    label: domain.domain ?? String(domain),
    resource_ref: domain.domainId ?? domain.domain ?? null,
    importable: true,
  })).filter((item) => item.value);
}

export function mapNamecheapInventory(raw) {
  const domains = raw?.domains ?? raw?.DomainGetListResult?.Domain ?? [];
  const list = Array.isArray(domains) ? domains : [domains];
  return list.map((domain) => ({
    kind: 'fqdn',
    value: String(domain.Name ?? domain.name ?? domain).trim().toLowerCase(),
    label: domain.Name ?? domain.name ?? String(domain),
    resource_ref: domain.ID ?? domain.id ?? null,
    importable: true,
  })).filter((item) => item.value);
}

export function mapAwsInventory(raw) {
  const items = [];
  for (const lb of raw?.LoadBalancers ?? raw?.load_balancers ?? []) {
    const dns = lb.DNSName ?? lb.dns_name;
    if (dns) {
      items.push({
        kind: 'fqdn',
        value: String(dns).trim().toLowerCase(),
        label: lb.LoadBalancerName ?? dns,
        resource_ref: lb.LoadBalancerArn ?? lb.arn ?? null,
        importable: true,
      });
    }
  }
  for (const ip of raw?.PublicIps ?? raw?.ips ?? []) {
    items.push({
      kind: 'ip',
      value: String(ip.PublicIp ?? ip).trim(),
      label: ip.PublicIp ?? String(ip),
      resource_ref: ip.AllocationId ?? ip,
      importable: true,
    });
  }
  return items;
}

export function mapGcpInventory(raw) {
  const items = [];
  for (const addr of raw?.addresses ?? raw?.items ?? []) {
    items.push({
      kind: addr.kind === 'ip' ? 'ip' : 'fqdn',
      value: String(addr.value ?? addr.address ?? addr.name).trim().toLowerCase(),
      label: addr.name ?? addr.value,
      resource_ref: addr.selfLink ?? addr.id ?? null,
      importable: true,
    });
  }
  return items.filter((item) => item.value);
}

export function mapAzureInventory(raw) {
  const items = [];
  for (const entry of raw?.value ?? raw?.items ?? []) {
    const fqdn = entry?.properties?.fqdn ?? entry?.fqdn ?? entry?.name;
    if (!fqdn) continue;
    items.push({
      kind: 'fqdn',
      value: String(fqdn).trim().toLowerCase(),
      label: entry.name ?? fqdn,
      resource_ref: entry.id ?? null,
      importable: entry.properties?.provisioningState !== 'Failed',
    });
  }
  return items;
}

const PROVIDER_MAPPERS = Object.freeze({
  cloudflare: mapCloudflareInventory,
  route53: mapRoute53Inventory,
  godaddy: mapGodaddyInventory,
  namecheap: mapNamecheapInventory,
  aws: mapAwsInventory,
  aws_waf: mapAwsInventory,
  gcp: mapGcpInventory,
  azure: mapAzureInventory,
});

/**
 * @param {string} provider
 * @param {unknown} raw
 */
export function mapProviderInventory(provider, raw) {
  const key = String(provider ?? '').trim().toLowerCase();
  const mapper = PROVIDER_MAPPERS[key];
  if (!mapper) return [];
  const mapped = mapper(raw).map(normalizeItem).filter(Boolean);
  assertNoSecrets(mapped);
  return mapped;
}

export function listProviderInventoryMappers() {
  return Object.keys(PROVIDER_MAPPERS);
}