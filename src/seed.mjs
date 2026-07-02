import { CHECK_CATALOG } from './contracts/checks.mjs';
import { getStore, migrateDevStore, persistStore } from './store.mjs';

export function seedIfEmpty() {
  const store = getStore();
  if (migrateDevStore(store)) {
    persistStore();
  }
  if (store.tenants.length > 0) return;

  const tenantId = 'ten_demo';
  const envId = 'env_demo';
  store.tenants.push({
    id: tenantId,
    name: 'Demo Organization',
    created_at: new Date().toISOString(),
    privacy_settings: {
      store_packet_payloads: false,
      metadata_retention_days: 90,
      redact_headers_by_default: true,
    },
  });
  store.environments.push({
    id: envId,
    tenant_id: tenantId,
    name: 'Production Validation',
    created_at: new Date().toISOString(),
  });
  store.users.push({
    id: 'usr_admin',
    tenant_id: tenantId,
    email: 'admin@demo.astranull.local',
    role: 'admin',
    name: 'Demo Admin',
  });
  store.users.push({
    id: 'usr_soc',
    tenant_id: tenantId,
    email: 'soc@demo.astranull.local',
    role: 'soc',
    name: 'Demo SOC',
  });

  const tgId = 'tg_demo_origin';
  store.targetGroups.push({
    id: tgId,
    tenant_id: tenantId,
    environment_id: envId,
    name: 'Origin Protection Group',
    description: 'Customer-declared origin targets for bypass validation.',
    expected_behavior_default: 'must_block_before_origin',
    created_at: new Date().toISOString(),
  });
  store.targets.push({
    id: 'tgt_demo_1',
    tenant_id: tenantId,
    target_group_id: tgId,
    kind: 'fqdn',
    value: 'origin.demo.customer.example',
    expected_behavior: 'must_block_before_origin',
    created_at: new Date().toISOString(),
  });

  store.checkCatalog = CHECK_CATALOG.map((c) => ({ ...c }));
  store.readiness[tenantId] = {
    score: 42,
    factors: [],
    updated_at: new Date().toISOString(),
  };

  persistStore();
}