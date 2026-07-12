#!/usr/bin/env node
/**
 * Seeds .data/astranull-dev.json with the full portal demo fixture.
 * Restart the API after running (in-memory store is loaded at startup).
 */
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { migrateDevStore, writeDevStoreToDisk, clearStoreCacheForTests } from '../src/store.mjs';
import {
  buildPortalDemoStore,
  PORTAL_DEMO_IDS,
} from '../tests/fixtures/portal-demo/seed.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
  return { help: argv.includes('--help') || argv.includes('-h') };
}

function main() {
  const { help } = parseArgs(process.argv);
  if (help) {
    console.log(`Usage: node scripts/seed-dev-portal-demo.mjs

Writes the portal demo fixture to .data/astranull-dev.json (overwrites existing dev store).
Restart \`npm run dev:api\` afterward so the control plane reloads the file.

Session defaults (dev-headers):
  x-tenant-id: ${PORTAL_DEMO_IDS.tenantId}
  x-user-id: usr_admin
  x-role: admin

Detail deep-links (append to /app#...):
  target-group-detail?id=${PORTAL_DEMO_IDS.targetGroupId}
  target-detail?id=${PORTAL_DEMO_IDS.targetId}
  agent-detail?id=${PORTAL_DEMO_IDS.agentId}
  run-detail?id=${PORTAL_DEMO_IDS.runId}
  finding-detail?id=${PORTAL_DEMO_IDS.findingId}
  report-detail?id=${PORTAL_DEMO_IDS.reportId}
  environment-detail?id=${PORTAL_DEMO_IDS.environmentId}
  check-detail?id=origin.direct_bypass.safe
  policy-detail?id=${PORTAL_DEMO_IDS.policyId}
  evidence-detail?id=${PORTAL_DEMO_IDS.evidenceId}
  queue-detail?id=${PORTAL_DEMO_IDS.highScaleId}
  tenant-detail?id=${PORTAL_DEMO_IDS.provisionedTenantId}
`);
    return;
  }

  delete process.env.ASTRANULL_NO_PERSIST;
  const store = buildPortalDemoStore();
  migrateDevStore(store);
  writeDevStoreToDisk(store);
  clearStoreCacheForTests();

  const counts = {
    tenants: store.tenants.length,
    environments: store.environments.length,
    target_groups: store.targetGroups.length,
    targets: store.targets.length,
    agents: store.agents.length,
    runs: store.testRuns.length,
    findings: store.findings.length,
    reports: store.reports.length,
    notifications_rules: store.notificationRules.length,
    audit: store.auditLog.length,
    signup_requests: store.signupRequests.length,
    high_scale: store.highScaleRequests.length,
    release_evidence: store.productionReleaseEvidence.length,
    waf_connectors: store.wafConnectors.length,
  };

  console.log(`seed-dev-portal-demo: wrote ${path.join(ROOT, '.data', 'astranull-dev.json')}`);
  console.log(`seed-dev-portal-demo: tenant=${PORTAL_DEMO_IDS.tenantId}`);
  for (const [key, value] of Object.entries(counts)) {
    console.log(`  ${key}: ${value}`);
  }
  console.log('seed-dev-portal-demo: restart the API (`npm run dev:api`) then open http://127.0.0.1:5173/app');
}

main();