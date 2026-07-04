import assert from 'node:assert/strict';
import net from 'node:net';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { mintBundledStagingOidcJwt } from '../../src/lib/bundledStagingOidc.mjs';
import {
  applyReleaseChecklistCloseouts,
  applyReleasePlanCloseouts,
} from '../../scripts/apply-release-gate-closeouts.mjs';
import { aggregateProductionReadinessGapAudit } from '../../scripts/production-readiness-gap-audit.mjs';
import { runLiveOidcStagingLogin } from '../../scripts/run-live-oidc-staging-login.mjs';
import { runOperatorRunbookExercise } from '../../scripts/run-operator-runbook-exercise.mjs';
import {
  completeEvidenceRecords,
  stampAcceptedReleaseRecords,
} from '../fixtures/productionReleaseEvidenceComplete.mjs';
import { resolveReleaseProfileKinds } from '../../scripts/staging-readiness-attestation.mjs';
import { request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let baseUrl;
let server;
let originalFetch;

function completeAcceptedRecords(releaseId = 'rel-e2e-local') {
  return stampAcceptedReleaseRecords(
    completeEvidenceRecords(resolveReleaseProfileKinds('full')),
    releaseId,
  );
}

const closeoutManifest = {
  releaseId: 'rel-e2e-flow',
  inventoryComplete: true,
  kindsPresent: new Set(completeAcceptedRecords().map((record) => record.kind)),
  manifestPath: 'output/release-evidence/records.json',
};

const closedChecklistMarkdown = applyReleaseChecklistCloseouts(
  '- [x] OIDC ready. **Deferred (operational config):** IdP signoff\n',
  closeoutManifest,
);
const closedReleasePlanMarkdown = applyReleasePlanCloseouts(`
## Open production release gates
| Gate | Owner | Evidence | Status |
| Product and API contract accuracy | Product | docs | **Open** |
`, closeoutManifest);

async function reserveLocalPort() {
  const probe = net.createServer();
  await new Promise((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(0, resolve);
  });
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

before(async () => {
  process.env.ASTRANULL_NO_PERSIST = '1';
  process.env.ASTRANULL_BUNDLED_STAGING_OIDC = '1';
  delete process.env.NODE_ENV;
  delete process.env.ASTRANULL_AUTH_MODE;
  delete process.env.ASTRANULL_OIDC_ISSUER;
  delete process.env.ASTRANULL_OIDC_JWKS_URL;
  delete process.env.ASTRANULL_OIDC_AUDIENCE;

  const port = await reserveLocalPort();
  baseUrl = `http://127.0.0.1:${port}`;
  process.env.ASTRANULL_PUBLIC_BASE_URL = baseUrl;
  process.env.ASTRANULL_HOSTED_STAGING_BASE_URL = baseUrl;

  freshStore();
  server = createServer();
  await new Promise((resolve) => server.listen(port, resolve));
});

after(() => {
  server.close();
  if (originalFetch) globalThis.fetch = originalFetch;
});

describe('production readiness e2e flow', () => {
  it('runs local OIDC staging login probes against bundled fixture IdP', async () => {
    const result = await runLiveOidcStagingLogin({
      baseUrl,
      releaseId: 'rel-e2e-local',
      environment: 'staging',
      out: '/tmp/oidc-e2e-local.json',
    });
    assert.equal(result.manifest.validation.ok, true);
    assert.equal(result.evidence.scenarios.length, 8);
    assert.ok(result.evidence.scenarios.every((s) => s.status === 'passed'));
  });

  it('runs operator runbook exercise against local control plane', async () => {
    const result = await runOperatorRunbookExercise({
      baseUrl,
      releaseId: 'rel-e2e-local',
      environment: 'staging',
      out: '/tmp/runbook-e2e-local.json',
    });
    assert.equal(result.steps.length, 4);
    assert.ok(result.steps.every((step) => step.ok));
    assert.equal(result.artifact.validation.ok, true);
  });

  it('OIDC JWT auth reaches tenant APIs on local bundled staging server', async () => {
    const token = mintBundledStagingOidcJwt({
      role: 'admin',
      userId: 'usr_admin',
      tenantId: 'ten_demo',
    }, { ...process.env, ASTRANULL_PUBLIC_BASE_URL: baseUrl, ASTRANULL_BUNDLED_STAGING_OIDC: '1' });

    const checks = await request(baseUrl, 'GET', '/v1/checks', {
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(checks.status, 200);
    assert.ok(Array.isArray(checks.json.items));

    const headerOnly = await request(baseUrl, 'GET', '/v1/checks', {
      headers: {
        'x-tenant-id': 'ten_demo',
        'x-user-id': 'usr_admin',
        'x-role': 'admin',
      },
    });
    assert.equal(headerOnly.status, 401);
  });

  it('gap audit reports production_ready when evidence and doc gates are closed', () => {
    const report = aggregateProductionReadinessGapAudit(
      {
        releaseId: 'rel-e2e-local',
        records: completeAcceptedRecords('rel-e2e-local'),
      },
      {
        releaseChecklistMarkdown: closedChecklistMarkdown,
        releasePlanMarkdown: closedReleasePlanMarkdown,
      },
    );
    assert.equal(report.production_ready, true);
    assert.equal(report.evidence_attestation_complete, true);
    assert.equal(report.checklist_gates_open, false);
    assert.equal(report.required_evidence_kinds.counts.present, 31);
  });

  it('gap audit stays false when deferred checklist markers remain open', () => {
    const report = aggregateProductionReadinessGapAudit(
      {
        releaseId: 'rel-e2e-open',
        records: completeAcceptedRecords('rel-e2e-open'),
      },
      {
        releaseChecklistMarkdown: '- [x] OIDC. **Deferred (operational config):** pending IdP\n',
        releasePlanMarkdown: closedReleasePlanMarkdown,
      },
    );
    assert.equal(report.production_ready, false);
    assert.equal(report.checklist_gates_open, true);
    assert.ok(report.blocker_summary.some((line) => /checklist gates remain open/i.test(line)));
  });

  it('operator runbook exercise fails when metrics body lacks required counters', async () => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      const pathname = new URL(url).pathname;
      if (pathname === '/health') {
        return new Response(JSON.stringify({ status: 'ok' }), { status: 200 });
      }
      if (pathname === '/ready') {
        return new Response(JSON.stringify({ status: 'ready' }), { status: 200 });
      }
      if (pathname === '/metrics') {
        return new Response('http_requests_total 1\n', { status: 200 });
      }
      return new Response('not found', { status: 404 });
    };

    await assert.rejects(
      () => runOperatorRunbookExercise({
        baseUrl: 'http://127.0.0.1:9',
        releaseId: 'rel-metrics-fail',
        environment: 'staging',
        out: '/tmp/runbook-metrics-fail.json',
      }),
      /metrics/,
    );
  });
});