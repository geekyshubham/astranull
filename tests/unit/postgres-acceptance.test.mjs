import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  acceptanceTenantsNeedingCleanup,
  buildAcceptanceTempIds,
  createAcceptanceTenantSeedState,
  redactAcceptanceErrorMessage,
  resolvePostgresAcceptanceDecision,
} from '../../scripts/postgres-acceptance.mjs';

describe('postgres acceptance gating', () => {
  it('skips when acceptance flag is not set', () => {
    const decision = resolvePostgresAcceptanceDecision({});
    assert.equal(decision.action, 'skip');
    assert.match(decision.message ?? '', /skipped/i);
  });

  it('fails when required but acceptance flag is missing', () => {
    const decision = resolvePostgresAcceptanceDecision({
      ASTRANULL_REQUIRE_POSTGRES_ACCEPTANCE: '1',
    });
    assert.equal(decision.action, 'fail');
    assert.match(decision.message ?? '', /required/i);
  });

  it('fails when enabled without database URL', () => {
    const decision = resolvePostgresAcceptanceDecision({
      ASTRANULL_POSTGRES_ACCEPTANCE: '1',
    });
    assert.equal(decision.action, 'fail');
    assert.match(decision.message ?? '', /ASTRANULL_DATABASE_URL/i);
  });

  it('runs when enabled with database URL', () => {
    const decision = resolvePostgresAcceptanceDecision({
      ASTRANULL_POSTGRES_ACCEPTANCE: '1',
      ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull',
    });
    assert.equal(decision.action, 'run');
  });

  it('does not treat non-1 acceptance values as enabled', () => {
    const decision = resolvePostgresAcceptanceDecision({
      ASTRANULL_POSTGRES_ACCEPTANCE: 'true',
      ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull',
    });
    assert.equal(decision.action, 'skip');
  });
});

describe('postgres acceptance helpers', () => {
  it('redacts database URLs from error messages', () => {
    const redacted = redactAcceptanceErrorMessage(
      'connect failed: postgresql://user:secret@db.example:5432/astranull',
    );
    assert.doesNotMatch(redacted, /postgresql:\/\//);
    assert.match(redacted, /\[redacted-database-url\]/);
  });

  it('builds deterministic temporary ids from suffix', () => {
    assert.deepEqual(buildAcceptanceTempIds('staging42'), {
      tenantId: 'ten_accept_staging42',
      environmentId: 'env_accept_staging42',
      targetGroupId: 'tg_accept_staging42',
      targetId: 'tgt_accept_staging42',
    });
    assert.deepEqual(buildAcceptanceTempIds('  '), {
      tenantId: 'ten_accept_run',
      environmentId: 'env_accept_run',
      targetGroupId: 'tg_accept_run',
      targetId: 'tgt_accept_run',
    });
  });

  it('starts tenant seed state with no fixtures marked seeded', () => {
    assert.deepEqual(createAcceptanceTenantSeedState(), {
      tenantA: false,
      tenantB: false,
    });
    assert.deepEqual(acceptanceTenantsNeedingCleanup(createAcceptanceTenantSeedState()), []);
  });

  it('plans cleanup only for tenants that finished seeding', () => {
    const onlyA = { tenantA: true, tenantB: false };
    assert.deepEqual(acceptanceTenantsNeedingCleanup(onlyA), ['tenantA']);

    const both = { tenantA: true, tenantB: true };
    assert.deepEqual(acceptanceTenantsNeedingCleanup(both), ['tenantA', 'tenantB']);

    const onlyB = { tenantA: false, tenantB: true };
    assert.deepEqual(acceptanceTenantsNeedingCleanup(onlyB), ['tenantB']);
  });

  it('redacts database URLs from Error objects', () => {
    const err = new Error('pool failed: postgresql://user:secret@db.example:5432/astranull');
    const redacted = redactAcceptanceErrorMessage(err);
    assert.doesNotMatch(redacted, /postgresql:\/\//);
    assert.match(redacted, /\[redacted-database-url\]/);
  });
});