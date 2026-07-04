import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseArgs, runProductionPromotionAttest } from '../../scripts/production-promotion-attest.mjs';

describe('production promotion attest', () => {
  it('parseArgs reads profile and base-url flags', () => {
    const opts = parseArgs(['--profile', 'hosted', '--base-url', 'https://staging.example.test']);
    assert.equal(opts.profile, 'hosted');
    assert.equal(opts.baseUrl, 'https://staging.example.test');
    assert.equal(opts.help, false);
  });

  it('requires base URL before running attest orchestration', async () => {
    await assert.rejects(
      () => runProductionPromotionAttest({ baseUrl: '' }),
      /ASTRANULL_HOSTED_STAGING_BASE_URL or --base-url is required/,
    );
  });

  it('parseArgs sets help when -h is passed', () => {
    const opts = parseArgs(['-h']);
    assert.equal(opts.help, true);
  });

  it('runs unit tests before setting hosted staging env', async () => {
    const commands = [];
    const envSnapshots = [];
    const originalHosted = process.env.ASTRANULL_HOSTED_STAGING_BASE_URL;
    delete process.env.ASTRANULL_HOSTED_STAGING_BASE_URL;

    const shell = (command) => {
      commands.push(command);
      envSnapshots.push(process.env.ASTRANULL_HOSTED_STAGING_BASE_URL);
      if (command.startsWith('node scripts/run-live-oidc-staging-login.mjs')) {
        throw new Error('stop-after-hosted-env-set');
      }
    };

    await assert.rejects(
      () => runProductionPromotionAttest({ baseUrl: 'https://staging.example.test' }, { shell }),
      /stop-after-hosted-env-set/,
    );

    const npmTestIndex = commands.indexOf('npm test');
    const oidcIndex = commands.findIndex((command) => command.startsWith('node scripts/run-live-oidc-staging-login.mjs'));
    assert.ok(npmTestIndex >= 0);
    assert.ok(oidcIndex > npmTestIndex);
    assert.equal(envSnapshots[npmTestIndex], undefined);
    assert.equal(envSnapshots[oidcIndex], 'https://staging.example.test');

    if (originalHosted === undefined) delete process.env.ASTRANULL_HOSTED_STAGING_BASE_URL;
    else process.env.ASTRANULL_HOSTED_STAGING_BASE_URL = originalHosted;
  });

  it('reruns gap audit after gate closeouts', async () => {
    const commands = [];
    const shell = (command) => {
      commands.push(command);
      if (command.startsWith('node scripts/production-readiness-gap-audit.mjs')) {
        throw new Error('gap-audit-rerun-ok');
      }
    };

    await assert.rejects(
      () => runProductionPromotionAttest({ baseUrl: 'https://staging.example.test' }, { shell }),
      /gap-audit-rerun-ok/,
    );

    const closeoutIndex = commands.indexOf('node scripts/apply-release-gate-closeouts.mjs');
    const gapAuditIndex = commands.indexOf(
      'node scripts/production-readiness-gap-audit.mjs --evidence output/release-evidence/records.json',
    );
    assert.ok(closeoutIndex >= 0);
    assert.ok(gapAuditIndex > closeoutIndex);
  });

  it('runs external verification check after gap audit without failing promotion', async () => {
    const commands = [];
    const shell = (command) => {
      commands.push(command);
    };

    const report = await runProductionPromotionAttest(
      { baseUrl: 'https://staging.example.test' },
      {
        shell,
        readGapAuditReport: () => ({
          production_ready: true,
          customer_production_ready: false,
          production_readiness_scorecard: { overall_percent: 95 },
        }),
      },
    );

    assert.equal(report.production_ready, true);
    const gapAuditIndex = commands.indexOf(
      'node scripts/production-readiness-gap-audit.mjs --evidence output/release-evidence/records.json',
    );
    const attachIndex = commands.indexOf('node scripts/attach-external-verification-markers.mjs --force');
    const externalVerifyIndex = commands.indexOf(
      'node scripts/verify-external-production-readiness.mjs --validate-only',
    );
    assert.ok(gapAuditIndex >= 0);
    assert.ok(attachIndex > gapAuditIndex);
    assert.ok(externalVerifyIndex > attachIndex);
  });
});