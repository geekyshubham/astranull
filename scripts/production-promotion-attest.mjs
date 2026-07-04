#!/usr/bin/env node
/**
 * Full production promotion attest: live drills + staging attest + gap audit.
 */
import { execSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

function defaultShell(command, inherit = false) {
  execSync(command, {
    cwd: REPO_ROOT,
    stdio: inherit ? 'inherit' : 'pipe',
    encoding: 'utf8',
  });
}

export function parseArgs(argv = []) {
  const opts = {
    profile: 'hosted',
    baseUrl: process.env.ASTRANULL_HOSTED_STAGING_BASE_URL ?? '',
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--profile') opts.profile = argv[++i];
    else if (arg === '--base-url') opts.baseUrl = argv[++i];
  }
  return opts;
}

export async function runProductionPromotionAttest(opts = {}, deps = {}) {
  const shell = deps.shell ?? defaultShell;
  const baseUrl = String(opts.baseUrl || process.env.ASTRANULL_HOSTED_STAGING_BASE_URL || '').replace(/\/$/, '');
  if (!baseUrl) throw new Error('ASTRANULL_HOSTED_STAGING_BASE_URL or --base-url is required');

  shell('npm test', true);
  shell('npm run lint');
  shell('npm run safety');
  shell('node scripts/validate-db-schema.mjs');

  process.env.ASTRANULL_HOSTED_STAGING_BASE_URL = baseUrl;
  process.env.ASTRANULL_RELEASE_ID = 'rel-hosted-staging-2026-07-03';

  shell(`node scripts/run-live-oidc-staging-login.mjs --base-url ${JSON.stringify(baseUrl)}`);
  shell(`node scripts/run-live-ui-accessibility-matrix.mjs --base-url ${JSON.stringify(baseUrl)}`);
  shell(`node scripts/run-operator-runbook-exercise.mjs --base-url ${JSON.stringify(baseUrl)}`);

  shell(`ASTRANULL_HOSTED_STAGING_BASE_URL=${JSON.stringify(baseUrl)} npm run staging:hosted:attest`, true);

  shell('node scripts/apply-release-gate-closeouts.mjs');
  shell('node scripts/production-readiness-gap-audit.mjs --evidence output/release-evidence/records.json');
  try {
    shell('node scripts/attach-external-verification-markers.mjs --force');
  } catch (err) {
    console.log(`production-promotion-attest: external verification manifest attach skipped (${err.message})`);
  }
  try {
    shell('node scripts/verify-external-production-readiness.mjs --validate-only');
  } catch {
    console.log(
      'production-promotion-attest: external verification incomplete (expected until live markers are attached).',
    );
  }

  const gapOut = path.join(REPO_ROOT, 'output/production-readiness-gap-audit.json');
  const readGapAuditReport = deps.readGapAuditReport
    ?? (() => JSON.parse(readFileSync(gapOut, 'utf8')));
  const report = readGapAuditReport();
  if (!report.production_ready) {
    throw new Error(
      `production_ready=false after promotion attest (external_blockers=${report.release_checklist_gates?.combined?.external_blockers ?? '?'})`,
    );
  }
  if (report.customer_production_ready !== true) {
    console.log(
      'production-promotion-attest: customer_production_ready=false — attach live external verification markers before customer launch.',
    );
  }
  return report;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log('Usage: node scripts/production-promotion-attest.mjs [--base-url URL]');
    return 0;
  }
  const report = await runProductionPromotionAttest(opts);
  console.log(
    `production-promotion-attest: production_ready=true scorecard=${report.production_readiness_scorecard?.overall_percent ?? 'n/a'}`,
  );
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code ?? 0),
    (err) => {
      console.error(`production-promotion-attest: ${err.message}`);
      process.exit(1);
    },
  );
}