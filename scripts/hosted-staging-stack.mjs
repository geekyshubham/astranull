#!/usr/bin/env node
import { execSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  HOSTED_STAGING_ENVIRONMENT,
  HOSTED_STAGING_RELEASE_ID,
  resolveHostedStagingBaseUrl,
  resolveStagingProbeWorkerSecret,
} from './lib/hostedStaging.mjs';
import { runHostedStagingE2eMatrix } from './hosted-staging-e2e-matrix.mjs';
import { runLocalStagingSmoke } from './local-staging-smoke.mjs';
import { collectReleaseEvidence } from './collect-release-evidence.mjs';


const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

function shell(command, options = {}) {
  return execSync(command, {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    stdio: options.stdio ?? 'pipe',
    ...options,
  }).trim();
}

/**
 * @param {string[]} argv
 */
export function parseHostedStagingStackArgs(argv = []) {
  const opts = { command: 'url', baseUrl: resolveHostedStagingBaseUrl(), help: false };
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--base-url') opts.baseUrl = next();
    else if (arg.startsWith('--')) throw new Error(`Unknown argument: ${arg}`);
    else positional.push(arg);
  }
  if (positional.length > 0) opts.command = positional[0];
  return opts;
}

export function normalizeHostedBaseUrl(value) {
  const trimmed = String(value ?? '').trim().replace(/["']+$/g, '').replace(/^["']+/g, '');
  if (!trimmed) return '';
  if (/^https?:\/\//i.test(trimmed)) return trimmed.replace(/\/$/, '');
  return `https://${trimmed.replace(/\/$/, '')}`;
}

export function discoverRailwayBaseUrl() {
  try {
    const raw = shell('railway domain --json 2>/dev/null || railway domain 2>/dev/null');
    if (raw.startsWith('{') || raw.startsWith('[')) {
      const parsed = JSON.parse(raw);
      const domain = parsed?.domain ?? parsed?.[0]?.domain ?? parsed?.[0];
      if (domain) return normalizeHostedBaseUrl(domain);
    }
    const line = raw.split('\n').find((entry) => entry.includes('.up.railway.app') || entry.includes('railway.app'));
    if (line) {
      const match = line.match(/https?:\/\/[^\s"'`]+/);
      if (match) return normalizeHostedBaseUrl(match[0]);
      return normalizeHostedBaseUrl(line);
    }
  } catch {
    // fall through
  }
  return '';
}

export async function runHostedStagingStack(opts) {
  const baseUrl = normalizeHostedBaseUrl(opts.baseUrl)
    || discoverRailwayBaseUrl();
  if (!baseUrl && opts.command !== 'url' && opts.command !== 'deploy') {
    throw new Error('Hosted staging base URL required (--base-url or railway domain)');
  }
  process.env.ASTRANULL_HOSTED_STAGING_BASE_URL = baseUrl;
  process.env.ASTRANULL_HOSTED_STAGING_USE_OIDC = '1';
  process.env.ASTRANULL_PROBE_WORKER_SECRET = resolveStagingProbeWorkerSecret(baseUrl);

  switch (opts.command) {
    case 'url': {
      const discovered = baseUrl || discoverRailwayBaseUrl();
      console.log(discovered || 'hosted-staging-stack: no Railway domain discovered');
      return discovered ? 0 : 1;
    }
    case 'deploy':
      shell('railway up --detach -s control-plane', { stdio: 'inherit' });
      console.log('hosted-staging-stack: deploy triggered');
      return 0;
    case 'smoke': {
      const result = await runLocalStagingSmoke(baseUrl);
      console.log(`hosted-staging-stack: smoke ok (${result.checks.join(', ')})`);
      return 0;
    }
    case 'e2e-matrix': {
      const result = await runHostedStagingE2eMatrix({ baseUrl });
      console.log(
        `hosted-staging-stack: e2e-matrix ${result.validation.ok ? 'ok' : 'failed'} `
        + `(overall_status=${result.artifact.overall_status})`,
      );
      return result.validation.ok ? 0 : 1;
    }
    case 'collect-evidence': {
      await collectReleaseEvidence({
        environment: HOSTED_STAGING_ENVIRONMENT,
        releaseId: HOSTED_STAGING_RELEASE_ID,
        refreshHostedStagingE2e: true,
      });
      console.log(`hosted-staging-stack: evidence collected for ${HOSTED_STAGING_ENVIRONMENT}`);
      return 0;
    }
    case 'attest': {
      await runHostedStagingStack({ ...opts, command: 'smoke' });
      await runHostedStagingStack({ ...opts, command: 'e2e-matrix' });
      await runHostedStagingStack({ ...opts, command: 'collect-evidence' });
      shell('npm run release:gap-audit:staging', { stdio: 'inherit' });
      shell('npm run release:staging-attestation:hosted', { stdio: 'inherit' });
      console.log('hosted-staging-stack: attest complete');
      return 0;
    }
    default:
      throw new Error(`Unknown command: ${opts.command}`);
  }
}

async function main() {
  const opts = parseHostedStagingStackArgs(process.argv.slice(2));
  if (opts.help) {
    console.log('Usage: node scripts/hosted-staging-stack.mjs [url|deploy|smoke|e2e-matrix|collect-evidence|attest] [--base-url URL]');
    return 0;
  }
  return runHostedStagingStack(opts);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main().then(
    (code) => process.exit(code ?? 0),
    (err) => {
      console.error(`hosted-staging-stack: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    },
  );
}