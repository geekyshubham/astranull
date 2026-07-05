#!/usr/bin/env node
/**
 * One-time DigitalOcean App Platform bootstrap for astranull.site.
 * Requires: doctl authenticated (`doctl auth init` or DIGITALOCEAN_ACCESS_TOKEN).
 */
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const SPEC_PATH = path.join(REPO_ROOT, 'ops/digitalocean/app.yaml');

function run(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    stdio: options.capture ? 'pipe' : 'inherit',
    env: process.env,
  });
  if (result.status !== 0) {
    const detail = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
    throw new Error(`${cmd} ${args.join(' ')} failed${detail ? `: ${detail}` : ''}`);
  }
  return result.stdout?.trim() ?? '';
}

function ensureDoctl() {
  if (process.env.DIGITALOCEAN_ACCESS_TOKEN?.trim()) {
    process.env.DIGITALOCEAN_ACCESS_TOKEN = process.env.DIGITALOCEAN_ACCESS_TOKEN.trim();
    return;
  }
  const account = run('doctl', ['account', 'get'], { capture: true });
  if (!account) throw new Error('doctl is not authenticated. Run: doctl auth init');
}

function existingAppId() {
  const out = run('doctl', ['apps', 'list', '--format', 'ID,Spec.Name', '--no-header'], { capture: true });
  for (const line of out.split('\n')) {
    const [id, name] = line.trim().split(/\s+/, 2);
    if (name === 'astranull' && id) return id;
  }
  return null;
}

function buildSpecWithSecrets() {
  const base = readFileSync(SPEC_PATH, 'utf8');
  const encryptionKey = randomBytes(32).toString('hex');
  const probeSecret = randomBytes(24).toString('hex');
  const extra = `
      - key: ASTRANULL_SECRET_ENCRYPTION_KEY
        scope: RUN_TIME
        type: SECRET
        value: ${encryptionKey}
      - key: ASTRANULL_PROBE_WORKER_SECRET
        scope: RUN_TIME
        type: SECRET
        value: ${probeSecret}
`;
  const patched = base.replace(
    '      # - ASTRANULL_PROBE_WORKER_SECRET    (32+ chars)',
    extra.trimEnd(),
  );
  const tmp = path.join(REPO_ROOT, 'ops/digitalocean/.app.generated.yaml');
  writeFileSync(tmp, patched, 'utf8');
  return tmp;
}

async function main() {
  ensureDoctl();
  run('doctl', ['apps', 'spec', 'validate', SPEC_PATH], { capture: true });

  const generated = buildSpecWithSecrets();
  const appId = existingAppId();

  if (appId) {
    console.log(`digitalocean-bootstrap: updating existing app ${appId}`);
    run('doctl', ['apps', 'update', appId, '--spec', generated]);
    run('doctl', ['apps', 'create-deployment', appId, '--wait']);
  } else {
    console.log('digitalocean-bootstrap: creating app astranull');
    const out = run('doctl', ['apps', 'create', '--spec', generated, '--format', 'ID', '--no-header'], {
      capture: true,
    });
    const createdId = out.split('\n')[0]?.trim();
    if (!createdId) throw new Error('doctl apps create did not return an app id');
    console.log(`digitalocean-bootstrap: created app ${createdId}`);
    run('doctl', ['apps', 'create-deployment', createdId, '--wait']);
  }

  console.log('\nNext steps:');
  console.log('1. App Platform → astranull → Settings → Domains → confirm astranull.site DNS');
  console.log('2. GitHub → geekyshubham/astranull → Settings → Secrets → DIGITALOCEAN_ACCESS_TOKEN');
  console.log('3. Push to main (or run Deploy DigitalOcean workflow) for CI/CD deploys');
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  if (/GitHub user not authenticated/i.test(message)) {
    console.error(`${message}\n`);
    console.error('Link GitHub to DigitalOcean, then re-run: npm run do:bootstrap');
    console.error('https://cloud.digitalocean.com/apps/github/install');
    process.exit(1);
  }
  console.error(message);
  process.exit(1);
});