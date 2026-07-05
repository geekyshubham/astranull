import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const START_SCRIPT = path.join(REPO_ROOT, 'scripts/railway-staging-start.mjs');

describe('railway-staging-start probe worker URL', () => {
  it('prefers loopback for in-container polling unless overridden', async () => {
    const mod = await import('../../scripts/railway-staging-start.mjs');
    assert.equal(
      mod.resolveProbeWorkerApiUrl(
        { ASTRANULL_PUBLIC_BASE_URL: 'https://astranull-qteog.ondigitalocean.app', PORT: '8080' },
        '8080',
      ),
      'http://127.0.0.1:8080',
    );
    assert.equal(
      mod.resolveProbeWorkerApiUrl(
        { ASTRANULL_PROBE_WORKER_API_URL: 'http://127.0.0.1:9090' },
        '8080',
      ),
      'http://127.0.0.1:9090',
    );
  });
});

describe('railway-staging-start', () => {
  it('refuses to start without ASTRANULL_DATABASE_URL', async () => {
    const child = spawn(process.execPath, [START_SCRIPT], {
      cwd: REPO_ROOT,
      env: { ...process.env, ASTRANULL_DATABASE_URL: '' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const [code, stderr] = await new Promise((resolve, reject) => {
      let err = '';
      child.stderr.on('data', (chunk) => { err += chunk; });
      child.on('error', reject);
      child.on('exit', (exitCode) => resolve([exitCode, err]));
    });

    assert.equal(code, 1);
    assert.match(stderr, /ASTRANULL_DATABASE_URL is required|managed Postgres/);
  });
});