#!/usr/bin/env node
/**
 * Capture full portal revamp CI matrix output for verifier evidence (plan §6).
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const SCRATCH = process.env.ASTRANULL_CI_SCRATCH
  ?? path.join(ROOT, '.ci-evidence');

const CLEAN_ENV = {
  ASTRANULL_PORTAL_SCALE: '',
  ASTRANULL_PORTAL_SCALE_FAST: '',
  ASTRANULL_PORTAL_PERF_ITERATIONS: '',
};

function runSection(title, command, args, env = {}) {
  const header = `\n=== ${title} ===\n`;
  process.stdout.write(header);
  const result = spawnSync(command, args, {
    cwd: ROOT,
    env: { ...process.env, ...CLEAN_ENV, ...env },
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const output = `${header}${result.stdout ?? ''}${result.stderr ?? ''}`;
  const exitNote = result.status !== 0 ? `\n[exit ${result.status}]\n` : '';
  return { output: output + exitNote, status: result.status ?? 1 };
}

fs.mkdirSync(SCRATCH, { recursive: true });

const sections = [
  ['lint:portal', 'npm', ['run', 'lint:portal']],
  ['test:contract', 'npm', ['run', 'test:contract']],
  ['test:unit', 'npm', ['run', 'test:unit']],
  ['test:db-migrate', 'npm', ['run', 'test:db-migrate']],
  ['test:integration', 'npm', ['run', 'test:integration'], CLEAN_ENV],
  ['test:e2e', 'npm', ['run', 'test:e2e'], CLEAN_ENV],
  ['test:portal-playwright', 'npm', ['run', 'test:portal-playwright'], CLEAN_ENV],
  ['test:a11y', 'npm', ['run', 'test:a11y'], CLEAN_ENV],
  ['test:portal-scale (10k)', 'npm', ['run', 'test:portal-scale'], {
    ASTRANULL_PORTAL_SCALE: '1',
    ASTRANULL_PORTAL_PERF_ITERATIONS: '12',
  }],
];

let combined = '';
let failed = false;

for (const [title, command, args, env] of sections) {
  const { output, status } = runSection(title, command, args, env ?? {});
  combined += output;
  if (status !== 0) failed = true;
  if (title.startsWith('test:portal-scale')) {
    fs.writeFileSync(path.join(SCRATCH, 'portal-scale.log'), output);
  }
  if (title === 'test:db-migrate') {
    fs.writeFileSync(path.join(SCRATCH, 'db-migrate-test.log'), output);
  }
  if (title === 'test:portal-playwright') {
    fs.writeFileSync(path.join(SCRATCH, 'portal-playwright.log'), output);
  }
}

// Matrix gate reads ci-full.log from disk — flush suite output before asserting.
fs.writeFileSync(path.join(SCRATCH, 'ci-full.log'), combined);

const matrix = spawnSync('node', ['scripts/assert-portal-matrix.mjs'], {
  cwd: ROOT,
  env: { ...process.env, ASTRANULL_CI_SCRATCH: SCRATCH },
  encoding: 'utf8',
});
const matrixOutput = `\n=== assert-portal-matrix ===\n${matrix.stdout ?? ''}${matrix.stderr ?? ''}`;
combined += matrixOutput;
process.stdout.write(matrixOutput);
if (matrix.status !== 0) failed = true;

fs.writeFileSync(path.join(SCRATCH, 'ci-full.log'), combined);
console.log(`generate-ci-full-evidence: wrote ${SCRATCH}/ci-full.log`);

process.exit(failed ? 1 : 0);