#!/usr/bin/env node
/**
 * Mechanical doc-17 §12 gate: every gating FT id must appear in captured CI evidence logs.
 */
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const SCRATCH = process.env.ASTRANULL_CI_SCRATCH
  ?? path.join(ROOT, '.ci-evidence');

const REQUIRED = [
  'FT-CRUD-TG-01',
  'FT-CRUD-TGT-01',
  'FT-CRUD-AGT-01',
  'FT-CRUD-POL-01',
  'FT-CRUD-CHK-01',
  'FT-CRUD-CONN-01',
  'FT-CRUD-NOTIF-01',
  'FT-CRUD-REM-01',
  'FT-CRUD-TEN-01',
  'FT-STATE-populated',
  'FT-STATE-empty',
  'FT-STATE-loading',
  'FT-STATE-error',
  'FT-STATE-edge',
  'FT-PERF-01',
  'FT-PERF-02',
  'FT-PERF-03',
  'FT-PERF-04',
  'FT-PERF-05',
  'FT-PERF-06',
  'FT-PERF-07',
  'FT-PERF-PG-01',
  'FT-PERF-PG-02',
  'FT-PERF-PG-03',
  'FT-PERF-PG-04',
  'FT-PROV-dyn-01',
  'FT-PROV-dyn-02',
  'FT-PROV-dyn-03',
  'FT-PROV-dyn-04',
  'FT-PROV-dyn-05',
  'FT-PROV-dyn-06',
  'FT-PROV-dyn-07',
];

const CRUD_DESCRIBES = [
  'target group lifecycle (FT-CRUD-TG-01)',
  'target lifecycle (FT-CRUD-TGT-01)',
  'agent lifecycle (FT-CRUD-AGT-01)',
  'test policy lifecycle (FT-CRUD-POL-01)',
  'check enable/disable lifecycle (FT-CRUD-CHK-01)',
  'connector lifecycle (FT-CRUD-CONN-01)',
  'notification lifecycle (FT-CRUD-NOTIF-01)',
  'finding remediation lifecycle (FT-CRUD-REM-01)',
  'tenant lifecycle (FT-CRUD-TEN-01)',
];

function readLog(name) {
  const file = path.join(SCRATCH, name);
  if (!fs.existsSync(file)) return '';
  return fs.readFileSync(file, 'utf8');
}

function missingFrom(text, ids) {
  return ids.filter((id) => !text.includes(id));
}

const ciFull = readLog('ci-full.log');
const portalScale = readLog('portal-scale.log');
const portalPlaywright = readLog('portal-playwright.log');
const combined = `${ciFull}\n${portalScale}\n${portalPlaywright}`;

const missingIds = missingFrom(combined, REQUIRED);
const missingCrud = CRUD_DESCRIBES.filter((label) => !ciFull.includes(label));
const missingP95 = [
  'FT-PERF-01 measured p95',
  'FT-PERF-PG-01 postgres measured p95',
].filter((line) => !portalScale.includes(line) && !ciFull.includes(line));

const errors = [];
if (missingIds.length) {
  errors.push(`missing FT ids: ${missingIds.join(', ')}`);
}
if (missingCrud.length) {
  errors.push(`missing CRUD describe blocks in ci-full.log: ${missingCrud.join('; ')}`);
}
if (missingP95.length) {
  errors.push(`missing measured p95 lines in portal-scale.log: ${missingP95.join('; ')}`);
}
const scaleText = `${portalScale}\n${ciFull}`;
if (!/10000 groups|10[_,]?000 groups|10_000/.test(scaleText)) {
  errors.push('portal-scale evidence must document doc-16 10k-scale profile (10000 groups)');
}
if (/portal-hydrator-perf postgres: 200 groups/.test(scaleText)) {
  errors.push('portal-scale evidence must not use FAST 200-group profile when doc-16 requires 10k');
}
if (!portalPlaywright.includes('44 passed') && !portalPlaywright.match(/\b44 passed\b/)) {
  const passMatch = portalPlaywright.match(/(\d+) passed/);
  if (!passMatch || Number(passMatch[1]) < 44) {
    errors.push(`portal-playwright.log expected 44 passed tests, got: ${passMatch?.[0] ?? 'no run'}`);
  }
}

if (errors.length) {
  console.error('assert-portal-matrix: FAILED');
  for (const err of errors) console.error(`  - ${err}`);
  process.exit(1);
}

console.log(`assert-portal-matrix: ok (${REQUIRED.length} FT ids present in ${SCRATCH})`);