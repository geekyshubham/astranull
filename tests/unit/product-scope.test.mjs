import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';

const ROOT = process.cwd();
const IMPL_DIRS = ['src', 'agents', 'apps/web', 'scripts', 'workers'];

const PROMISE_MARKERS = [
  'customer-declared targets',
  'cloud credentials',
  'automatic IP inventory discovery',
];

const FORBIDDEN_IMPL = [
  /process\.env\.AWS_/,
  /process\.env\.AZURE_/i,
  /process\.env\.GOOGLE_APPLICATION_CREDENTIALS/,
  /DefaultAzureCredential/,
  /fromIni\s*\(/,
  /@aws-sdk\//,
  /@google-cloud\//,
  /google-cloud\//,
  /@azure\//,
  /automatic[_-]ip[_-]inventory[_-]discover/i,
  /enable(?:Automatic)?IpInventoryDiscovery/i,
  /discover(?:All)?EnterpriseIps/i,
  /scanIpInventory/i,
];

function readUtf8(rel) {
  return readFileSync(path.join(ROOT, rel), 'utf8');
}

function walkImpl(dir, files = []) {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walkImpl(p, files);
    else if (/\.(mjs|js)$/.test(name) && !name.endsWith('safety-check.mjs')) files.push(p);
  }
  return files;
}

function assertContainsMarkers(text, label) {
  for (const marker of PROMISE_MARKERS) {
    assert.ok(text.includes(marker), `${label} missing promise marker: ${marker}`);
  }
}

describe('product scope and no-access-first promise', () => {
  it('documents the final promise in README and platform overview', () => {
    const readme = readUtf8('README.md');
    const overview = readUtf8('docs/product/01-platform-overview.md');
    assertContainsMarkers(readme, 'README.md');
    assertContainsMarkers(overview, 'docs/product/01-platform-overview.md');
    assert.ok(readme.includes('no-access-first'), 'README.md should state no-access-first');
    assert.ok(overview.includes('no-access-first'), 'platform overview should state no-access-first');
  });

  it('surfaces no-access-first promise copy in the web app', () => {
    const appJs = readUtf8('apps/web/app.js');
    assertContainsMarkers(appJs, 'apps/web/app.js');
    assert.ok(appJs.includes('PLATFORM_PROMISE'), 'apps/web/app.js should define PLATFORM_PROMISE');
    assert.ok(appJs.includes('No-access-first'), 'apps/web/app.js should label no-access-first in UI copy');
  });

  it('keeps implementation free of cloud SDK defaults and inventory-discovery feature paths', () => {
    const hits = [];
    for (const d of IMPL_DIRS) {
      const full = path.join(ROOT, d);
      try {
        for (const file of walkImpl(full)) {
          const text = readFileSync(file, 'utf8');
          for (const pattern of FORBIDDEN_IMPL) {
            if (pattern.test(text)) hits.push({ file, pattern: String(pattern) });
          }
        }
      } catch (e) {
        if (e.code !== 'ENOENT') throw e;
      }
    }
    assert.equal(
      hits.length,
      0,
      `forbidden implementation patterns:\n${hits.map((h) => `${h.pattern} in ${h.file}`).join('\n')}`,
    );
  });
});