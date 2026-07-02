import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  REQUIRED_PAGES,
  assertValidUiAccessibilityMatrixEvidence,
  createUiAccessibilityMatrixArtifact,
  main,
  parseArgs,
  validateUiAccessibilityMatrixEvidence,
} from '../../scripts/ui-accessibility-matrix-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-ui-a11y-matrix-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function baseRun(page, viewport, browser) {
  return {
    page,
    viewport,
    browser,
    axe_status: 'pass',
    keyboard_status: 'pass',
    screen_reader_status: 'pass',
    issues: { critical: 0, serious: 0, moderate: 1, minor: 2 },
    captured_at: '2026-07-02T12:00:00.000Z',
  };
}

function validMatrixEvidence() {
  const runs = [];
  for (const page of REQUIRED_PAGES) {
    runs.push(baseRun(page, 'desktop', 'chromium'));
    runs.push(baseRun(page, 'mobile', 'webkit'));
  }
  return {
    schema_version: 1,
    artifact_type: 'ui_accessibility_matrix_input',
    captured_at: '2026-07-02T12:00:00.000Z',
    runs,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('ui accessibility matrix evidence validator', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'matrix.json']), {
      input: 'matrix.json',
      out: 'output/ui-accessibility-matrix-evidence.json',
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(parseArgs(['--input', 'matrix.json', '--out', 'out.json', '--validate-only']), {
      input: 'matrix.json',
      out: 'out.json',
      validateOnly: true,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts a valid browser/accessibility matrix', () => {
    const validation = validateUiAccessibilityMatrixEvidence(validMatrixEvidence());
    assert.equal(validation.ok, true);
    assert.deepEqual(validation.missing_pages, []);
    assert.deepEqual(validation.missing_viewports, []);
    assert.deepEqual(validation.forbidden_fields, []);
    assert.equal(validation.summary.run_count, REQUIRED_PAGES.length * 2);
    assert.doesNotThrow(() => assertValidUiAccessibilityMatrixEvidence(validMatrixEvidence()));
  });

  it('rejects missing viewport and browser metadata', () => {
    const evidence = validMatrixEvidence();
    evidence.runs = evidence.runs.filter((run) => !(run.page === 'dashboard' && run.viewport === 'mobile'));
    const validation = validateUiAccessibilityMatrixEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.deepEqual(validation.missing_viewports, ['dashboard:mobile']);

    const noBrowser = validMatrixEvidence();
    delete noBrowser.runs[0].browser;
    assert.throws(
      () => assertValidUiAccessibilityMatrixEvidence(noBrowser),
      /Missing run metadata:.*dashboard\.browser/,
    );
  });

  it('rejects unresolved critical accessibility issues', () => {
    const evidence = validMatrixEvidence();
    evidence.runs.find((run) => run.page === 'findings' && run.viewport === 'desktop').issues.critical = 2;
    const validation = validateUiAccessibilityMatrixEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.match(validation.unresolved_critical.join(','), /findings/);
    assert.throws(
      () => assertValidUiAccessibilityMatrixEvidence(evidence),
      /Unresolved critical accessibility issue/,
    );
  });

  it('rejects forbidden raw artifact fields and secrets', () => {
    const evidence = {
      ...validMatrixEvidence(),
      screenshot: 'base64-not-allowed',
      runs: [
        {
          ...baseRun('dashboard', 'desktop', 'chromium'),
          raw_html: '<html>secret page</html>',
        },
      ],
    };
    const validation = validateUiAccessibilityMatrixEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.forbidden_fields.includes('screenshot'));
    assert.ok(validation.forbidden_fields.some((field) => field.includes('raw_html')));
    assert.throws(
      () => assertValidUiAccessibilityMatrixEvidence(evidence),
      /Forbidden artifact field/,
    );

    const withToken = validMatrixEvidence();
    withToken.token = 'ast_v1.fake.fake.fake';
    assert.throws(
      () => assertValidUiAccessibilityMatrixEvidence(withToken),
      /Forbidden artifact field.*token/,
    );
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'artifact.json');
    writeJson(input, validMatrixEvidence());
    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('writes a metadata-only validated artifact', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'artifact.json');
    writeJson(input, validMatrixEvidence());
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    const artifact = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(artifact.artifact_type, 'ui_accessibility_matrix_evidence');
    assert.equal(artifact.validation.ok, true);
    assert.equal(artifact.runs.length, REQUIRED_PAGES.length * 2);
    const blob = JSON.stringify(artifact);
    assert.equal(blob.includes('base64-not-allowed'), false);
    assert.equal(blob.includes('raw_html'), false);

    const bundle = createUiAccessibilityMatrixArtifact({
      createdAt: '2026-07-02T00:00:00.000Z',
      evidence: validMatrixEvidence(),
      database_url: 'postgres://secret',
    });
    assert.equal(bundle.created_at, '2026-07-02T00:00:00.000Z');
    assert.equal(JSON.stringify(bundle).includes('postgres://secret'), false);
  });
});