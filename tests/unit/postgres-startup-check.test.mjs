import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  parseStartupCheckArgs,
  redactStartupCheckErrorMessage,
  resolveStartupCheckConfig,
  summarizeMigrationResults,
} from '../../scripts/postgres-startup-check.mjs';

describe('postgres startup check args', () => {
  it('parses default non-mutating flags', () => {
    assert.deepEqual(parseStartupCheckArgs(['node', 'script.mjs']), {
      migrate: false,
      help: false,
    });
  });

  it('parses --migrate', () => {
    assert.deepEqual(parseStartupCheckArgs(['node', 'script.mjs', '--migrate']), {
      migrate: true,
      help: false,
    });
  });

  it('parses --help', () => {
    assert.deepEqual(parseStartupCheckArgs(['node', 'script.mjs', '--help']), {
      migrate: false,
      help: true,
    });
  });

  it('rejects unknown arguments', () => {
    assert.throws(
      () => parseStartupCheckArgs(['node', 'script.mjs', '--force']),
      /unknown argument/i,
    );
  });
});

describe('postgres startup check config', () => {
  it('fails when database URL is missing', () => {
    const config = resolveStartupCheckConfig({});
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /ASTRANULL_DATABASE_URL/i);
  });

  it('defaults to verify-only when migrate is not set', () => {
    const config = resolveStartupCheckConfig(
      { ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull' },
      {},
    );
    assert.equal(config.ok, true);
    assert.equal(config.migrate, false);
    assert.ok(config.poolLabels);
  });

  it('enables apply when --migrate is requested', () => {
    const config = resolveStartupCheckConfig(
      { ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull' },
      { migrate: true },
    );
    assert.equal(config.ok, true);
    assert.equal(config.migrate, true);
  });
});

describe('postgres startup check helpers', () => {
  it('redacts database URLs from strings', () => {
    const env = { ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example:5432/astranull' };
    const redacted = redactStartupCheckErrorMessage(
      'connect failed: postgresql://user:secret@db.example:5432/astranull',
      env,
    );
    assert.doesNotMatch(redacted, /postgresql:\/\//);
    assert.match(redacted, /\[redacted-database-url\]/);
  });

  it('redacts database URLs from Error objects', () => {
    const env = { ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example:5432/astranull' };
    const err = new Error('pool failed: postgresql://user:secret@db.example:5432/astranull');
    const redacted = redactStartupCheckErrorMessage(err, env);
    assert.doesNotMatch(redacted, /postgresql:\/\//);
    assert.match(redacted, /\[redacted-database-url\]/);
  });

  it('summarizes migration results', () => {
    const summary = summarizeMigrationResults([
      { version: '001_init', status: 'applied' },
      { version: '002_rls', status: 'skipped' },
      { version: '003_idx', status: 'applied' },
    ]);
    assert.deepEqual(summary, {
      applied: ['001_init', '003_idx'],
      skipped: ['002_rls'],
    });
  });
});