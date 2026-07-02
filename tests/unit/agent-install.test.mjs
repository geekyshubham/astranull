import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

const installSh = path.join(process.cwd(), 'agents/linux/install.sh');
const uninstallSh = path.join(process.cwd(), 'agents/linux/uninstall.sh');
const agentSource = path.join(process.cwd(), 'agents/linux/astranull-agent.mjs');
const TEST_TOKEN = 'ast_testtoken1234567890';

function stagedInstall(root) {
  const sha = sha256File(agentSource);
  execFileSync(
    installSh,
    [
      '--token',
      TEST_TOKEN,
      '--sha256',
      sha,
      '--agent-source',
      agentSource,
      '--install-root',
      root,
      '--no-start',
      '--api',
      'https://api.example.test',
    ],
    { encoding: 'utf8' },
  );
}

function sha256File(filePath) {
  const data = fs.readFileSync(filePath);
  return createHash('sha256').update(data).digest('hex');
}

describe('agent install packaging (developer validation)', () => {
  it('dry-run validates token without echoing secret', () => {
    const out = execFileSync(installSh, ['--dry-run', '--token', TEST_TOKEN], {
      encoding: 'utf8',
    });
    assert.match(out, /dry-run/);
    assert.doesNotMatch(out, /ast_testtoken1234567890/);
  });

  it('non-dry-run without --sha256 fails safely', () => {
    assert.throws(
      () => execFileSync(installSh, ['--token', TEST_TOKEN], { encoding: 'utf8' }),
      (err) => err.status === 1,
    );
  });

  it('staged install writes files without echoing token', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-install-'));
    const sha = sha256File(agentSource);
    const out = execFileSync(
      installSh,
      [
        '--token',
        TEST_TOKEN,
        '--sha256',
        sha,
        '--agent-source',
        agentSource,
        '--install-root',
        root,
        '--no-start',
        '--api',
        'https://api.example.test',
        '--tenant',
        'ten_demo',
      ],
      { encoding: 'utf8' },
    );
    assert.doesNotMatch(out, new RegExp(TEST_TOKEN));

    const bin = path.join(root, 'usr/local/bin/astranull-agent.mjs');
    const envFile = path.join(root, 'etc/astranull/agent.env');
    const tokenFile = path.join(root, 'var/lib/astranull/bootstrap-token');
    const unit = path.join(root, 'etc/systemd/system/astranull-agent.service');

    assert.ok(fs.existsSync(bin));
    assert.ok(fs.existsSync(envFile));
    assert.ok(fs.existsSync(tokenFile));
    assert.ok(fs.existsSync(unit));

    const envText = fs.readFileSync(envFile, 'utf8');
    assert.match(envText, /ASTRANULL_API_URL=https:\/\/api\.example\.test/);
    assert.doesNotMatch(envText, /ast_testtoken/);
    assert.match(envText, /ASTRANULL_BOOTSTRAP_TOKEN_FILE=/);

    const tokenStat = fs.statSync(tokenFile);
    if (process.platform !== 'win32') {
      assert.equal(tokenStat.mode & 0o777, 0o600);
    }
    assert.equal(fs.readFileSync(tokenFile, 'utf8'), TEST_TOKEN);
  });

  it('bad checksum refuses install', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-install-bad-'));
    assert.throws(
      () =>
        execFileSync(
          installSh,
          [
            '--token',
            TEST_TOKEN,
            '--sha256',
            '0'.repeat(64),
            '--agent-source',
            agentSource,
            '--install-root',
            root,
            '--no-start',
          ],
          { encoding: 'utf8' },
        ),
      (err) => err.status === 1,
    );
    assert.equal(fs.existsSync(path.join(root, 'usr/local/bin/astranull-agent.mjs')), false);
  });
});

describe('agent uninstall (developer validation)', () => {
  it('staged uninstall without purge removes binary/env/unit but preserves identity data', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-uninstall-'));
    stagedInstall(root);

    const bin = path.join(root, 'usr/local/bin/astranull-agent.mjs');
    const envFile = path.join(root, 'etc/astranull/agent.env');
    const tokenFile = path.join(root, 'var/lib/astranull/bootstrap-token');
    const unit = path.join(root, 'etc/systemd/system/astranull-agent.service');
    const identityFile = path.join(root, 'var/lib/astranull/identity.json');

    fs.writeFileSync(identityFile, '{"agent_id":"ag_test"}', 'utf8');

    const out = execFileSync(uninstallSh, ['--install-root', root], { encoding: 'utf8' });
    assert.doesNotMatch(out, new RegExp(TEST_TOKEN));

    assert.equal(fs.existsSync(bin), false);
    assert.equal(fs.existsSync(envFile), false);
    assert.equal(fs.existsSync(unit), false);
    assert.ok(fs.existsSync(tokenFile));
    assert.ok(fs.existsSync(identityFile));
    assert.equal(fs.readFileSync(tokenFile, 'utf8'), TEST_TOKEN);
  });

  it('staged uninstall with --purge-data removes bootstrap and identity directory', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-uninstall-purge-'));
    stagedInstall(root);

    const identityDir = path.join(root, 'var/lib/astranull');
    const tokenFile = path.join(identityDir, 'bootstrap-token');
    assert.ok(fs.existsSync(tokenFile));

    execFileSync(uninstallSh, ['--install-root', root, '--purge-data'], { encoding: 'utf8' });

    assert.equal(fs.existsSync(identityDir), false);
    assert.equal(fs.existsSync(tokenFile), false);
  });

  it('dry-run does not remove files and does not echo secrets', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-uninstall-dry-'));
    stagedInstall(root);

    const bin = path.join(root, 'usr/local/bin/astranull-agent.mjs');
    const tokenFile = path.join(root, 'var/lib/astranull/bootstrap-token');

    const out = execFileSync(uninstallSh, ['--dry-run', '--install-root', root], {
      encoding: 'utf8',
    });
    assert.match(out, /dry-run/);
    assert.doesNotMatch(out, new RegExp(TEST_TOKEN));

    assert.ok(fs.existsSync(bin));
    assert.ok(fs.existsSync(tokenFile));
  });

  it('rerunning uninstall is idempotent', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-uninstall-idem-'));
    stagedInstall(root);

    execFileSync(uninstallSh, ['--install-root', root], { encoding: 'utf8' });
    assert.doesNotThrow(() =>
      execFileSync(uninstallSh, ['--install-root', root], { encoding: 'utf8' }),
    );
  });

  it('rejects relative --install-root and does not remove workspace files', () => {
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-uninstall-rel-'));
    const decoyBin = path.join(workDir, 'usr/local/bin/astranull-agent.mjs');
    fs.mkdirSync(path.dirname(decoyBin), { recursive: true });
    fs.writeFileSync(decoyBin, 'decoy-agent-artifact', 'utf8');

    assert.throws(
      () =>
        execFileSync(uninstallSh, ['--install-root', '.'], {
          encoding: 'utf8',
          cwd: workDir,
        }),
      (err) => err.status === 1,
    );

    assert.equal(fs.readFileSync(decoyBin, 'utf8'), 'decoy-agent-artifact');
  });
});