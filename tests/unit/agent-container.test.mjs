import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  buildAgentDockerBuildCommand,
  buildAgentImageVerifyCommand,
  createAgentContainerEvidenceManifest,
  parseArgs,
  validateAgentDockerfile,
} from '../../scripts/agent-container-evidence.mjs';

const REPO_ROOT = process.cwd();
const AGENT_DOCKERFILE = path.join(REPO_ROOT, 'agents/linux/Dockerfile');
const AGENT_DOCKERIGNORE = path.join(REPO_ROOT, 'agents/linux/.dockerignore');

const SECRET_PATTERNS = [
  /ast_[A-Za-z0-9_-]{8,}/,
  /bootstrap[_-]?token/i,
];

function assertNoSecrets(text, label) {
  for (const pattern of SECRET_PATTERNS) {
    assert.doesNotMatch(text, pattern, `${label} must not contain secret-like content (${pattern})`);
  }
}

describe('agent container packaging', () => {
  it('validates Dockerfile enforces non-root user and single agent artifact', () => {
    const dockerfile = fs.readFileSync(AGENT_DOCKERFILE, 'utf8');
    const result = validateAgentDockerfile(dockerfile);
    assert.equal(result.ok, true, result.issues.join('; '));
    assert.match(dockerfile, /^USER astranull/m);
    assert.match(dockerfile, /COPY --chown=astranull:astranull astranull-agent\.mjs/);
    assert.doesNotMatch(dockerfile, /host\.docker\.internal/);
    assert.doesNotMatch(dockerfile, /\bENV\b.*ASTRANULL_BOOTSTRAP_TOKEN=/);
    assert.doesNotMatch(dockerfile, /\bCOPY\b.*bootstrap/i);
  });

  it('dockerignore excludes installer, helm, and systemd artifacts from image context', () => {
    const ignore = fs.readFileSync(AGENT_DOCKERIGNORE, 'utf8');
    assert.match(ignore, /^helm\//m);
    assert.match(ignore, /^install\.sh/m);
    assert.match(ignore, /^uninstall\.sh/m);
    assert.match(ignore, /^systemd\//m);
  });

  it('builds docker commands scoped to agents/linux context', () => {
    const opts = parseArgs(['--image', 'astranull-agent:test']);
    assert.deepEqual(buildAgentDockerBuildCommand(opts), {
      cmd: 'docker',
      args: [
        'build',
        '--pull',
        '--label',
        'org.opencontainers.image.title=AstraNull Agent',
        '-f',
        'agents/linux/Dockerfile',
        '-t',
        'astranull-agent:test',
        'agents/linux',
      ],
    });
    const verify = buildAgentImageVerifyCommand('astranull-agent:test');
    assert.equal(verify.cmd, 'docker');
    assert.equal(verify.args[0], 'run');
    assert.match(verify.args.join(' '), /id -u/);
    assert.match(verify.args.join(' '), /astranull-agent\.mjs/);
    assert.match(verify.args.join(' '), /bootstrap-token/);
  });

  it('creates agent container evidence manifest without secret dumps', () => {
    const manifest = createAgentContainerEvidenceManifest({
      createdAt: '2026-07-02T00:00:00.000Z',
      image: 'astranull-agent:test',
      dockerfile: 'agents/linux/Dockerfile',
      context: 'agents/linux',
      imageId: 'sha256:abc',
      repoDigests: ['registry.example/astranull-agent@sha256:def'],
      verifyStatus: 'passed',
    });
    assert.equal(manifest.artifact_type, 'agent_container');
    assert.equal(manifest.verify_status, 'passed');
    const blob = JSON.stringify(manifest);
    assertNoSecrets(blob, 'agent container evidence manifest');
    assert.match(blob, /customer registry publish/);
  });
});