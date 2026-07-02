#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_DOCKERFILE = 'agents/linux/Dockerfile';
const DEFAULT_CONTEXT = 'agents/linux';
const DEFAULT_IMAGE = 'astranull-agent:local';
const DEFAULT_OUT = 'output/agent-container-evidence.json';

const FORBIDDEN_DOCKERFILE_PATTERNS = [
  /\bCOPY\b.*bootstrap/i,
  /\bENV\b.*ASTRANULL_BOOTSTRAP_TOKEN=/i,
  /\bARG\b.*bootstrap/i,
  /host\.docker\.internal/i,
];

export function validateAgentDockerfile(content) {
  const issues = [];
  if (!/\bUSER\s+astranull\b/m.test(content)) {
    issues.push('Dockerfile must run as non-root user astranull');
  }
  if (!/\bCOPY\b.*astranull-agent\.mjs/m.test(content)) {
    issues.push('Dockerfile must copy only astranull-agent.mjs');
  }
  for (const pattern of FORBIDDEN_DOCKERFILE_PATTERNS) {
    if (pattern.test(content)) {
      issues.push(`Dockerfile contains forbidden pattern: ${pattern}`);
    }
  }
  return { ok: issues.length === 0, issues };
}

export function parseArgs(argv = []) {
  const opts = {
    image: DEFAULT_IMAGE,
    dockerfile: DEFAULT_DOCKERFILE,
    context: DEFAULT_CONTEXT,
    out: DEFAULT_OUT,
    skipBuild: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--image') opts.image = next();
    else if (arg === '--dockerfile') opts.dockerfile = next();
    else if (arg === '--context') opts.context = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--skip-build') opts.skipBuild = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}

export function buildAgentDockerBuildCommand(opts) {
  return {
    cmd: 'docker',
    args: [
      'build',
      '--pull',
      '--label',
      'org.opencontainers.image.title=AstraNull Agent',
      '-f',
      opts.dockerfile,
      '-t',
      opts.image,
      opts.context,
    ],
  };
}

export function buildAgentDockerInspectCommand(opts) {
  return {
    cmd: 'docker',
    args: ['image', 'inspect', opts.image, '--format', '{{json .}}'],
  };
}

export function buildAgentImageVerifyCommand(image) {
  const script = [
    'set -e',
    'uid="$(id -u)"',
    'test "$uid" = "10001"',
    'test -f /opt/astranull/astranull-agent.mjs',
    '! test -f /var/lib/astranull/bootstrap-token',
    'count="$(find /opt/astranull -mindepth 1 -maxdepth 1 | wc -l | tr -d " ")"',
    'test "$count" = "1"',
  ].join(' && ');
  return {
    cmd: 'docker',
    args: ['run', '--rm', '--entrypoint', 'sh', image, '-c', script],
  };
}

export function createAgentContainerEvidenceManifest(input) {
  return {
    schema_version: 1,
    artifact_type: 'agent_container',
    created_at: input.createdAt ?? new Date().toISOString(),
    image: input.image ?? null,
    dockerfile: input.dockerfile ?? null,
    context: input.context ?? null,
    image_id: input.imageId ?? null,
    repo_digests: Array.isArray(input.repoDigests) ? input.repoDigests.map(String) : [],
    verify_status: input.verifyStatus ?? 'not_run',
    verify_summary: input.verifySummary ?? null,
    caveats: [
      'Manifest records local agent image build/inspect/verify evidence only.',
      'Production promotion still requires customer registry publish, image signing, enrollment credential custody, and staging canary validation.',
    ],
  };
}

function runCommand(command, label) {
  const result = spawnSync(command.cmd, command.args, {
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    throw new Error(`${label} failed${detail ? `: ${detail}` : ''}`);
  }
  return result.stdout ?? '';
}

function parseInspectJson(stdout) {
  const parsed = JSON.parse(stdout);
  return Array.isArray(parsed) ? parsed[0] : parsed;
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/agent-container-evidence.mjs [--image name] [--dockerfile path] [--context path] [--out file] [--skip-build]',
    );
    return 0;
  }

  const dockerfilePath = path.resolve(ROOT, opts.dockerfile);
  const dockerfileText = fs.readFileSync(dockerfilePath, 'utf8');
  const dockerfileCheck = validateAgentDockerfile(dockerfileText);
  if (!dockerfileCheck.ok) {
    throw new Error(`Dockerfile validation failed: ${dockerfileCheck.issues.join('; ')}`);
  }

  if (!opts.skipBuild) {
    runCommand(buildAgentDockerBuildCommand(opts), 'docker build');
  }

  const inspect = parseInspectJson(runCommand(buildAgentDockerInspectCommand(opts), 'docker image inspect'));

  let verifyStatus = 'not_run';
  let verifySummary = null;
  try {
    runCommand(buildAgentImageVerifyCommand(opts.image), 'agent image verify');
    verifyStatus = 'passed';
  } catch (err) {
    verifyStatus = 'failed';
    verifySummary = { error: err.message };
    throw err;
  }

  const manifest = createAgentContainerEvidenceManifest({
    ...opts,
    imageId: inspect.Id,
    repoDigests: inspect.RepoDigests ?? [],
    verifyStatus,
    verifySummary,
  });
  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`agent-container-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`agent-container-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}