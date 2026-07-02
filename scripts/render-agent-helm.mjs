#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const AGENT_HELM_CHART_DIR = path.join(ROOT, 'agents/linux/helm');

export function isHelmAvailable() {
  const result = spawnSync('helm', ['version', '--short'], { encoding: 'utf8' });
  return result.status === 0;
}

export function buildHelmTemplateCommand(options = {}) {
  const chartDir = options.chartDir ?? AGENT_HELM_CHART_DIR;
  const releaseName = options.releaseName ?? 'astranull-agent';
  const args = ['template', releaseName, chartDir, '--namespace', options.namespace ?? 'astranull'];
  const sets = options.sets ?? {};
  for (const [key, value] of Object.entries(sets)) {
    args.push('--set', `${key}=${value}`);
  }
  if (options.valuesFile) {
    args.push('-f', options.valuesFile);
  }
  return { cmd: 'helm', args };
}

export function renderAgentHelmManifests(options = {}) {
  if (!isHelmAvailable()) {
    return { ok: false, reason: 'helm_not_available', manifests: null, stdout: null };
  }
  const command = buildHelmTemplateCommand(options);
  const result = spawnSync(command.cmd, command.args, { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || '').trim();
    throw new Error(`helm template failed${detail ? `: ${detail}` : ''}`);
  }
  return {
    ok: true,
    reason: null,
    manifests: splitYamlDocuments(result.stdout),
    stdout: result.stdout,
  };
}

export function splitYamlDocuments(text) {
  return text
    .split(/^---\s*$/m)
    .map((chunk) => chunk.trim())
    .filter(Boolean);
}

export function loadHelmValues(chartDir = AGENT_HELM_CHART_DIR) {
  const valuesPath = path.join(chartDir, 'values.yaml');
  return fs.readFileSync(valuesPath, 'utf8');
}

export function loadHelmTemplates(chartDir = AGENT_HELM_CHART_DIR) {
  const templatesDir = path.join(chartDir, 'templates');
  const files = fs.readdirSync(templatesDir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  const out = {};
  for (const file of files) {
    out[file] = fs.readFileSync(path.join(templatesDir, file), 'utf8');
  }
  return out;
}

export function assertHelmTemplateSecurity(templates) {
  const issues = [];
  const combined = Object.values(templates).join('\n');
  if (!/runAsNonRoot:\s*true/m.test(combined)) {
    issues.push('templates must set runAsNonRoot: true');
  }
  if (!/runAsUser:\s*10001/m.test(combined)) {
    issues.push('templates must run as UID 10001');
  }
  if (!/ASTRANULL_BOOTSTRAP_TOKEN_FILE/m.test(combined)) {
    issues.push('templates must mount bootstrap token via ASTRANULL_BOOTSTRAP_TOKEN_FILE');
  }
  if (/privileged:\s*true/m.test(combined)) {
    issues.push('templates must not enable privileged mode');
  }
  if (/value:\s*["']?<BOOTSTRAP_TOKEN>/m.test(combined)) {
    issues.push('templates must not embed literal bootstrap token placeholders in env values');
  }
  if (!/hostPath:/m.test(combined) || !/persistentVolumeClaim:/m.test(combined)) {
    issues.push('templates must support persistent agent identity storage');
  }
  return { ok: issues.length === 0, issues };
}
