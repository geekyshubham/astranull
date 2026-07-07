#!/usr/bin/env node
/**
 * FT-PROV-static — portal revamp no-hardcoded-values lint (docs/ux/17 §5.1).
 * Scans apps/web/react/src/pages and components for literals that must come from the DB.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const SCAN_ROOTS = [
  path.join(ROOT, 'apps/web/react/src/pages'),
  path.join(ROOT, 'apps/web/react/src/components'),
];
const STYLES_CSS = path.join(ROOT, 'apps/web/react/src/styles.css');

const ISO_DATE = /\b20\d{2}-\d{2}-\d{2}\b/;
const READINESS_PCT = /\b(\d{1,3})%\b/;
const READINESS_RATIO = /\b82\/100\b/;
const FINDINGS_COUNT_STRING = /\b\d+\s+(?:open|closed|accepted)\s+findings\b/i;
const JSX_LITERAL_NUMBER = />\s*(\d{1,6})\s*</;
const KPI_CLASS = /(?:kpi|stat|count|gauge)/i;
const HEX_COLOR = /#[0-9a-fA-F]{3,8}\b/g;

function walk(dir, files = []) {
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, files);
    else if (/\.(tsx|ts|jsx|js)$/.test(name)) files.push(full);
  }
  return files;
}

function stripTypeDeclarations(source) {
  return source.replace(
    /(?:export\s+)?type\s+\w+\s*=\s*[^;]+;/gs,
    '',
  );
}

function stripEnumDeclarations(source) {
  return source.replace(/enum\s+\w+\s*\{[\s\S]*?\}/g, '');
}

function lineContext(source, index) {
  const before = source.slice(0, index);
  const line = before.split('\n').length;
  const lines = source.split('\n');
  return { line, text: lines[line - 1] ?? '' };
}

function isAllowedContext(line) {
  if (/data-testid|aria-label|aria-labelledby|placeholder=|title=/.test(line)) return true;
  if (/\$\{/.test(line)) return true;
  if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) return true;
  return false;
}

function scanEmptyStateLiterals(source, file, errors) {
  const callPattern = /emptyStateFromApi\s*\(\s*\{[\s\S]*?\}\s*\)/g;
  for (const match of source.matchAll(callPattern)) {
    const block = match[0] ?? '';
    if (/empty_reason\s*:\s*['"`][^'"`]+['"`]/.test(block)
      || /getString\s*\([^)]*,\s*['"`][^'"`]+['"`]\s*\)/.test(block)) {
      const idx = match.index ?? 0;
      const ctx = lineContext(source, idx);
      errors.push({
        file,
        line: ctx.line,
        rule: 'empty-state-literal',
        detail: 'emptyStateFromApi must read copy from API meta only',
      });
    }
  }
}

function scanLoadingCopy(source, file, errors) {
  for (const match of source.matchAll(/<p[^>]*className=(?:"muted"|{'muted'})[^>]*>\s*Loading[^<]*<\/p>/g)) {
    const idx = match.index ?? 0;
    const ctx = lineContext(source, idx);
    errors.push({
      file,
      line: ctx.line,
      rule: 'loading-copy',
      detail: match[0].replace(/\s+/g, ' ').trim(),
    });
  }
}

function isJsxPercentageContext(line) {
  if (/<[^>]+>/.test(line)) return true;
  if (/(?:readiness|coverage|gauge|score|protected|underprotected)/i.test(line)) return true;
  return false;
}

function scanSourceFile(file, errors) {
  const raw = readFileSync(file, 'utf8');
  const source = stripEnumDeclarations(stripTypeDeclarations(raw));

  for (const match of source.matchAll(new RegExp(ISO_DATE.source, 'g'))) {
    const ctx = lineContext(source, match.index ?? 0);
    if (isAllowedContext(ctx.text)) continue;
    errors.push({ file, line: ctx.line, rule: 'iso-date', detail: match[0] });
  }

  for (const match of source.matchAll(new RegExp(READINESS_RATIO.source, 'g'))) {
    const ctx = lineContext(source, match.index ?? 0);
    errors.push({ file, line: ctx.line, rule: 'readiness-ratio', detail: match[0] });
  }

  for (const match of source.matchAll(new RegExp(READINESS_PCT.source, 'g'))) {
    const ctx = lineContext(source, match.index ?? 0);
    if (!isJsxPercentageContext(ctx.text)) continue;
    if (isAllowedContext(ctx.text)) continue;
    errors.push({ file, line: ctx.line, rule: 'readiness-percent', detail: match[0] });
  }

  for (const match of source.matchAll(new RegExp(FINDINGS_COUNT_STRING.source, 'g'))) {
    const ctx = lineContext(source, match.index ?? 0);
    if (isAllowedContext(ctx.text)) continue;
    errors.push({ file, line: ctx.line, rule: 'findings-count-string', detail: match[0] });
  }

  scanEmptyStateLiterals(source, file, errors);
  scanLoadingCopy(source, file, errors);

  const jsxBlocks = source.match(/<[^>]*className=(?:"[^"]*"|{`[^`]*`}|{'[^']*'})[^>]*>[\s\S]*?<\/[^>]+>/g) ?? [];
  for (const block of jsxBlocks) {
    if (!KPI_CLASS.test(block)) continue;
    const numberMatch = block.match(JSX_LITERAL_NUMBER);
    if (numberMatch) {
      const idx = source.indexOf(block);
      const ctx = lineContext(source, idx);
      errors.push({
        file,
        line: ctx.line,
        rule: 'kpi-literal-count',
        detail: numberMatch[1],
      });
    }
  }
}

function scanStylesCss(errors) {
  const source = readFileSync(STYLES_CSS, 'utf8');
  const rootMatch = source.match(/:root\s*\{[\s\S]*?\}/);
  const rootBlock = rootMatch?.[0] ?? '';
  const outsideRoot = rootMatch
    ? source.slice(0, rootMatch.index) + source.slice(rootMatch.index + rootBlock.length)
    : source;

  for (const match of outsideRoot.matchAll(HEX_COLOR)) {
    const ctx = lineContext(source, (rootMatch?.index ?? 0) + rootBlock.length + (match.index ?? 0));
    errors.push({ file: STYLES_CSS, line: ctx.line, rule: 'hex-outside-root', detail: match[0] });
  }
}

const errors = [];
for (const root of SCAN_ROOTS) {
  try {
    for (const file of walk(root)) scanSourceFile(file, errors);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
}

try {
  scanStylesCss(errors);
} catch (err) {
  if (err.code !== 'ENOENT') throw err;
}

if (errors.length > 0) {
  console.error('lint:portal: hardcoded value violations (FT-PROV-static)');
  for (const err of errors) {
    console.error(`  ${path.relative(ROOT, err.file)}:${err.line} [${err.rule}] ${err.detail}`);
  }
  process.exit(1);
}

console.log('lint:portal: ok (0 hardcoded portal values)');