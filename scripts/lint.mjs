import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const SCAN_DIRS = ['src', 'apps/web', 'agents/linux', 'tests', 'scripts', 'workers'];

function walk(dir, files = []) {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, files);
    else if (/\.(mjs|js|html|css)$/.test(name)) files.push(p);
  }
  return files;
}

let errors = 0;
for (const d of SCAN_DIRS) {
  const full = path.join(ROOT, d);
  try {
    for (const file of walk(full)) {
      const text = readFileSync(file, 'utf8');
      if (text.includes('\t')) {
        console.error(`lint: tab character in ${file}`);
        errors += 1;
      }
      if (/\r\n/.test(text)) {
        console.error(`lint: CRLF line endings in ${file}`);
        errors += 1;
      }
    }
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
}

if (errors > 0) {
  process.exit(1);
}
console.log('lint: ok');