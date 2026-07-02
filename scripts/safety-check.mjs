import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const IMPL_DIRS = ['src', 'agents', 'apps/web', 'scripts', 'workers'];

const WAVE1_SERVICE_FILES = [
  'src/services/cvePipeline.mjs',
  'src/services/externalDiscovery.mjs',
  'src/services/supplyChainRisk.mjs',
  'src/persistence/postgres/cvePipelineServiceAdapters.mjs',
  'src/persistence/postgres/externalDiscoveryServiceAdapters.mjs',
  'src/persistence/postgres/supplyChainRiskServiceAdapters.mjs',
];

const FORBIDDEN = [
  /hping3/i,
  /loic/i,
  /botnet/i,
  /amplification_attack/i,
  /spoofed?_?flood/i,
  /traffic_generator/i,
  /ddos[_-]?script/i,
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

const WAVE1_FORBIDDEN_FIELD_LEAKS = [
  /\b(exploit_code|exploit_payload|attack_script|poc_code|raw_page_body|html_content|page_source|dns_zone_file|raw_response_body)\s*:/i,
  /\b(acquire_resource|auto_claim|dns_modify|modify_dns|create_account|register_domain)\s*:/i,
];

function walk(dir, files = []) {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, files);
    else if (/\.(mjs|js)$/.test(name) && !name.endsWith('safety-check.mjs')) files.push(p);
  }
  return files;
}

function scanFile(file, patterns, label) {
  let hits = 0;
  const text = readFileSync(file, 'utf8');
  for (const pattern of patterns) {
    if (pattern.test(text)) {
      console.error(`safety: ${label} ${pattern} in ${file}`);
      hits += 1;
    }
  }
  return hits;
}

let hits = 0;
for (const d of IMPL_DIRS) {
  const full = path.join(ROOT, d);
  try {
    for (const file of walk(full)) {
      hits += scanFile(file, FORBIDDEN, 'forbidden pattern');
    }
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
}

for (const rel of WAVE1_SERVICE_FILES) {
  const file = path.join(ROOT, rel);
  if (!existsSync(file)) {
    console.error(`safety: missing required wave1 service file ${rel}`);
    hits += 1;
    continue;
  }
  hits += scanFile(file, FORBIDDEN, 'forbidden pattern');
  hits += scanFile(file, WAVE1_FORBIDDEN_FIELD_LEAKS, 'forbidden field leak');
}

if (hits > 0) process.exit(1);
console.log('safety-check: ok');