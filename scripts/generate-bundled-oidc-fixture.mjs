#!/usr/bin/env node
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(__dirname, '..', 'ops', 'staging');
mkdirSync(outDir, { recursive: true });

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = publicKey.export({ format: 'jwk' });
publicJwk.kid = 'hosted-staging-rsa-1';
publicJwk.alg = 'RS256';
publicJwk.use = 'sig';

const fixture = {
  issuer_suffix: '/staging-oidc',
  audience: 'astranull-hosted-staging',
  kid: 'hosted-staging-rsa-1',
  public_jwk: publicJwk,
  private_key_pem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  note: 'STAGING-ONLY fixture IdP — not for customer secrets or production tenant data',
};

writeFileSync(path.join(outDir, 'bundled-oidc-fixture.json'), `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`wrote ${path.join(outDir, 'bundled-oidc-fixture.json')}`);