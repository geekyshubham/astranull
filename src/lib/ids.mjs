import { randomBytes } from 'node:crypto';

const PREFIX = {
  tenant: 'ten',
  env: 'env',
  user: 'usr',
  tg: 'tg',
  target: 'tgt',
  token: 'btok',
  agent: 'agt',
  run: 'run',
  event: 'evt',
  finding: 'fnd',
  report: 'rpt',
  hs: 'hsr',
  job: 'job',
  evidence: 'evd',
  agentUpdateRelease: 'aup',
  agentUpdateStatus: 'aus',
  agentUpdateTrustKey: 'autk',
};

export function newId(kind) {
  const p = PREFIX[kind] ?? 'id';
  return `${p}_${randomBytes(8).toString('hex')}`;
}