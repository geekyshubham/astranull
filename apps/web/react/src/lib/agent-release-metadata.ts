import { pickReleaseEvidenceCustodyUri } from './release-evidence';
import type { DataItem } from './types';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getNestedItem(item: DataItem | null | undefined, path: string[]) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return null;
    current = (current as DataItem)[key];
  }
  return current && typeof current === 'object' && !Array.isArray(current) ? current as DataItem : null;
}

export type AgentReleaseMetadata = {
  version: string;
  digest: string;
  cosignStatus: string;
  sbomUri: string;
  provenanceUri: string;
  packageName: string;
};

export function resolveAgentReleaseMetadata(releaseEvidence: DataItem[]): AgentReleaseMetadata {
  const sbomRecord = releaseEvidence.find((item) => getString(item, ['kind']) === 'agent_sbom_provenance') ?? null;
  const matrixRecord = releaseEvidence.find((item) => getString(item, ['kind']) === 'agent_install_matrix') ?? null;
  const evidence = sbomRecord?.evidence && typeof sbomRecord.evidence === 'object'
    ? sbomRecord.evidence as DataItem
    : sbomRecord;
  const pkg = getNestedItem(evidence, ['package']) ?? {};
  const sbom = getNestedItem(evidence, ['sbom']) ?? {};
  const provenance = getNestedItem(evidence, ['provenance']) ?? {};
  const version = getString(matrixRecord, ['release_id'], getString(evidence, ['release_id'], getString(pkg, ['version'], '—')));
  const digest = getString(pkg, ['sha256'], '—');
  const cosignStatus = getString(evidence, ['cosign_status', 'signature_status'], sbomRecord ? 'metadata recorded' : '—');
  return {
    version,
    digest: digest !== '—' ? `sha256:${digest.slice(0, 12)}…` : '—',
    cosignStatus,
    sbomUri: pickReleaseEvidenceCustodyUri(sbom) ?? getString(sbom, ['evidence_uri'], '—'),
    provenanceUri: pickReleaseEvidenceCustodyUri(provenance) ?? getString(provenance, ['evidence_uri'], '—'),
    packageName: getString(pkg, ['name'], 'astranull-agent')
  };
}