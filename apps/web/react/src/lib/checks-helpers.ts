import type { DataItem } from './types';

export type CheckFamilyTabId =
  | 'all'
  | 'recommended'
  | 'origin-bypass'
  | 'l3l4'
  | 'dns'
  | 'l7api'
  | 'protocols'
  | 'high-scale'
  | 'custom';

export type CheckSafetyScopeId = 'all' | 'safe' | 'soc';

export const CHECK_SAFETY_SCOPE_TABS: { id: CheckSafetyScopeId; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'safe', label: 'Safe' },
  { id: 'soc', label: 'SOC' }
];

const RECOMMENDED_VECTOR_FAMILIES = new Set(['origin', 'path', 'l7', 'dns', 'l3_l4']);

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getNestedString(item: DataItem | null | undefined, path: string[], fallback = '') {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  if (current !== undefined && current !== null && current !== '') return String(current);
  return fallback;
}

export function isSocGatedCheck(check: DataItem) {
  const safetyClass = getString(check, ['safety_class'], '');
  return safetyClass === 'soc_gated' || safetyClass === 'soc_only';
}

export function isSafeCheck(check: DataItem) {
  return getString(check, ['safety_class']) === 'safe';
}

export function filterChecksBySafetyScope(checks: DataItem[], scope: CheckSafetyScopeId) {
  if (scope === 'safe') return checks.filter((check) => isSafeCheck(check));
  if (scope === 'soc') return checks.filter((check) => isSocGatedCheck(check));
  return checks;
}

function isOriginBypassCheck(check: DataItem) {
  const family = getString(check, ['vector_family']);
  if (family === 'origin') return true;
  const checkId = getString(check, ['check_id']);
  if (checkId.includes('origin_bypass') || checkId.includes('host_sni_bypass')) return true;
  const scenarioFamily = getNestedString(check, ['probe_profile', 'scenario_family']);
  return family === 'waf' && scenarioFamily === 'origin_bypass';
}

function isL7ApiCheck(check: DataItem) {
  const family = getString(check, ['vector_family']);
  return family === 'l7' || family === 'waf';
}

export function filterChecksByFamilyTab(checks: DataItem[], familyTab: CheckFamilyTabId) {
  if (familyTab === 'all') return checks;
  if (familyTab === 'custom') return [];
  if (familyTab === 'recommended') {
    const safe = checks.filter((check) => isSafeCheck(check));
    const starters = safe.filter((check) => RECOMMENDED_VECTOR_FAMILIES.has(getString(check, ['vector_family'])));
    return (starters.length ? starters : safe).slice(0, 20);
  }
  if (familyTab === 'origin-bypass') return checks.filter((check) => isOriginBypassCheck(check));
  if (familyTab === 'l3l4') return checks.filter((check) => getString(check, ['vector_family']) === 'l3_l4');
  if (familyTab === 'dns') return checks.filter((check) => getString(check, ['vector_family']) === 'dns');
  if (familyTab === 'l7api') return checks.filter((check) => isL7ApiCheck(check));
  if (familyTab === 'protocols') {
    return checks.filter((check) => ['protocol', 'tls'].includes(getString(check, ['vector_family'])));
  }
  if (familyTab === 'high-scale') return checks.filter((check) => isSocGatedCheck(check));
  return checks;
}

export function filterChecksCatalog(
  checks: DataItem[],
  familyTab: CheckFamilyTabId,
  safetyScope: CheckSafetyScopeId = 'all'
) {
  const scoped = filterChecksBySafetyScope(checks, safetyScope);
  return filterChecksByFamilyTab(scoped, familyTab);
}

export function countChecksBySafetyScope(checks: DataItem[]) {
  const safe = checks.filter((check) => isSafeCheck(check)).length;
  const soc = checks.filter((check) => isSocGatedCheck(check)).length;
  return {
    all: checks.length,
    safe,
    soc
  };
}