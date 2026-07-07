import { Target } from 'lucide-react';
import type { CSSProperties } from 'react';
import { Fragment } from 'react';
import { Badge } from '../ui/badge';
import { EmptyState } from '../ui/empty-state';

const families = [
  { label: 'Origin', keys: ['origin'] },
  { label: 'L3/L4', keys: ['l3_l4', 'l3/l4', 'layer_3_4'] },
  { label: 'DNS', keys: ['dns'] },
  { label: 'L7/API', keys: ['l7_api', 'l7/api', 'application', 'api'] },
  { label: 'Protocol', keys: ['protocol', 'tls', 'http2', 'http3'] }
];

type VectorHeatmapProps = {
  checks: Record<string, unknown>[];
  targetGroups: Record<string, unknown>[];
  testPolicies: Record<string, unknown>[];
  runs: Record<string, unknown>[];
  evidence: Record<string, unknown>[];
};

function stringValue(item: Record<string, unknown>, key: string) {
  const value = item[key];
  return value === undefined || value === null ? '' : String(value).toLowerCase();
}

function nestedString(item: Record<string, unknown>, key: string, nestedKey: string) {
  const value = item[key];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return '';
  const nested = (value as Record<string, unknown>)[nestedKey];
  return nested === undefined || nested === null ? '' : String(nested);
}

function itemCheckId(item: Record<string, unknown>) {
  return String(item.check_id ?? item.checkId ?? nestedString(item, 'check', 'check_id') ?? '');
}

function itemTargetGroupId(item: Record<string, unknown>) {
  return String(item.target_group_id ?? item.targetGroupId ?? nestedString(item, 'target_group', 'id') ?? '');
}

function checkMatchesFamily(check: Record<string, unknown>, family: { keys: string[] }) {
  const haystack = [
    stringValue(check, 'vector_family'),
    stringValue(check, 'category'),
    stringValue(check, 'name'),
    stringValue(check, 'check_id')
  ].join(' ');
  return family.keys.some((key) => haystack.includes(key));
}

type FamilyCoverageStatus = 'evidence' | 'run' | 'policy' | 'none' | 'no-data';

type FamilyCoverage = {
  status: FamilyCoverageStatus;
  policyCount: number;
  runCount: number;
  evidenceCount: number;
};

function familyCoverage({
  checkIds,
  groupId,
  testPolicies,
  runs,
  evidence
}: {
  checkIds: Set<string>;
  groupId: string;
  testPolicies: Record<string, unknown>[];
  runs: Record<string, unknown>[];
  evidence: Record<string, unknown>[];
}): FamilyCoverage {
  // No declared group or no checks mapped to this vector family: nothing real to score.
  if (!groupId || checkIds.size === 0) {
    return { status: 'no-data', policyCount: 0, runCount: 0, evidenceCount: 0 };
  }
  const policyCount = testPolicies.filter((policy) => itemTargetGroupId(policy) === groupId && checkIds.has(itemCheckId(policy))).length;
  const runCount = runs.filter((run) => itemTargetGroupId(run) === groupId && checkIds.has(itemCheckId(run))).length;
  const evidenceCount = evidence.filter((record) => itemTargetGroupId(record) === groupId && checkIds.has(itemCheckId(record))).length;
  let status: FamilyCoverageStatus = 'none';
  if (evidenceCount > 0) status = 'evidence';
  else if (runCount > 0) status = 'run';
  else if (policyCount > 0) status = 'policy';
  return { status, policyCount, runCount, evidenceCount };
}

const COVERAGE_TONE: Record<FamilyCoverageStatus, string> = {
  evidence: 'success',
  run: 'warn',
  policy: 'warn',
  none: 'danger',
  'no-data': 'muted'
};

const COVERAGE_LABEL: Record<FamilyCoverageStatus, string> = {
  evidence: 'Evidence',
  run: 'Run',
  policy: 'Policy',
  none: 'No record',
  'no-data': 'No data'
};

function coverageTitle(coverage: FamilyCoverage) {
  if (coverage.status === 'no-data') {
    return 'No checks mapped to this vector family for this target group.';
  }
  return `${coverage.evidenceCount} evidence · ${coverage.runCount} runs · ${coverage.policyCount} policies`;
}

export function VectorHeatmap({ checks, targetGroups, testPolicies, runs, evidence }: VectorHeatmapProps) {
  const groups = targetGroups.slice(0, 5);

  if (groups.length === 0) {
    return (
      <EmptyState
        icon={Target}
        title="No declared target groups yet."
        body="Declare target groups before coverage can be calculated from policies, runs, or evidence."
      />
    );
  }

  const gridStyle = { '--heatmap-cols': families.length } as CSSProperties;

  return (
    <div className="heatmap">
      <div className="heatmap-grid heatmap-grid--variable" style={gridStyle}>
        <span className="heatmap-head">Target group</span>
        {families.map((family) => (
          <span className="heatmap-head" key={family.label}>{family.label}</span>
        ))}
        {groups.map((group, groupIndex) => (
          <Fragment key={String(group.id ?? groupIndex)}>
            <strong className="heatmap-name">
              {String(group.name ?? group.id ?? 'Declared group')}
            </strong>
            {families.map((family) => {
              const groupId = String(group.id ?? '');
              const familyCheckIds = new Set(
                checks
                  .filter((check) => checkMatchesFamily(check, family))
                  .map((check) => String(check.check_id ?? check.id ?? ''))
                  .filter(Boolean)
              );
              const score = familyCoverage({ checkIds: familyCheckIds, groupId, testPolicies, runs, evidence });
              const tone = COVERAGE_TONE[score.status];
              return (
                <span key={`${groupIndex}-${family.label}`} className={`heatmap-cell heatmap-${tone}`} title={coverageTitle(score)}>
                  {COVERAGE_LABEL[score.status]}
                </span>
              );
            })}
          </Fragment>
        ))}
      </div>
      <div className="heatmap-legend">
        <Badge tone="success">Evidence</Badge>
        <Badge tone="warn">Policy/run</Badge>
        <Badge tone="danger">No record</Badge>
        <Badge tone="muted">No data</Badge>
      </div>
    </div>
  );
}
