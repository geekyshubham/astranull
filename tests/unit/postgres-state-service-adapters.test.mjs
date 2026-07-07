import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  POSTGRES_STATE_SERVICE_METHODS,
  STATE_AGENT_CONTROL_REPOSITORY_METHODS,
  STATE_CORE_CATALOG_REPOSITORY_METHODS,
  STATE_HIGH_SCALE_REPOSITORY_METHODS,
  STATE_KILL_SWITCH_REPOSITORY_METHODS,
  STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  createPostgresStateServices,
} from '../../src/persistence/postgres/stateServiceAdapters.mjs';
import { ARTIFACT_PROOF_FIELDS, REQUIRED_ARTIFACT_TYPES } from '../../src/lib/highScalePolicy.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const STATE_ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/stateServiceAdapters.mjs'),
  'utf8',
);

const FIXED_NOW = new Date('2026-06-15T12:00:00.000Z');
const RECENT_TS = '2026-06-10T10:00:00.000Z';

function stubRepositories(overrides = {}) {
  const groups = overrides.groups ?? [{ id: 'tg_1', name: 'Edge', tenant_id: 'ten_demo' }];
  const agents = overrides.agents ?? [
    {
      id: 'agt_1',
      tenant_id: 'ten_demo',
      status: 'online',
      target_group_id: 'tg_1',
    },
  ];
  const runs = overrides.runs ?? [
    {
      id: 'run_1',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      status: 'verdicted',
      created_at: RECENT_TS,
      completed_at: RECENT_TS,
    },
  ];
  const findings = overrides.findings ?? [{ id: 'find_1', tenant_id: 'ten_demo', status: 'open' }];
  const evidence = overrides.evidence ?? [
    { id: 'ev_1', tenant_id: 'ten_demo', test_run_id: 'run_1', created_at: RECENT_TS },
  ];
  const events = overrides.events ?? [
    {
      id: 'evt_1',
      tenant_id: 'ten_demo',
      test_run_id: 'run_1',
      signal_type: 'agent_observation',
      timestamp: RECENT_TS,
    },
  ];
  const verdict = overrides.verdict ?? {
    id: 'ver_1',
    tenant_id: 'ten_demo',
    test_run_id: 'run_1',
    created_at: RECENT_TS,
  };
  const highScaleRequests = overrides.highScaleRequests ?? [];
  const killSwitchRecord = overrides.killSwitchRecord ?? {
    tenant_id: 'ten_demo',
    active: false,
    reason: null,
    updated_at: null,
    updated_by: null,
  };

  const coreCatalog = {
    listTargetGroups: async () => groups,
  };
  const agentControl = {
    listAgents: async () => agents,
  };
  const validationEvidence = {
    listTestRuns: async (_ctx, options) => {
      assert.equal(options.limit, 500);
      return runs;
    },
    listEvidence: async (_ctx, options) => {
      assert.equal(options.limit, 500);
      return evidence;
    },
    listFindings: async () => findings,
    getVerdictForRun: async (_ctx, runId) => (runId === 'run_1' ? verdict : null),
    listRunEvents: async (_ctx, runId, options) => {
      assert.equal(options.limit, 1000);
      return runId === 'run_1' ? events : [];
    },
  };
  const highScale = {
    listHighScaleRequests: async () => highScaleRequests,
  };
  const killSwitch = {
    getKillSwitchRecord: async () => killSwitchRecord,
  };

  return { coreCatalog, agentControl, validationEvidence, highScale, killSwitch };
}

function acceptedAuthorizationArtifacts() {
  return REQUIRED_ARTIFACT_TYPES.map((type) => ({
    id: `art_${type}`,
    type,
    status: 'accepted',
    approval_reference: 'APPROVED-1',
    approver: 'Security Owner',
    valid_window: {
      window_start: '2026-06-01T00:00:00.000Z',
      window_end: '2026-08-01T00:00:00.000Z',
    },
    emergency_contacts: [{ name: 'SOC Lead', phone: '+15555550100' }],
    abort_criteria: {
      stop_on_customer_request: true,
      stop_on_service_health_degradation: true,
    },
    approved_scenario_families: ['governed_readiness'],
    max_rate: 'bounded-by-soc-plan',
    max_duration_minutes: 30,
    proof_fields: ARTIFACT_PROOF_FIELDS[type] ?? [],
  }));
}

describe('postgres state service adapter', () => {
  it('exposes getState service method contract', () => {
    assert.deepEqual(POSTGRES_STATE_SERVICE_METHODS, ['getState']);
    assert.ok(STATE_CORE_CATALOG_REPOSITORY_METHODS.includes('listTargetGroups'));
    assert.ok(STATE_AGENT_CONTROL_REPOSITORY_METHODS.includes('listAgents'));
    assert.ok(STATE_HIGH_SCALE_REPOSITORY_METHODS.includes('listHighScaleRequests'));
    assert.ok(STATE_KILL_SWITCH_REPOSITORY_METHODS.includes('getKillSwitchRecord'));
    for (const method of [
      'listTestRuns',
      'getVerdictForRun',
      'listRunEvents',
      'listEvidence',
      'listFindings',
    ]) {
      assert.ok(STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS.includes(method), method);
    }
  });

  it('throws when required repositories or methods are missing', () => {
    assert.throws(() => createPostgresStateServices({}), /coreCatalog/);
    const partial = stubRepositories();
    delete partial.agentControl.listAgents;
    assert.throws(
      () => createPostgresStateServices(partial),
      /agentControl\.listAgents/,
    );
    const noHighScale = stubRepositories();
    delete noHighScale.highScale.listHighScaleRequests;
    assert.throws(
      () => createPostgresStateServices(noHighScale),
      /highScale\.listHighScaleRequests/,
    );
    const noKillSwitch = stubRepositories();
    delete noKillSwitch.killSwitch.getKillSwitchRecord;
    assert.throws(
      () => createPostgresStateServices(noKillSwitch),
      /killSwitch\.getKillSwitchRecord/,
    );
  });

  it('does not import dev store or dev readiness modules', () => {
    assert.equal(/\bgetStore\b/.test(STATE_ADAPTER_SOURCE), false);
    assert.equal(/\bcomputeReadiness\b/.test(STATE_ADAPTER_SOURCE), false);
    assert.equal(/from\s+['"].*\/services\//.test(STATE_ADAPTER_SOURCE), false);
  });

  it('returns dashboard aggregate with evidence-backed readiness and repository-backed SOC state', async () => {
    const repositories = stubRepositories({
      highScaleRequests: [{ id: 'hs_1', tenant_id: 'ten_demo', state: 'submitted', artifacts: [] }],
      killSwitchRecord: {
        tenant_id: 'ten_demo',
        active: true,
        reason: 'incident',
        updated_at: '2026-06-15T11:00:00.000Z',
        updated_by: 'soc_1',
        secret_note: 'do not expose',
      },
      runs: [
        {
          id: 'run_5',
          tenant_id: 'ten_demo',
          target_group_id: 'tg_1',
          status: 'verdicted',
          created_at: '2026-06-14T00:00:00.000Z',
        },
        {
          id: 'run_4',
          tenant_id: 'ten_demo',
          target_group_id: 'tg_1',
          status: 'verdicted',
          created_at: '2026-06-13T00:00:00.000Z',
        },
        {
          id: 'run_3',
          tenant_id: 'ten_demo',
          target_group_id: 'tg_1',
          status: 'verdicted',
          created_at: '2026-06-12T00:00:00.000Z',
        },
        {
          id: 'run_2',
          tenant_id: 'ten_demo',
          target_group_id: 'tg_1',
          status: 'verdicted',
          created_at: '2026-06-11T00:00:00.000Z',
        },
        {
          id: 'run_1',
          tenant_id: 'ten_demo',
          target_group_id: 'tg_1',
          status: 'verdicted',
          created_at: RECENT_TS,
        },
        {
          id: 'run_old',
          tenant_id: 'ten_demo',
          target_group_id: 'tg_1',
          status: 'verdicted',
          created_at: '2026-05-01T00:00:00.000Z',
        },
      ],
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const payload = await state.getState(ctx);

    assert.equal(payload.tenant_id, 'ten_demo');
    assert.equal(payload.target_groups, 1);
    assert.equal(payload.agents_online, 1);
    assert.equal(payload.open_findings, 1);
    assert.equal(payload.recent_runs.length, 5);
    assert.equal(payload.recent_runs[0].id, 'run_5');
    assert.equal(payload.high_scale_requests, 1);
    assert.equal(payload.high_scale_status, 'degraded');
    assert.deepEqual(payload.kill_switch, {
      tenant_id: 'ten_demo',
      active: true,
      reason: 'incident',
      updated_at: '2026-06-15T11:00:00.000Z',
      updated_by: 'soc_1',
    });

    assert.ok(payload.readiness.score >= 0);
    const factorKeys = payload.readiness.factors.map((f) => f.key);
    assert.ok(factorKeys.includes('coverage'));
    assert.ok(factorKeys.includes('agent_placement'));
    assert.ok(factorKeys.includes('verdicts'));
    assert.ok(factorKeys.includes('evidence_freshness'));
    const soc = payload.readiness.factors.find((f) => f.key === 'soc_readiness');
    assert.equal(soc.score, 10);
    assert.match(soc.detail, /Kill switch state recorded/);
    assert.match(soc.detail, /Other request\(s\) still pending gates/);
    assert.equal(payload.readiness.persistence, 'postgres');
  });

  it('reports pending high-scale gates without awarding SOC readiness credit', async () => {
    const repositories = stubRepositories({
      highScaleRequests: [
        {
          id: 'hs_pending',
          tenant_id: 'ten_demo',
          state: 'under_review',
          artifacts: [{ id: 'art_auth', type: 'customer_authorization', status: 'accepted' }],
          soc_approvals: [{ user_id: 'soc_a', at: RECENT_TS }],
        },
      ],
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });
    const soc = payload.readiness.factors.find((f) => f.key === 'soc_readiness');
    assert.equal(payload.high_scale_requests, 1);
    assert.equal(payload.high_scale_status, 'pending');
    assert.equal(soc.score, 0);
    assert.match(soc.detail, /Pending high-scale workflow gates remain/);
    assert.match(soc.detail, /SOC approvals 1\/2/);
    assert.match(soc.detail, /missing accepted artifacts/);
  });

  it('awards SOC readiness for accepted authorization pack and two distinct approvers', async () => {
    const repositories = stubRepositories({
      highScaleRequests: [
        {
          id: 'hs_ready',
          tenant_id: 'ten_demo',
          state: 'approved',
          artifacts: acceptedAuthorizationArtifacts(),
          soc_approvals: [
            { user_id: 'soc_a', at: RECENT_TS },
            { user_id: 'soc_b', at: RECENT_TS },
          ],
        },
      ],
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });
    const soc = payload.readiness.factors.find((f) => f.key === 'soc_readiness');
    assert.equal(soc.score, 10);
    assert.match(soc.detail, /authorization pack accepted/);
    assert.match(soc.detail, /2 SOC approver/);
  });

  it('awards SOC readiness for kill-switch evidence and returns only safe fields', async () => {
    const repositories = stubRepositories({
      killSwitchRecord: {
        tenant_id: 'ten_demo',
        active: false,
        reason: 'drill',
        updated_at: '2026-06-15T11:30:00.000Z',
        updated_by: 'soc_2',
        raw_operator_note: 'sensitive',
      },
    });
    const state = createPostgresStateServices(repositories, { now: () => FIXED_NOW });
    const payload = await state.getState({ tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' });
    const soc = payload.readiness.factors.find((f) => f.key === 'soc_readiness');
    assert.equal(soc.score, 10);
    assert.match(soc.detail, /Kill switch state recorded/);
    assert.deepEqual(Object.keys(payload.kill_switch).sort(), [
      'active',
      'reason',
      'tenant_id',
      'updated_at',
      'updated_by',
    ]);
    assert.equal(payload.kill_switch.reason, 'drill');
  });
});
