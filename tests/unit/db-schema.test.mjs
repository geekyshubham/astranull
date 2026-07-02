import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  TENANT_CONSISTENT_FK_CONSTRAINTS,
  validateDbSchema,
} from '../../scripts/validate-db-schema.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');

describe('db schema contract', () => {
  it('schema.sql and migrations satisfy validation loop contract', () => {
    const schemaSql = readFileSync(path.join(ROOT, 'db', 'schema.sql'), 'utf8');
    const migrationSqls = readdirSync(path.join(ROOT, 'db', 'migrations'))
      .filter((n) => n.endsWith('.sql'))
      .sort()
      .map((n) => readFileSync(path.join(ROOT, 'db', 'migrations', n), 'utf8'));

    const result = validateDbSchema({ schemaSql, migrationSqls });
    assert.equal(result.ok, true, result.errors.join('; '));
  });

  it('enforces tenants RLS, audit sequence uniqueness, and nullable event_id idempotency', () => {
    const schemaSql = readFileSync(path.join(ROOT, 'db', 'schema.sql'), 'utf8');
    assert.match(schemaSql, /ALTER TABLE tenants ENABLE ROW LEVEL SECURITY/);
    assert.match(schemaSql, /ALTER TABLE tenants FORCE ROW LEVEL SECURITY/);
    assert.match(
      schemaSql,
      /CREATE POLICY tenant_isolation_tenants ON tenants[\s\S]*?USING \(id = current_setting\('app\.tenant_id', true\)\)/m,
    );
    assert.match(schemaSql, /CREATE UNIQUE INDEX uniq_audit_tenant_sequence ON audit_logs\(tenant_id, sequence\)/);
    assert.match(
      schemaSql,
      /CREATE UNIQUE INDEX uniq_events_tenant_event_id ON events\(tenant_id, event_id\) WHERE event_id IS NOT NULL/,
    );
    assert.doesNotMatch(schemaSql, /CREATE TABLE events\b[\s\S]*?\bevent_id TEXT NOT NULL/m);
    assert.doesNotMatch(schemaSql, /CREATE TABLE events[\s\S]*?UNIQUE \(tenant_id, event_id\)/m);
  });

  it('fails validation when FORCE ROW LEVEL SECURITY is missing on tenant tables', () => {
    const schemaSql = readFileSync(path.join(ROOT, 'db', 'schema.sql'), 'utf8');
    const weakened = schemaSql.replace(
      /ALTER TABLE tenants FORCE ROW LEVEL SECURITY;\n/,
      '',
    );
    const result = validateDbSchema({ schemaSql: weakened, migrationSqls: [] });
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((e) => /FORCE ROW LEVEL SECURITY/.test(e)));
  });

  it('fails validation when a required tenant-consistent FK constraint is removed', () => {
    const schemaSql = readFileSync(path.join(ROOT, 'db', 'schema.sql'), 'utf8');
    const weakened = schemaSql.replace(
      /ALTER TABLE targets ADD CONSTRAINT fk_targets_target_group_tenant[\s\S]*?;\n/,
      '',
    );
    const result = validateDbSchema({ schemaSql: weakened, migrationSqls: [] });
    assert.equal(result.ok, false);
    assert.ok(
      result.errors.some((e) => /tenant_fk:fk_targets_target_group_tenant/.test(e)),
    );
    assert.ok(TENANT_CONSISTENT_FK_CONSTRAINTS.includes('fk_targets_target_group_tenant'));
    assert.ok(TENANT_CONSISTENT_FK_CONSTRAINTS.includes('fk_verdicts_target_tenant'));
    assert.ok(TENANT_CONSISTENT_FK_CONSTRAINTS.includes('fk_evidence_vault_related_event_tenant'));
  });

  it('includes production ledger tables, high-scale workflow columns, RLS, and composite FKs', () => {
    const schemaSql = readFileSync(path.join(ROOT, 'db', 'schema.sql'), 'utf8');
    const productionTables = [
      'service_accounts',
      'encrypted_secrets',
      'agent_update_trust_keys',
      'agent_update_releases',
      'agent_update_statuses',
      'high_scale_telemetry',
      'soc_reports',
      'notification_delivery_attempts',
    ];
    for (const table of productionTables) {
      assert.match(schemaSql, new RegExp(`CREATE TABLE ${table}\\b`, 'i'));
      assert.match(schemaSql, new RegExp(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`, 'i'));
      assert.match(
        schemaSql,
        new RegExp(
          `CREATE POLICY tenant_isolation_${table} ON ${table}[\\s\\S]*?tenant_id = current_setting\\('app\\.tenant_id', true\\)`,
          'm',
        ),
      );
    }
    assert.match(schemaSql, /CREATE TABLE high_scale_requests[\s\S]*?requested_window/m);
    assert.match(schemaSql, /CREATE TABLE high_scale_requests[\s\S]*?adapter_json/m);
    assert.match(schemaSql, /ADD CONSTRAINT fk_agent_update_statuses_release_tenant\b/);
    assert.match(schemaSql, /ADD CONSTRAINT fk_notification_delivery_attempts_event_tenant\b/);
    assert.match(schemaSql, /ADD CONSTRAINT notification_events_tenant_id_id_key UNIQUE \(tenant_id, id\)/);
    assert.match(schemaSql, /ADD CONSTRAINT agent_update_releases_tenant_id_id_key UNIQUE \(tenant_id, id\)/);
    assert.ok(TENANT_CONSISTENT_FK_CONSTRAINTS.includes('fk_soc_reports_high_scale_request_tenant'));
    assert.ok(TENANT_CONSISTENT_FK_CONSTRAINTS.includes('fk_high_scale_telemetry_high_scale_request_tenant'));
  });

  it('includes runtime shape parity for findings, verdicts parent key, and agent_jobs.type', () => {
    const schemaSql = readFileSync(path.join(ROOT, 'db', 'schema.sql'), 'utf8');
    const migrationSqls = readdirSync(path.join(ROOT, 'db', 'migrations'))
      .filter((n) => n.endsWith('.sql'))
      .sort()
      .map((n) => readFileSync(path.join(ROOT, 'db', 'migrations', n), 'utf8'));
    const combinedMigration = migrationSqls.join('\n');

    assert.match(schemaSql, /CREATE TABLE findings[\s\S]*?verdict_id TEXT/m);
    assert.match(schemaSql, /CREATE TABLE findings[\s\S]*?last_verdict_id TEXT/m);
    assert.match(schemaSql, /CREATE TABLE findings[\s\S]*?assignee TEXT/m);
    assert.match(schemaSql, /ADD CONSTRAINT verdicts_tenant_id_id_key UNIQUE \(tenant_id, id\)/);
    assert.match(schemaSql, /ADD CONSTRAINT fk_findings_verdict_tenant\b/);
    assert.match(schemaSql, /ADD CONSTRAINT fk_findings_last_verdict_tenant\b/);
    assert.match(schemaSql, /CREATE TABLE agent_jobs[\s\S]*?type TEXT NOT NULL DEFAULT 'observe_window'/m);
    assert.doesNotMatch(schemaSql, /CREATE TABLE agent_jobs[\s\S]*?\bjob_type\b/m);

    assert.ok(TENANT_CONSISTENT_FK_CONSTRAINTS.includes('fk_findings_verdict_tenant'));
    assert.ok(TENANT_CONSISTENT_FK_CONSTRAINTS.includes('fk_findings_last_verdict_tenant'));

    assert.match(combinedMigration, /RENAME COLUMN job_type TO type/);
    assert.match(combinedMigration, /findings ADD COLUMN IF NOT EXISTS verdict_id/);
    assert.match(combinedMigration, /verdicts_tenant_id_id_key UNIQUE \(tenant_id, id\)/);
    assert.match(combinedMigration, /ADD CONSTRAINT fk_findings_verdict_tenant\b/);
  });

  it('includes validation ledger hot-path indexes in schema and migrations', () => {
    const schemaSql = readFileSync(path.join(ROOT, 'db', 'schema.sql'), 'utf8');
    const migrationSqls = readdirSync(path.join(ROOT, 'db', 'migrations'))
      .filter((n) => n.endsWith('.sql'))
      .sort()
      .map((n) => readFileSync(path.join(ROOT, 'db', 'migrations', n), 'utf8'));
    const combinedMigration = migrationSqls.join('\n');

    const indexPatterns = [
      /CREATE INDEX idx_test_runs_tenant_created ON test_runs\(tenant_id, created_at DESC\)/,
      /CREATE INDEX idx_test_runs_tenant_group_created ON test_runs\(tenant_id, target_group_id, created_at DESC\)/,
      /CREATE INDEX idx_events_tenant_run_time ON events\(tenant_id, test_run_id, timestamp\)/,
      /CREATE INDEX idx_evidence_vault_tenant_run_created ON evidence_vault\(tenant_id, test_run_id, created_at DESC\)/,
      /CREATE INDEX idx_evidence_vault_tenant_related_event ON evidence_vault\(tenant_id, related_event_id\)/,
      /CREATE UNIQUE INDEX uniq_findings_open_target_check ON findings\(tenant_id, target_group_id, target_id, check_id\) WHERE status = 'open'/,
      /CREATE UNIQUE INDEX uniq_probe_result_per_run_nonce ON events\(tenant_id, test_run_id, signal_type, nonce_hash\) WHERE signal_type = 'probe_result' AND nonce_hash IS NOT NULL/,
    ];

    for (const pattern of indexPatterns) {
      assert.match(schemaSql, pattern);
      assert.match(combinedMigration, pattern);
    }

    const migrationNames = readdirSync(path.join(ROOT, 'db', 'migrations'))
      .filter((n) => n.endsWith('.sql'))
      .sort();
    assert.ok(migrationNames.includes('0004_validation_ledger_indexes.sql'));
  });

  it('includes verdict placement_confidence_json in schema and migration 0005', () => {
    const schemaSql = readFileSync(path.join(ROOT, 'db', 'schema.sql'), 'utf8');
    const migrationSql = readFileSync(
      path.join(ROOT, 'db', 'migrations', '0005_verdict_placement_confidence.sql'),
      'utf8',
    );
    assert.match(schemaSql, /CREATE TABLE verdicts[\s\S]*?placement_confidence_json JSONB/m);
    assert.match(migrationSql, /verdicts ADD COLUMN IF NOT EXISTS placement_confidence_json JSONB/);
  });

  it('includes notification trigger and metadata JSON columns in schema and migration 0006', () => {
    const schemaSql = readFileSync(path.join(ROOT, 'db', 'schema.sql'), 'utf8');
    const migrationSql = readFileSync(
      path.join(ROOT, 'db', 'migrations', '0006_notification_rule_triggers.sql'),
      'utf8',
    );
    assert.match(schemaSql, /CREATE TABLE notification_rules[\s\S]*?triggers_json JSONB/m);
    assert.match(schemaSql, /CREATE TABLE notification_events[\s\S]*?metadata_json JSONB/m);
    assert.match(migrationSql, /notification_rules ADD COLUMN IF NOT EXISTS triggers_json JSONB/);
    assert.match(migrationSql, /notification_events ADD COLUMN IF NOT EXISTS metadata_json JSONB/);
    assert.match(migrationSql, /jsonb_build_array\(trigger\)/);
  });

  it('includes WAF posture tables with forced RLS, indexes, and metadata-only evidence columns', () => {
    const schemaSql = readFileSync(path.join(ROOT, 'db', 'schema.sql'), 'utf8');
    const migrationSql = readFileSync(
      path.join(ROOT, 'db', 'migrations', '0008_waf_posture.sql'),
      'utf8',
    );

    const wafTenantTables = [
      'external_asset_candidates',
      'waf_assets',
      'waf_fingerprints',
      'waf_validation_runs',
      'waf_scenario_results',
      'waf_posture_snapshots',
      'waf_baselines',
      'waf_drift_events',
      'waf_connectors',
      'waf_connector_snapshots',
      'cve_pipeline_items',
      'cve_asset_matches',
      'waf_rule_recommendations',
    ];
    for (const table of wafTenantTables) {
      assert.match(schemaSql, new RegExp(`CREATE TABLE ${table}\\b`, 'i'));
      assert.match(schemaSql, new RegExp(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`, 'i'));
      assert.match(
        schemaSql,
        new RegExp(
          `CREATE POLICY tenant_isolation_${table} ON ${table}[\\s\\S]*?current_setting\\('app\\.tenant_id', true\\)`,
          'm',
        ),
      );
      assert.match(migrationSql, new RegExp(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`, 'i'));
    }

    assert.match(schemaSql, /CREATE TABLE waf_products\b/i);
    assert.doesNotMatch(schemaSql, /ALTER TABLE waf_products FORCE ROW LEVEL SECURITY/i);

    const forbiddenRaw = [
      /\bCREATE TABLE waf_[\w]+[\s\S]*?\braw_payload\b/im,
      /\bCREATE TABLE waf_[\w]+[\s\S]*?\brequest_body\b/im,
      /\bCREATE TABLE waf_[\w]+[\s\S]*?\bresponse_body\b/im,
    ];
    for (const pattern of forbiddenRaw) {
      assert.doesNotMatch(schemaSql, pattern);
      assert.doesNotMatch(migrationSql, pattern);
    }

    assert.match(schemaSql, /uniq_waf_posture_snapshot_current/);
    assert.match(schemaSql, /idx_waf_posture_snapshots_dashboard/);
    assert.match(schemaSql, /idx_waf_drift_events_queue/);
    assert.match(schemaSql, /idx_waf_connector_snapshots_history/);
    assert.match(schemaSql, /idx_cve_pipeline_items_lookup/);
    assert.match(schemaSql, /idx_external_asset_candidates_approval_queue/);
    assert.match(schemaSql, /idx_waf_assets_tenant_group_url/);
    assert.match(schemaSql, /uniq_cve_asset_matches_dedupe/);

    assert.ok(TENANT_CONSISTENT_FK_CONSTRAINTS.includes('fk_waf_assets_target_group_tenant'));
    assert.ok(TENANT_CONSISTENT_FK_CONSTRAINTS.includes('fk_waf_drift_events_finding_tenant'));
    assert.match(schemaSql, /ADD CONSTRAINT findings_tenant_id_id_key UNIQUE \(tenant_id, id\)/);
    assert.match(migrationSql, /findings_tenant_id_id_key UNIQUE \(tenant_id, id\)/);
    assert.match(schemaSql, /waf_connectors[\s\S]*?status TEXT NOT NULL DEFAULT 'disabled'/m);
  });
});
