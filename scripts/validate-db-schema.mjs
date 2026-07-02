#!/usr/bin/env node
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const SCHEMA_PATH = path.join(ROOT, 'db', 'schema.sql');
const MIGRATIONS_DIR = path.join(ROOT, 'db', 'migrations');

function readSqlFiles() {
  const schemaSql = readFileSync(SCHEMA_PATH, 'utf8');
  const migrationFiles = readdirSync(MIGRATIONS_DIR)
    .filter((name) => name.endsWith('.sql'))
    .sort()
    .map((name) => ({
      name,
      sql: readFileSync(path.join(MIGRATIONS_DIR, name), 'utf8'),
    }));
  return { schemaSql, migrationFiles };
}

function assertPattern(label, sql, pattern) {
  if (!pattern.test(sql)) {
    return `${label}: missing required pattern ${pattern}`;
  }
  return null;
}

function assertAbsent(label, sql, pattern) {
  if (pattern.test(sql)) {
    return `${label}: stale or forbidden pattern ${pattern}`;
  }
  return null;
}

const REQUIRED_TABLES = [
  'schema_migrations',
  'tenants',
  'environments',
  'users',
  'target_groups',
  'targets',
  'bootstrap_tokens',
  'agents',
  'agent_jobs',
  'probe_jobs',
  'test_runs',
  'events',
  'verdicts',
  'findings',
  'evidence_vault',
  'soc_kill_switch',
  'audit_logs',
  'platform_metrics',
  'service_accounts',
  'encrypted_secrets',
  'agent_update_trust_keys',
  'agent_update_releases',
  'agent_update_statuses',
  'high_scale_telemetry',
  'soc_reports',
  'notification_delivery_attempts',
  'production_release_evidence',
  'external_asset_candidates',
  'waf_products',
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
  'discovery_entities',
  'supply_chain_risks',
  'waf_action_items',
];

const REQUIRED_COLUMNS = [
  [/CREATE TABLE probe_jobs[\s\S]*?job_signature/m, 'probe_jobs.job_signature'],
  [/CREATE TABLE agent_jobs[\s\S]*?type TEXT NOT NULL DEFAULT 'observe_window'/m, 'agent_jobs.type'],
  [/CREATE TABLE agent_jobs[\s\S]*?nonce_for_agent/m, 'agent_jobs.nonce_for_agent'],
  [/CREATE TABLE agent_jobs[\s\S]*?observed_at/m, 'agent_jobs.observed_at'],
  [/CREATE TABLE findings[\s\S]*?verdict_id/m, 'findings.verdict_id'],
  [/CREATE TABLE findings[\s\S]*?last_verdict_id/m, 'findings.last_verdict_id'],
  [/CREATE TABLE findings[\s\S]*?assignee/m, 'findings.assignee'],
  [/CREATE TABLE agents[\s\S]*?fingerprint/m, 'agents.fingerprint'],
  [/CREATE TABLE agents[\s\S]*?bootstrap_token_id/m, 'agents.bootstrap_token_id'],
  [/CREATE TABLE agents[\s\S]*?target_group_id/m, 'agents.target_group_id'],
  [/CREATE TABLE test_runs[\s\S]*?probe_external_result/m, 'test_runs.probe_external_result'],
  [/CREATE TABLE test_runs[\s\S]*?awaiting_external_probe/m, 'test_runs.awaiting_external_probe'],
  [/CREATE TABLE test_runs[\s\S]*?safety_constraints/m, 'test_runs.safety_constraints'],
  [/CREATE TABLE test_runs[\s\S]*?created_by/m, 'test_runs.created_by'],
  [/CREATE TABLE events[\s\S]*?agent_id/m, 'events.agent_id'],
  [/CREATE TABLE audit_logs[\s\S]*?sequence/m, 'audit_logs.sequence'],
  [/CREATE TABLE audit_logs[\s\S]*?prev_hash/m, 'audit_logs.prev_hash'],
  [/CREATE TABLE audit_logs[\s\S]*?entry_hash/m, 'audit_logs.entry_hash'],
  [/CREATE TABLE target_groups[\s\S]*?safety_policy/m, 'target_groups.safety_policy'],
  [/CREATE TABLE target_groups[\s\S]*?safe_test_windows/m, 'target_groups.safe_test_windows'],
  [/CREATE TABLE high_scale_requests[\s\S]*?requested_window/m, 'high_scale_requests.requested_window'],
  [/CREATE TABLE high_scale_requests[\s\S]*?emergency_contacts/m, 'high_scale_requests.emergency_contacts'],
  [/CREATE TABLE high_scale_requests[\s\S]*?scope_confirmation/m, 'high_scale_requests.scope_confirmation'],
  [/CREATE TABLE high_scale_requests[\s\S]*?audit_trail/m, 'high_scale_requests.audit_trail'],
  [/CREATE TABLE high_scale_requests[\s\S]*?adapter_json/m, 'high_scale_requests.adapter_json'],
  [/CREATE TABLE high_scale_requests[\s\S]*?soc_approvals/m, 'high_scale_requests.soc_approvals'],
  [/CREATE TABLE high_scale_requests[\s\S]*?provider_approval_checklist/m, 'high_scale_requests.provider_approval_checklist'],
  [/CREATE TABLE service_accounts[\s\S]*?secret_hash/m, 'service_accounts.secret_hash'],
  [/CREATE TABLE encrypted_secrets[\s\S]*?envelope_json/m, 'encrypted_secrets.envelope_json'],
  [/CREATE TABLE agent_update_trust_keys[\s\S]*?fingerprint_sha256/m, 'agent_update_trust_keys.fingerprint_sha256'],
  [/CREATE TABLE agent_update_releases[\s\S]*?manifest_json/m, 'agent_update_releases.manifest_json'],
  [/CREATE TABLE agent_update_statuses[\s\S]*?release_id/m, 'agent_update_statuses.release_id'],
  [/CREATE TABLE high_scale_telemetry[\s\S]*?metrics_json/m, 'high_scale_telemetry.metrics_json'],
  [/CREATE TABLE soc_reports[\s\S]*?derived_json/m, 'soc_reports.derived_json'],
  [/CREATE TABLE notification_delivery_attempts[\s\S]*?destination_preview/m, 'notification_delivery_attempts.destination_preview'],
  [/CREATE TABLE verdicts[\s\S]*?placement_confidence_json/m, 'verdicts.placement_confidence_json'],
  [/CREATE TABLE production_release_evidence[\s\S]*?evidence_json/m, 'production_release_evidence.evidence_json'],
  [/CREATE TABLE production_release_evidence[\s\S]*?validation_json/m, 'production_release_evidence.validation_json'],
  [/CREATE TABLE waf_scenario_results[\s\S]*?evidence_summary_json/m, 'waf_scenario_results.evidence_summary_json'],
  [/CREATE TABLE waf_connectors[\s\S]*?config_json/m, 'waf_connectors.config_json'],
  [/CREATE TABLE waf_connectors[\s\S]*?status TEXT NOT NULL DEFAULT 'disabled'/m, 'waf_connectors.status default disabled'],
];

const WAF_FORBIDDEN_RAW_COLUMN_PATTERNS = [
  [/\bCREATE TABLE waf_[\w]+[\s\S]*?\braw_payload\b/im, 'WAF tables must not define raw_payload columns'],
  [/\bCREATE TABLE waf_[\w]+[\s\S]*?\brequest_body\b/im, 'WAF tables must not define request_body columns'],
  [/\bCREATE TABLE waf_[\w]+[\s\S]*?\bresponse_body\b/im, 'WAF tables must not define response_body columns'],
  [/\bCREATE TABLE waf_[\w]+[\s\S]*?\bheader_dump\b/im, 'WAF tables must not define header_dump columns'],
  [/\bCREATE TABLE waf_[\w]+[\s\S]*?\bpacket_capture\b/im, 'WAF tables must not define packet_capture columns'],
  [
    /\bCREATE TABLE (external_asset_candidates|cve_pipeline_items|cve_asset_matches|discovery_entities|supply_chain_risks|waf_action_items)[\s\S]*?\braw_payload\b/im,
    'WAF-adjacent and wave 1 tables must not define raw_payload columns',
  ],
  [
    /\bCREATE TABLE (discovery_entities|supply_chain_risks|waf_action_items)[\s\S]*?\b(page_body|html_source|request_body|response_body|header_dump|packet_capture)\b/im,
    'Wave 1 tables must not define raw evidence body columns',
  ],
];

const REQUIRED_INDEXES = [
  'idx_agent_jobs',
  'uniq_active_test_run',
  'uniq_verdict_per_test_run',
  'idx_events_correlation',
  'uniq_audit_tenant_sequence',
  'uniq_events_tenant_event_id',
  'uniq_active_agent_update_trust_key_fingerprint',
  'uniq_soc_report_per_high_scale_request',
  'idx_high_scale_telemetry_request_observed',
  'idx_notification_delivery_attempts_event',
  'idx_production_release_evidence_tenant_kind_created',
  'idx_waf_assets_tenant_group_url',
  'idx_external_asset_candidates_approval_queue',
  'uniq_waf_posture_snapshot_current',
  'idx_waf_posture_snapshots_dashboard',
  'idx_waf_drift_events_queue',
  'idx_waf_connector_snapshots_history',
  'idx_cve_pipeline_items_lookup',
  'uniq_cve_asset_matches_dedupe',
  'idx_supply_chain_risks_lookup',
  'idx_waf_action_items_status',
  'idx_discovery_entities_lookup',
  'uniq_supply_chain_risks_dedupe',
  'uniq_waf_action_items_dedupe',
];

/** Tenant-facing tables that must ENABLE + FORCE RLS (not global tables). */
const TENANT_RLS_TABLES = [
  'tenants',
  'environments',
  'users',
  'target_groups',
  'targets',
  'bootstrap_tokens',
  'agents',
  'test_runs',
  'probe_jobs',
  'agent_jobs',
  'events',
  'verdicts',
  'findings',
  'evidence_vault',
  'reports',
  'high_scale_requests',
  'authorization_artifacts',
  'soc_notes',
  'soc_kill_switch',
  'notification_rules',
  'notification_events',
  'audit_logs',
  'service_accounts',
  'encrypted_secrets',
  'agent_update_trust_keys',
  'agent_update_releases',
  'agent_update_statuses',
  'high_scale_telemetry',
  'soc_reports',
  'notification_delivery_attempts',
  'production_release_evidence',
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
  'discovery_entities',
  'supply_chain_risks',
  'waf_action_items',
];

const REQUIRED_RLS = [
  /ALTER TABLE tenants ENABLE ROW LEVEL SECURITY/,
  /ALTER TABLE tenants FORCE ROW LEVEL SECURITY/,
  /CREATE POLICY tenant_isolation_tenants ON tenants[\s\S]*?USING \(id = current_setting\('app\.tenant_id', true\)\)/m,
  /tenant_isolation_probe_jobs/,
];

const FORBIDDEN_SCHEMA_PATTERNS = [
  [
    /CREATE TABLE events\b[\s\S]*?\bevent_id TEXT NOT NULL/m,
    'events.event_id must be nullable for internal runtime events',
  ],
  [
    /CREATE TABLE events[\s\S]*?UNIQUE \(tenant_id, event_id\)/m,
    'events must use partial unique index uniq_events_tenant_event_id, not table UNIQUE (tenant_id, event_id)',
  ],
  [
    /CREATE INDEX idx_audit_tenant_sequence ON audit_logs\(tenant_id, sequence\)/,
    'audit_logs requires uniq_audit_tenant_sequence (unique per-tenant sequence)',
  ],
  [
    /REFERENCES (environments|users|target_groups|targets|bootstrap_tokens|agents|test_runs|high_scale_requests|notification_rules|notification_events|agent_update_releases|findings|waf_assets|waf_validation_runs|waf_baselines|waf_connectors|cve_pipeline_items|cve_asset_matches|discovery_entities)\(id\)/,
    'tenant-scoped parent references must use composite FK (tenant_id, parent_id), not single-column REFERENCES parent(id)',
  ],
  [
    /CREATE TABLE agent_jobs[\s\S]*?\bjob_type\b/m,
    'agent_jobs must use column type, not job_type (see 0003_runtime_shape_parity)',
  ],
];

/** Composite UNIQUE on tenant-scoped parents — required for tenant-consistent FK targets. */
export const TENANT_PARENT_UNIQUE_KEYS = [
  'environments_tenant_id_id_key',
  'users_tenant_id_id_key',
  'target_groups_tenant_id_id_key',
  'targets_tenant_id_id_key',
  'bootstrap_tokens_tenant_id_id_key',
  'agents_tenant_id_id_key',
  'test_runs_tenant_id_id_key',
  'verdicts_tenant_id_id_key',
  'events_tenant_id_id_key',
  'high_scale_requests_tenant_id_id_key',
  'notification_rules_tenant_id_id_key',
  'notification_events_tenant_id_id_key',
  'agent_update_releases_tenant_id_id_key',
  'production_release_evidence_tenant_id_id_key',
  'findings_tenant_id_id_key',
  'waf_assets_tenant_id_id_key',
  'waf_validation_runs_tenant_id_id_key',
  'waf_baselines_tenant_id_id_key',
  'waf_connectors_tenant_id_id_key',
  'cve_pipeline_items_tenant_id_id_key',
  'cve_asset_matches_tenant_id_id_key',
  'discovery_entities_tenant_id_id_key',
  'supply_chain_risks_tenant_id_id_key',
  'waf_action_items_tenant_id_id_key',
];

/** Named composite FK constraints enforced in schema + baseline migration. */
export const TENANT_CONSISTENT_FK_CONSTRAINTS = [
  'fk_target_groups_environment_tenant',
  'fk_target_groups_owner_user_tenant',
  'fk_targets_target_group_tenant',
  'fk_bootstrap_tokens_environment_tenant',
  'fk_bootstrap_tokens_target_group_tenant',
  'fk_agents_environment_tenant',
  'fk_agents_target_group_tenant',
  'fk_agents_bootstrap_token_tenant',
  'fk_test_runs_target_group_tenant',
  'fk_test_runs_target_tenant',
  'fk_probe_jobs_test_run_tenant',
  'fk_probe_jobs_target_tenant',
  'fk_agent_jobs_agent_tenant',
  'fk_agent_jobs_test_run_tenant',
  'fk_agent_jobs_target_tenant',
  'fk_events_test_run_tenant',
  'fk_events_target_tenant',
  'fk_events_agent_tenant',
  'fk_verdicts_test_run_tenant',
  'fk_verdicts_target_tenant',
  'fk_findings_target_group_tenant',
  'fk_findings_target_tenant',
  'fk_findings_test_run_tenant',
  'fk_findings_verdict_tenant',
  'fk_findings_last_verdict_tenant',
  'fk_evidence_vault_test_run_tenant',
  'fk_evidence_vault_related_event_tenant',
  'fk_high_scale_requests_target_group_tenant',
  'fk_authorization_artifacts_high_scale_request_tenant',
  'fk_soc_notes_high_scale_request_tenant',
  'fk_notification_events_rule_tenant',
  'fk_agent_update_statuses_agent_tenant',
  'fk_agent_update_statuses_release_tenant',
  'fk_high_scale_telemetry_high_scale_request_tenant',
  'fk_soc_reports_high_scale_request_tenant',
  'fk_notification_delivery_attempts_event_tenant',
  'fk_notification_delivery_attempts_rule_tenant',
  'fk_external_asset_candidates_approved_target_tenant',
  'fk_waf_assets_target_group_tenant',
  'fk_waf_assets_target_tenant',
  'fk_waf_assets_environment_tenant',
  'fk_waf_fingerprints_waf_asset_tenant',
  'fk_waf_fingerprints_test_run_tenant',
  'fk_waf_validation_runs_test_run_tenant',
  'fk_waf_validation_runs_waf_asset_tenant',
  'fk_waf_scenario_results_waf_validation_run_tenant',
  'fk_waf_posture_snapshots_waf_asset_tenant',
  'fk_waf_baselines_waf_asset_tenant',
  'fk_waf_drift_events_waf_asset_tenant',
  'fk_waf_drift_events_baseline_tenant',
  'fk_waf_drift_events_finding_tenant',
  'fk_waf_connectors_secret_tenant',
  'fk_waf_connector_snapshots_connector_tenant',
  'fk_cve_asset_matches_cve_pipeline_item_tenant',
  'fk_cve_asset_matches_waf_asset_tenant',
  'fk_cve_asset_matches_finding_tenant',
  'fk_waf_rule_recommendations_waf_asset_tenant',
  'fk_waf_rule_recommendations_cve_asset_match_tenant',
  'fk_external_asset_candidates_entity',
  'fk_waf_action_items_cve_pipeline_item_tenant',
];

const TENANT_FK_COMPOSITE_SHAPE =
  /ADD CONSTRAINT fk_[\w]+[\s\S]*?FOREIGN KEY \(tenant_id, [\w]+\) REFERENCES [\w]+ \(tenant_id, id\)/m;

export function validateDbSchema({ schemaSql, migrationSqls = [] } = {}) {
  const errors = [];
  const loaded = schemaSql != null ? { schemaSql, migrationFiles: migrationSqls } : readSqlFiles();
  const combinedMigration = loaded.migrationFiles.map((m) => (typeof m === 'string' ? m : m.sql)).join('\n');
  const schema = loaded.schemaSql ?? schemaSql;

  for (const table of REQUIRED_TABLES) {
    errors.push(assertPattern(`schema:${table}`, schema, new RegExp(`CREATE TABLE ${table}\\b`, 'i')));
  }

  for (const [re, label] of REQUIRED_COLUMNS) {
    errors.push(assertPattern(label, schema, re));
  }

  for (const idx of REQUIRED_INDEXES) {
    errors.push(assertPattern(`index:${idx}`, schema, new RegExp(idx, 'i')));
  }

  for (const re of REQUIRED_RLS) {
    errors.push(assertPattern('rls', schema, re));
  }

  for (const table of TENANT_RLS_TABLES) {
    errors.push(
      assertPattern(
        `rls:force:${table}`,
        schema,
        new RegExp(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`, 'i'),
      ),
    );
  }

  errors.push(
    assertAbsent(
      'rls:global_no_force',
      schema,
      /ALTER TABLE schema_migrations FORCE ROW LEVEL SECURITY/,
    ),
  );
  errors.push(
    assertAbsent('rls:global_no_force', schema, /ALTER TABLE platform_metrics FORCE ROW LEVEL SECURITY/),
  );

  for (const [re, message] of FORBIDDEN_SCHEMA_PATTERNS) {
    if (re.test(schema)) {
      errors.push(`schema: ${message}`);
    }
  }

  for (const [re, message] of WAF_FORBIDDEN_RAW_COLUMN_PATTERNS) {
    if (re.test(schema)) {
      errors.push(`schema:waf_evidence: ${message}`);
    }
  }

  errors.push(
    assertAbsent(
      'schema:waf_products_no_rls',
      schema,
      /ALTER TABLE waf_products FORCE ROW LEVEL SECURITY/,
    ),
  );

  errors.push(
    assertPattern(
      'index:uniq_events_partial',
      schema,
      /CREATE UNIQUE INDEX uniq_events_tenant_event_id ON events\(tenant_id, event_id\) WHERE event_id IS NOT NULL/,
    ),
  );
  errors.push(
    assertPattern(
      'index:uniq_audit_sequence',
      schema,
      /CREATE UNIQUE INDEX uniq_audit_tenant_sequence ON audit_logs\(tenant_id, sequence\)/,
    ),
  );

  for (const keyName of TENANT_PARENT_UNIQUE_KEYS) {
    errors.push(
      assertPattern(
        `tenant_fk:parent_unique:${keyName}`,
        schema,
        new RegExp(`ADD CONSTRAINT ${keyName} UNIQUE \\(tenant_id, id\\)`, 'i'),
      ),
    );
  }

  for (const fkName of TENANT_CONSISTENT_FK_CONSTRAINTS) {
    errors.push(
      assertPattern(`tenant_fk:${fkName}`, schema, new RegExp(`ADD CONSTRAINT ${fkName}\\b`, 'i')),
    );
  }

  errors.push(
    assertPattern('tenant_fk:composite_shape', schema, TENANT_FK_COMPOSITE_SHAPE),
  );

  if (loaded.migrationFiles.length === 0) {
    errors.push('migrations: expected at least one .sql file');
  } else {
    const first = loaded.migrationFiles[0];
    const firstSql = typeof first === 'string' ? first : first.sql;
    const firstName = typeof first === 'string' ? 'migration' : first.name;
    if (!/0001_core_validation_loop/.test(firstName) && !/0001_core_validation_loop/.test(firstSql)) {
      errors.push('migrations: expected 0001_core_validation_loop baseline');
    }
    for (const table of ['probe_jobs', 'agent_jobs']) {
      errors.push(assertPattern(`migration:${table}`, combinedMigration, new RegExp(`CREATE TABLE ${table}\\b`, 'i')));
    }
    errors.push(assertPattern('migration:rls', combinedMigration, /ALTER TABLE tenants ENABLE ROW LEVEL SECURITY/));
    errors.push(assertPattern('migration:rls_force', combinedMigration, /ALTER TABLE tenants FORCE ROW LEVEL SECURITY/));
    for (const table of TENANT_RLS_TABLES) {
      errors.push(
        assertPattern(
          `migration:rls:force:${table}`,
          combinedMigration,
          new RegExp(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY`, 'i'),
        ),
      );
    }
    errors.push(assertPattern('migration:tenants_policy', combinedMigration, /tenant_isolation_tenants/));
    errors.push(assertPattern('migration:uniq_audit', combinedMigration, /uniq_audit_tenant_sequence/));
    errors.push(assertPattern('migration:uniq_events', combinedMigration, /uniq_events_tenant_event_id/));
    for (const fkName of TENANT_CONSISTENT_FK_CONSTRAINTS) {
      errors.push(
        assertPattern(
          `migration:tenant_fk:${fkName}`,
          combinedMigration,
          new RegExp(`ADD CONSTRAINT ${fkName}\\b`, 'i'),
        ),
      );
    }
    errors.push(assertPattern('migration:tenant_fk:composite_shape', combinedMigration, TENANT_FK_COMPOSITE_SHAPE));
    errors.push(
      assertPattern(
        'migration:0003_runtime_shape_parity',
        combinedMigration,
        /0003_runtime_shape_parity|RENAME COLUMN job_type TO type/,
      ),
    );
    errors.push(
      assertPattern('migration:findings_runtime_parity', combinedMigration, /findings ADD COLUMN IF NOT EXISTS verdict_id/),
    );
    errors.push(
      assertPattern('migration:verdicts_parent_unique', combinedMigration, /verdicts_tenant_id_id_key UNIQUE \(tenant_id, id\)/),
    );
    errors.push(
      assertPattern('migration:fk_findings_verdict_tenant', combinedMigration, /ADD CONSTRAINT fk_findings_verdict_tenant\b/),
    );
    errors.push(
      assertPattern(
        'migration:verdict_placement_confidence',
        combinedMigration,
        /verdicts ADD COLUMN IF NOT EXISTS placement_confidence_json/,
      ),
    );
    errors.push(
      assertPattern(
        'migration:production_release_evidence',
        combinedMigration,
        /CREATE TABLE IF NOT EXISTS production_release_evidence/,
      ),
    );
    errors.push(
      assertPattern(
        'migration:production_release_evidence_rls',
        combinedMigration,
        /ALTER TABLE production_release_evidence FORCE ROW LEVEL SECURITY/,
      ),
    );
    errors.push(
      assertPattern(
        'migration:0008_waf_posture',
        combinedMigration,
        /CREATE TABLE IF NOT EXISTS waf_assets/,
      ),
    );
    errors.push(
      assertPattern(
        'migration:waf_posture_rls',
        combinedMigration,
        /ALTER TABLE waf_assets FORCE ROW LEVEL SECURITY/,
      ),
    );
    errors.push(
      assertPattern(
        'migration:findings_parent_unique_waf',
        combinedMigration,
        /findings_tenant_id_id_key UNIQUE \(tenant_id, id\)/,
      ),
    );
    errors.push(
      assertPattern(
        'migration:uniq_waf_posture_snapshot_current',
        combinedMigration,
        /uniq_waf_posture_snapshot_current/,
      ),
    );
    for (const fkName of [
      'fk_waf_assets_target_group_tenant',
      'fk_waf_drift_events_finding_tenant',
      'fk_waf_connector_snapshots_connector_tenant',
    ]) {
      errors.push(
        assertPattern(
          `migration:waf_fk:${fkName}`,
          combinedMigration,
          new RegExp(`ADD CONSTRAINT ${fkName}\\b`, 'i'),
        ),
      );
    }
    errors.push(
      assertPattern(
        'migration:0009_wave1_extensions',
        combinedMigration,
        /CREATE TABLE IF NOT EXISTS discovery_entities/,
      ),
    );
    errors.push(
      assertPattern(
        'migration:wave1_rls',
        combinedMigration,
        /ALTER TABLE discovery_entities FORCE ROW LEVEL SECURITY/,
      ),
    );
    errors.push(
      assertPattern(
        'migration:wave1_entity_fk',
        combinedMigration,
        /ADD CONSTRAINT fk_external_asset_candidates_entity\b/,
      ),
    );
    errors.push(
      assertPattern(
        'migration:wave1_action_item_fk',
        combinedMigration,
        /ADD CONSTRAINT fk_waf_action_items_cve_pipeline_item_tenant\b/,
      ),
    );
    for (const idx of [
      'idx_supply_chain_risks_lookup',
      'idx_waf_action_items_status',
      'idx_discovery_entities_lookup',
      'uniq_supply_chain_risks_dedupe',
      'uniq_waf_action_items_dedupe',
    ]) {
      errors.push(
        assertPattern(
          `migration:wave1_index:${idx}`,
          combinedMigration,
          new RegExp(idx, 'i'),
        ),
      );
    }
  }

  errors.push(assertAbsent('schema', schema, /identity_fingerprint/));

  const filtered = errors.filter(Boolean);
  return { ok: filtered.length === 0, errors: filtered };
}

export function main() {
  const result = validateDbSchema();
  if (!result.ok) {
    for (const err of result.errors) {
      console.error(`validate-db-schema: ${err}`);
    }
    process.exit(1);
  }
  console.log('validate-db-schema: ok');
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}
