/** @type {readonly string[]} */
export const CORE_CATALOG_TENANT_SERVICE_METHODS = Object.freeze([
  'getCurrentTenant',
  'patchCurrentTenant',
  'listEnvironments',
  'createEnvironment',
  'patchEnvironment',
]);

/** @type {readonly string[]} */
export const CORE_CATALOG_TARGET_GROUP_SERVICE_METHODS = Object.freeze([
  'listTargetGroups',
  'createTargetGroup',
  'getTargetGroup',
  'addTarget',
  'patchTargetGroup',
  'archiveTargetGroup',
  'patchTarget',
  'deleteTarget',
]);

/** @type {readonly string[]} */
export const CORE_CATALOG_SERVICE_METHODS = Object.freeze([
  ...CORE_CATALOG_TENANT_SERVICE_METHODS,
  ...CORE_CATALOG_TARGET_GROUP_SERVICE_METHODS,
]);

export {
  AUTH_TOKEN_REPOSITORY_METHODS,
  POSTGRES_AUTH_TOKEN_SERVICE_METHODS,
  POSTGRES_SERVICE_ACCOUNT_SERVICE_METHODS,
  SERVICE_ACCOUNT_REPOSITORY_METHODS,
  createPostgresAuthServices,
} from './authServiceAdapters.mjs';

export {
  AGENT_AUDIT_REPOSITORY_METHODS,
  AGENT_CONTROL_REPOSITORY_METHODS,
  POSTGRES_AGENT_AUTH_SERVICE_METHODS,
  POSTGRES_AGENT_SERVICE_METHODS,
  createPostgresAgentServices,
} from './agentServiceAdapters.mjs';

export {
  POSTGRES_VALIDATION_EVIDENCE_SERVICE_METHODS,
  POSTGRES_VALIDATION_FINDINGS_SERVICE_METHODS,
  POSTGRES_VALIDATION_ORCHESTRATION_ERROR,
  POSTGRES_VALIDATION_TEST_RUNS_SERVICE_METHODS,
  VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS,
  VALIDATION_AUDIT_REPOSITORY_METHODS,
  VALIDATION_CORE_CATALOG_REPOSITORY_METHODS,
  VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  VALIDATION_KILL_SWITCH_REPOSITORY_METHODS,
  VALIDATION_PROBE_JOB_REPOSITORY_METHODS,
  createPostgresValidationServices,
} from './validationServiceAdapters.mjs';

export {
  POSTGRES_SECRET_VAULT_SERVICE_METHODS,
  SECRET_VAULT_REPOSITORY_METHODS,
  createPostgresSecretVaultServices,
} from './secretVaultServiceAdapters.mjs';

export {
  POSTGRES_REPORT_SERVICE_METHODS,
  REPORT_AUDIT_REPOSITORY_METHODS,
  REPORT_REPOSITORY_METHODS,
  REPORT_VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  createPostgresReportServices,
} from './reportServiceAdapters.mjs';

export {
  NOTIFICATION_REPOSITORY_METHODS,
  POSTGRES_NOTIFICATION_SERVICE_METHODS,
  createPostgresNotificationServices,
} from './notificationServiceAdapters.mjs';

export {
  AGENT_UPDATE_REPOSITORY_METHODS,
  POSTGRES_AGENT_UPDATE_SERVICE_METHODS,
  createPostgresAgentUpdateServices,
} from './agentUpdateServiceAdapters.mjs';

export {
  STATE_AGENT_CONTROL_REPOSITORY_METHODS,
  STATE_CORE_CATALOG_REPOSITORY_METHODS,
  STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  POSTGRES_STATE_SERVICE_METHODS,
  createPostgresStateServices,
} from './stateServiceAdapters.mjs';

export {
  PLACEMENT_AGENT_CONTROL_REPOSITORY_METHODS,
  PLACEMENT_CORE_CATALOG_REPOSITORY_METHODS,
  PLACEMENT_VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  POSTGRES_PLACEMENT_SERVICE_METHODS,
  createPostgresPlacementServices,
} from './placementServiceAdapters.mjs';

export {
  PROBE_JOB_REPOSITORY_METHODS,
  POSTGRES_PROBE_JOB_SERVICE_METHODS,
  createPostgresProbeJobServices,
} from './probeJobServiceAdapters.mjs';

export {
  HIGH_SCALE_REPOSITORY_METHODS,
  HIGH_SCALE_KILL_SWITCH_REPOSITORY_METHODS,
  POSTGRES_HIGH_SCALE_SERVICE_METHODS,
  createPostgresHighScaleServices,
} from './highScaleServiceAdapters.mjs';

export {
  PRODUCTION_RELEASE_EVIDENCE_REPOSITORY_METHODS,
  POSTGRES_PRODUCTION_RELEASE_EVIDENCE_SERVICE_METHODS,
  createPostgresProductionReleaseEvidenceServices,
} from './productionReleaseEvidenceServiceAdapters.mjs';

export {
  RETENTION_REPOSITORY_METHODS,
  POSTGRES_RETENTION_SERVICE_METHODS,
  createPostgresRetentionServices,
} from './retentionServiceAdapters.mjs';

export {
  WAF_POSTURE_REPOSITORY_METHODS,
  POSTGRES_WAF_POSTURE_SERVICE_METHODS,
  createPostgresWafPostureServices,
} from './wafPostureServiceAdapters.mjs';

export {
  WAF_ORCHESTRATOR_REPOSITORY_METHODS,
  POSTGRES_WAF_ORCHESTRATOR_SERVICE_METHODS,
  createPostgresWafOrchestratorServices,
} from './wafOrchestratorServiceAdapters.mjs';

export {
  INTERNAL_MANAGEMENT_REPOSITORY_METHODS,
  POSTGRES_INTERNAL_MANAGEMENT_SERVICE_METHODS,
  createPostgresInternalManagementServices,
} from './internalManagementServiceAdapters.mjs';

export {
  TEST_POLICY_REPOSITORY_METHODS,
  TEST_POLICY_CORE_CATALOG_REPOSITORY_METHODS,
  TEST_POLICY_AUDIT_REPOSITORY_METHODS,
  POSTGRES_TEST_POLICY_SERVICE_METHODS,
  createPostgresTestPolicyServices,
} from './testPolicyServiceAdapters.mjs';

/**
 * @param {{ coreCatalog?: Record<string, unknown> }} repositories
 * @returns {{ tenants: Record<string, (...args: unknown[]) => unknown>, targetGroups: Record<string, (...args: unknown[]) => unknown> }}
 */
export function createPostgresCatalogServices(repositories) {
  const coreCatalog = repositories?.coreCatalog;
  if (!coreCatalog || typeof coreCatalog !== 'object') {
    throw new Error('Postgres catalog service adapter requires repositories.coreCatalog.');
  }

  for (const method of CORE_CATALOG_SERVICE_METHODS) {
    if (typeof coreCatalog[method] !== 'function') {
      throw new Error(`Postgres catalog service adapter requires coreCatalog.${method}().`);
    }
  }

  /** @type {Record<string, (...args: unknown[]) => unknown>} */
  const tenants = {};
  for (const method of CORE_CATALOG_TENANT_SERVICE_METHODS) {
    tenants[method] = (...args) => coreCatalog[method](...args);
  }

  /** @type {Record<string, (...args: unknown[]) => unknown>} */
  const targetGroups = {};
  for (const method of CORE_CATALOG_TARGET_GROUP_SERVICE_METHODS) {
    targetGroups[method] = (...args) => coreCatalog[method](...args);
  }

  return { tenants, targetGroups };
}
