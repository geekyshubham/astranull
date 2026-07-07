import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { closePgPool, createPgPool, pingPostgres } from './pool.mjs';
import {
  assertLatestMigrationApplied,
  getLatestMigrationVersion,
  listMigrationFiles,
  runMigrations,
} from './migrations.mjs';
import { createCoreCatalogRepository } from './coreCatalogRepository.mjs';
import { createAuditRepository } from './auditRepository.mjs';
import { createAuthTokenRepository } from './authTokenRepository.mjs';
import { createAgentControlRepository } from './agentControlRepository.mjs';
import { createValidationEvidenceRepository } from './validationEvidenceRepository.mjs';
import { createReportRepository } from './reportRepository.mjs';
import { createSecretVaultRepository } from './secretVaultRepository.mjs';
import { createNotificationRepository } from './notificationRepository.mjs';
import { createAgentUpdateRepository } from './agentUpdateRepository.mjs';
import { createProbeJobRepository } from './probeJobRepository.mjs';
import { createKillSwitchRepository } from './killSwitchRepository.mjs';
import { createOwnershipVerificationRepository } from './ownershipVerificationRepository.mjs';
import {
  createPostgresDnsOwnershipServices,
  createPostgresOwnershipVerificationServices,
} from './ownershipVerificationServiceAdapters.mjs';
import { createPortalRevampRepository } from './portalRevampRepository.mjs';
import {
  createPostgresPortalRevampServices,
  mergePortalDnsOwnershipServices,
  mergePortalOwnershipVerificationServices,
} from './portalRevampServiceAdapters.mjs';
import { createHighScaleRepository } from './highScaleRepository.mjs';
import { createProductionReleaseEvidenceRepository } from './productionReleaseEvidenceRepository.mjs';
import { createRetentionRepository } from './retentionRepository.mjs';
import { createWafPostureRepository } from './wafPostureRepository.mjs';
import { createWafOrchestratorRepository } from './wafOrchestratorRepository.mjs';
import { createInternalManagementRepository } from './internalManagementRepository.mjs';
import {
  createPostgresAgentServices,
  createPostgresAuthServices,
  createPostgresCatalogServices,
  createPostgresSecretVaultServices,
  createPostgresValidationServices,
  createPostgresReportServices,
  createPostgresNotificationServices,
  createPostgresAgentUpdateServices,
  createPostgresStateServices,
  createPostgresPlacementServices,
  createPostgresProbeJobServices,
  createPostgresHighScaleServices,
  createPostgresProductionReleaseEvidenceServices,
  createPostgresRetentionServices,
  createPostgresWafPostureServices,
  createPostgresWafOrchestratorServices,
  createPostgresInternalManagementServices,
} from './serviceAdapters.mjs';
import { createPostgresTestPolicyServices } from './testPolicyServiceAdapters.mjs';
import { createPostgresTestPolicyRepository } from './testPolicyRepository.mjs';
import { createPostgresCvePipelineServices } from './cvePipelineServiceAdapters.mjs';
import { createCvePipelineRepository } from './cvePipelineRepository.mjs';
import { createPostgresExternalDiscoveryServices } from './externalDiscoveryServiceAdapters.mjs';
import { createPostgresSupplyChainRiskServices } from './supplyChainRiskServiceAdapters.mjs';
import { createPostgresActionItemServices } from './actionItemServiceAdapters.mjs';
import { createPostgresWafCoverageRollupServices } from './wafCoverageRollupServiceAdapters.mjs';
import { createPostgresWafDriftServices } from './wafDriftServiceAdapters.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../../..');

/** @type {readonly string[]} */
export const POSTGRES_RUNTIME_REPOSITORY_KEYS = Object.freeze([
  'coreCatalog',
  'audit',
  'authTokens',
  'agentControl',
  'validationEvidence',
  'reports',
  'secretVault',
  'notifications',
  'agentUpdates',
  'probeJobs',
  'killSwitch',
  'ownershipVerifications',
  'highScale',
  'productionReleaseEvidence',
  'retention',
  'wafPosture',
  'wafOrchestrator',
  'internalManagement',
  'portalRevamp',
]);

/**
 * @returns {string}
 */
export function getDefaultPostgresMigrationsDir() {
  return path.join(REPO_ROOT, 'db', 'migrations');
}

const DEFAULT_REPOSITORY_FACTORIES = {
  coreCatalog: createCoreCatalogRepository,
  audit: createAuditRepository,
  authTokens: createAuthTokenRepository,
  agentControl: createAgentControlRepository,
  validationEvidence: createValidationEvidenceRepository,
  reports: createReportRepository,
  secretVault: createSecretVaultRepository,
  notifications: createNotificationRepository,
  agentUpdates: createAgentUpdateRepository,
  probeJobs: createProbeJobRepository,
  killSwitch: createKillSwitchRepository,
  ownershipVerifications: createOwnershipVerificationRepository,
  highScale: createHighScaleRepository,
  productionReleaseEvidence: createProductionReleaseEvidenceRepository,
  retention: createRetentionRepository,
  wafPosture: createWafPostureRepository,
  wafOrchestrator: createWafOrchestratorRepository,
  internalManagement: createInternalManagementRepository,
  portalRevamp: createPortalRevampRepository,
};

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 * @param {{
 *   autoMigrate?: boolean,
 *   migrationsDir?: string,
 *   createPool?: (env: NodeJS.ProcessEnv | Record<string, string | undefined>) => import('pg').Pool,
 *   closePool?: (pool: import('pg').Pool) => Promise<void>,
 *   ping?: (pool: import('pg').Pool) => Promise<unknown>,
 *   listMigrationFiles?: typeof listMigrationFiles,
 *   getLatestMigrationVersion?: typeof getLatestMigrationVersion,
 *   assertLatestMigrationApplied?: typeof assertLatestMigrationApplied,
 *   runMigrations?: typeof runMigrations,
 *   repositoryFactories?: Partial<typeof DEFAULT_REPOSITORY_FACTORIES>,
 *   authServiceOptions?: Parameters<typeof createPostgresAuthServices>[1],
 *   agentServiceOptions?: Omit<Parameters<typeof createPostgresAgentServices>[1], 'tokens'>,
 * }} [options]
 */
export async function createPostgresRuntime(env = process.env, options = {}) {
  const migrationsDir = options.migrationsDir ?? getDefaultPostgresMigrationsDir();
  const createPoolFn = options.createPool ?? createPgPool;
  const closePoolFn = options.closePool ?? closePgPool;
  const pingFn = options.ping ?? pingPostgres;
  const listFilesFn = options.listMigrationFiles ?? listMigrationFiles;
  const latestVersionFn = options.getLatestMigrationVersion ?? getLatestMigrationVersion;
  const assertLatestFn = options.assertLatestMigrationApplied ?? assertLatestMigrationApplied;
  const runMigrationsFn = options.runMigrations ?? runMigrations;
  const repositoryFactories = { ...DEFAULT_REPOSITORY_FACTORIES, ...options.repositoryFactories };

  const autoMigrate =
    options.autoMigrate === true || String(env.ASTRANULL_POSTGRES_AUTO_MIGRATE ?? '').trim() === '1';

  /** @type {import('pg').Pool | undefined} */
  let pool;
  let closed = false;

  const close = async () => {
    if (closed) {
      return;
    }
    closed = true;
    if (pool) {
      await closePoolFn(pool);
    }
  };

  try {
    pool = createPoolFn(env);
    const files = listFilesFn(migrationsDir);
    const latestMigration = latestVersionFn(files);

    await pingFn(pool);

    if (autoMigrate) {
      await runMigrationsFn(pool, { migrationsDir, files });
    }

    await assertLatestFn(pool, latestMigration);

    /** @type {Record<string, unknown>} */
    const repositories = {};
    for (const key of POSTGRES_RUNTIME_REPOSITORY_KEYS) {
      const factory = repositoryFactories[key];
      if (!factory) {
        throw new Error(`Missing repository factory for "${key}".`);
      }
      repositories[key] = factory(pool);
    }

    const retentionServices = createPostgresRetentionServices(repositories);
    const catalogServices = createPostgresCatalogServices(repositories);
    const authServices = createPostgresAuthServices(repositories, options.authServiceOptions);
    const agentServices = createPostgresAgentServices(repositories, {
      ...options.agentServiceOptions,
      tokens: authServices.tokens,
    });
    const validationServices = createPostgresValidationServices(repositories);
    const secretVault = createPostgresSecretVaultServices(repositories);
    const reportServices = createPostgresReportServices(repositories);
    const notificationServices = createPostgresNotificationServices(repositories);
    const agentUpdateServices = createPostgresAgentUpdateServices(repositories);
    const stateServices = createPostgresStateServices(repositories);
    const placementServices = createPostgresPlacementServices(repositories);
    const probeJobServices = createPostgresProbeJobServices(repositories);
    const highScaleServices = createPostgresHighScaleServices(repositories, {
      notifications: notificationServices,
    });
    const productionReleaseEvidenceServices =
      createPostgresProductionReleaseEvidenceServices(repositories);
    const cvePipelineRepository = createCvePipelineRepository(pool);
    const repositoriesWithCve = {
      ...repositories,
      cvePipeline: cvePipelineRepository,
    };
    const wafPostureServices = createPostgresWafPostureServices(repositoriesWithCve);
    const wafOrchestratorServices = createPostgresWafOrchestratorServices(repositories, {
      ...(options.wafOrchestratorServiceOptions ?? {}),
      testRuns: validationServices.testRuns,
    });
    const cvePipelineServices = createPostgresCvePipelineServices(pool, {
      repositories: {
        cvePipeline: cvePipelineRepository,
        wafPosture: repositories.wafPosture,
        audit: repositories.audit,
        actionItems: repositories.actionItems,
      },
    });
    const externalDiscoveryServices = createPostgresExternalDiscoveryServices(repositories, { pool });
    const supplyChainRiskServices = createPostgresSupplyChainRiskServices(pool);
    const actionItemServices = createPostgresActionItemServices(pool, {
      portalRevamp: repositories.portalRevamp,
    });
    const wafDriftServices = createPostgresWafDriftServices(repositories);
    const wafCoverageRollupServices = createPostgresWafCoverageRollupServices(repositories);
    const internalManagementServices = createPostgresInternalManagementServices(repositories);
    const testPolicyRepository = createPostgresTestPolicyRepository(pool);
    const testPolicyServices = createPostgresTestPolicyServices({
      testPolicies: testPolicyRepository,
      coreCatalog: repositories.coreCatalog,
      audit: repositories.audit,
    });
    const ownershipVerificationBase = createPostgresOwnershipVerificationServices({
      repositories,
      agentControl: repositories.agentControl,
      probeJobs: repositories.probeJobs,
      audit: repositories.audit,
    });
    const dnsOwnershipBase = createPostgresDnsOwnershipServices({
      repositories,
      audit: repositories.audit,
    });
    const portalRevampServices = createPostgresPortalRevampServices({ repositories });
    const ownershipVerification = mergePortalOwnershipVerificationServices(
      ownershipVerificationBase,
      portalRevampServices.portalOwnership,
    );
    const dnsOwnership = mergePortalDnsOwnershipServices(
      dnsOwnershipBase,
      portalRevampServices.portalDns,
    );
    const services = {
      ...catalogServices,
      ...authServices,
      ...agentServices,
      ...validationServices,
      ...reportServices,
      secretVault,
      notifications: notificationServices,
      agentUpdates: agentUpdateServices,
      state: stateServices,
      placement: placementServices,
      probeJobs: probeJobServices,
      highScale: highScaleServices,
      testPolicies: testPolicyServices,
      productionReleaseEvidence: productionReleaseEvidenceServices,
      retention: retentionServices,
      wafPosture: {
        ...wafPostureServices,
        getCoverageSummary: portalRevampServices.portalWaf.getCoverageSummary.bind(
          portalRevampServices.portalWaf,
        ),
        getConnectorInventory: portalRevampServices.portalWaf.getConnectorInventory.bind(
          portalRevampServices.portalWaf,
        ),
      },
      wafDrift: wafDriftServices,
      wafCoverageRollup: wafCoverageRollupServices,
      wafOrchestrator: wafOrchestratorServices,
      cvePipeline: cvePipelineServices,
      externalDiscovery: externalDiscoveryServices,
      supplyChainRisk: supplyChainRiskServices,
      actionItems: actionItemServices,
      internalManagement: internalManagementServices,
      signupIntake: {
        ...internalManagementServices,
        listEvents: portalRevampServices.portalSignup.listEvents.bind(
          portalRevampServices.portalSignup,
        ),
      },
      ownershipVerification,
      dnsOwnership,
      loa: portalRevampServices.loa,
      targetDetail: portalRevampServices.targetDetail,
      remediation: portalRevampServices.remediation,
      findings: {
        ...validationServices.findings,
        getEvidenceBundle: portalRevampServices.portalFindings.getEvidenceBundle.bind(
          portalRevampServices.portalFindings,
        ),
      },
      targetGroups: {
        ...catalogServices.targetGroups,
        restoreArchived: portalRevampServices.portalTargetGroups.restoreArchived.bind(
          portalRevampServices.portalTargetGroups,
        ),
        bulkImportTargets: portalRevampServices.portalTargetGroups.bulkImportTargets.bind(
          portalRevampServices.portalTargetGroups,
        ),
      },
      audit: repositories.audit,
    };

    const health = async () => {
      await pingFn(pool);
      await assertLatestFn(pool, latestMigration);
      return { ok: true, persistence: 'postgres', latestMigration };
    };

    return {
      pool,
      migrationsDir,
      latestMigration,
      repositories,
      services,
      health,
      close,
    };
  } catch (initErr) {
    try {
      await close();
    } catch (cleanupErr) {
      if (initErr && typeof initErr === 'object' && cleanupErr !== initErr) {
        initErr.cleanup_error = cleanupErr;
      }
    }
    throw initErr;
  }
}
