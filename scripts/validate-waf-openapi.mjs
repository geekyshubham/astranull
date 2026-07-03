import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ARTIFACT_REL = 'docs/api/waf-posture-openapi.json';

const REQUIRED_PATHS = [
  '/v1/waf/assets',
  '/v1/waf/assets/{id}',
  '/v1/waf/coverage',
  '/v1/waf/coverage/vendors',
  '/v1/waf/coverage/entities',
  '/v1/waf/coverage/criticality',
  '/v1/waf/coverage/geography',
  '/v1/waf/coverage/criticality',
  '/v1/waf/coverage/risk-roadmap',
  '/v1/waf/coverage/vendor-consolidation',
  '/v1/waf/cve-pipeline/{id}/playbook',
  '/v1/waf/cve-pipeline/{id}/playbook/approve',
  '/v1/waf/cve-pipeline/playbooks/{id}/retest',
  '/v1/waf/validations',
  '/v1/waf/validation-plans',
  '/v1/waf/validation-plans/scheduled',
  '/v1/waf/validation-plans/{id}/execute',
  '/v1/waf/validation-plans/{id}/cancel',
  '/v1/waf/reports/{kind}/export',
  '/v1/waf/retests',
  '/v1/waf/drift-events/{id}/retest',
  '/v1/waf/retests/{id}/execute',
  '/v1/waf/retests/{id}/complete',
  '/v1/waf/action-items',
  '/v1/waf/action-items/{id}',
];

const REQUIRED_SCHEMAS = [
  'WafAsset',
  'WafValidationPlan',
  'WafRetestRequest',
  'DelegatedJob',
  'WafActionItem',
  'ApiError',
  'WafPostureSnapshot',
  'WafDriftEvent',
  'WafReportExport',
];

const REQUIRED_ERROR_CODES = [
  'waf_feature_disabled',
  'postgres_waf_orchestrator_unavailable',
  'unsafe_orchestrator_plan',
  'validation_plan_not_found',
  'validation_plan_already_completed',
  'validation_plan_cancelled',
  'waf_orchestrator_execution_in_progress',
  'waf_orchestrator_execution_not_ready',
  'waf_orchestrator_signed_worker_required',
  'waf_orchestration_batch_too_large',
  'validation_plan_execution_failed',
  'waf_retest_not_found',
  'waf_retest_already_completed',
  'waf_retest_already_delegated',
  'waf_retest_closure_not_ready',
  'waf_drift_event_not_found',
  'waf_report_kind_invalid',
];

/**
 * @param {unknown} doc
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateWafOpenApi(doc) {
  const errors = [];

  if (!doc || typeof doc !== 'object') {
    return { ok: false, errors: ['document must be a JSON object'] };
  }

  const root = /** @type {Record<string, unknown>} */ (doc);

  if (root.openapi !== '3.1.0') {
    errors.push(`openapi must be 3.1.0 (got ${String(root.openapi)})`);
  }

  const info = root.info;
  if (!info || typeof info !== 'object') {
    errors.push('info object is required');
  } else {
    const infoObj = /** @type {Record<string, unknown>} */ (info);
    const desc = String(infoObj.description ?? '');
    if (!/no-access-first|no access/i.test(desc)) {
      errors.push('info.description must mention no-access-first posture');
    }
    if (!/safe-by-default|safe by default/i.test(desc)) {
      errors.push('info.description must mention safe-by-default boundaries');
    }
    if (!/production-ready|production ready/i.test(desc)) {
      errors.push('info.description must state production readiness gates remain open');
    }
  }

  const paths = root.paths;
  if (!paths || typeof paths !== 'object') {
    errors.push('paths object is required');
  } else {
    const pathObj = /** @type {Record<string, unknown>} */ (paths);
    for (const p of REQUIRED_PATHS) {
      if (!pathObj[p]) {
        errors.push(`missing path: ${p}`);
      }
    }
  }

  const components = root.components;
  if (!components || typeof components !== 'object') {
    errors.push('components object is required');
  } else {
    const comp = /** @type {Record<string, unknown>} */ (components);
    const schemas = comp.schemas;
    if (!schemas || typeof schemas !== 'object') {
      errors.push('components.schemas is required');
    } else {
      const schemaObj = /** @type {Record<string, unknown>} */ (schemas);
      for (const name of REQUIRED_SCHEMAS) {
        if (!schemaObj[name]) {
          errors.push(`missing schema: ${name}`);
        }
      }
      const apiError = schemaObj.ApiError;
      if (apiError && typeof apiError === 'object') {
        const errSchema = /** @type {Record<string, unknown>} */ (apiError);
        const props = errSchema.properties;
        if (!props || typeof props !== 'object') {
          errors.push('ApiError.properties is required');
        } else {
          const errorProp = /** @type {Record<string, unknown>} */ (props).error;
          const enumVals =
            errorProp &&
            typeof errorProp === 'object' &&
            Array.isArray(/** @type {Record<string, unknown>} */ (errorProp).enum)
              ? /** @type {unknown[]} */ (/** @type {Record<string, unknown>} */ (errorProp).enum)
              : [];
          for (const code of REQUIRED_ERROR_CODES) {
            if (!enumVals.includes(code)) {
              errors.push(`ApiError.error enum missing code: ${code}`);
            }
          }
        }
      }
    }
  }

  const securitySchemes = components && typeof components === 'object'
    ? /** @type {Record<string, unknown>} */ (components).securitySchemes
    : null;
  if (!securitySchemes || typeof securitySchemes !== 'object' || !securitySchemes.bearerAuth) {
    errors.push('components.securitySchemes.bearerAuth is required');
  }

  return { ok: errors.length === 0, errors };
}

/**
 * @param {{ rootDir?: string }} [options]
 * @returns {{ ok: boolean, errors: string[], artifactPath: string }}
 */
export function validateWafOpenApiArtifact(options = {}) {
  const rootDir = options.rootDir ?? process.cwd();
  const artifactPath = path.join(rootDir, ARTIFACT_REL);
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(artifactPath, 'utf8'));
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return { ok: false, errors: [`failed to read or parse ${ARTIFACT_REL}: ${message}`], artifactPath };
  }
  const result = validateWafOpenApi(parsed);
  return { ...result, artifactPath };
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  const result = validateWafOpenApiArtifact();
  if (!result.ok) {
    for (const err of result.errors) {
      console.error(`waf-openapi: ${err}`);
    }
    process.exit(1);
  }
  console.log(`waf-openapi: ok (${result.artifactPath})`);
}