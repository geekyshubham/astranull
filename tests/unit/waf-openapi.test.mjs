import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  validateWafOpenApi,
  validateWafOpenApiArtifact,
} from '../../scripts/validate-waf-openapi.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const ARTIFACT = path.join(ROOT, 'docs/api/waf-posture-openapi.json');

describe('WAF posture OpenAPI artifact', () => {
  it('parses as JSON and passes structural contract checks', () => {
    const raw = readFileSync(ARTIFACT, 'utf8');
    const doc = JSON.parse(raw);
    const result = validateWafOpenApi(doc);
    assert.equal(result.ok, true, result.errors.join('; '));
  });

  it('validateWafOpenApiArtifact loads the committed artifact from repo root', () => {
    const result = validateWafOpenApiArtifact({ rootDir: ROOT });
    assert.equal(result.ok, true, result.errors.join('; '));
    assert.match(result.artifactPath, /waf-posture-openapi\.json$/);
  });

  it('documents orchestrator execute path with POST and continuation semantics', () => {
    const doc = JSON.parse(readFileSync(ARTIFACT, 'utf8'));
    const execute = doc.paths['/v1/waf/validation-plans/{id}/execute'].post;
    assert.equal(execute.operationId, 'executeValidationPlan');
    const schema =
      execute.responses['200'].content['application/json'].schema.$ref;
    assert.equal(schema, '#/components/schemas/ValidationPlanExecuteResponse');
    const executeSchema = doc.components.schemas.ValidationPlanExecuteResponse;
    assert.ok('continuation_required' in executeSchema.properties);
  });

  it('fails validation when a required orchestrator error code is removed', () => {
    const doc = JSON.parse(readFileSync(ARTIFACT, 'utf8'));
    const apiError = doc.components.schemas.ApiError;
    apiError.properties.error.enum = apiError.properties.error.enum.filter(
      (c) => c !== 'waf_feature_disabled',
    );
    const result = validateWafOpenApi(doc);
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((e) => /waf_feature_disabled/.test(e)));
  });
});