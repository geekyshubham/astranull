import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  ARTIFACT_PROOF_FIELDS,
  REQUIRED_ARTIFACT_TYPES,
} from '../../src/lib/highScalePolicy.mjs';
import {
  AUTHORIZATION_TEMPLATE_CATALOG,
  authorizationTemplateCoverage,
  getAuthorizationTemplate,
  listAuthorizationTemplates,
} from '../../src/contracts/authorizationTemplates.mjs';

const ROOT = process.cwd();

describe('authorization template catalog', () => {
  it('covers every required high-scale artifact type plus provider approval', () => {
    const expected = [...REQUIRED_ARTIFACT_TYPES, 'provider_approval'];
    assert.deepEqual(
      listAuthorizationTemplates().map((t) => t.artifact_type).sort(),
      expected.toSorted(),
    );
    assert.equal(AUTHORIZATION_TEMPLATE_CATALOG.length, expected.length);
  });

  it('includes all enforced proof fields for each artifact type', () => {
    for (const type of REQUIRED_ARTIFACT_TYPES) {
      const template = getAuthorizationTemplate(type);
      assert.ok(template, `missing template for ${type}`);
      for (const field of ARTIFACT_PROOF_FIELDS[type] ?? []) {
        assert.ok(
          template.required_metadata_fields.includes(field),
          `${type} missing metadata field ${field}`,
        );
      }
    }
  });

  it('marks legal and governance-sensitive templates for review/retention', () => {
    for (const type of [
      'customer_authorization_letter',
      'target_ownership_confirmation',
      'business_approval',
      'legal_approval',
      'scope_and_rate_plan',
      'provider_approval',
    ]) {
      const template = getAuthorizationTemplate(type);
      assert.equal(template.legal_review_required, true, `${type} should require legal review`);
      assert.match(template.disclaimer, /not legal advice/i);
    }
    assert.equal(getAuthorizationTemplate('legal_approval').retention_classification, 'legal_hold_candidate');
    assert.equal(getAuthorizationTemplate('provider_approval').retention_classification, 'provider_authorization');
  });

  it('points every markdown-backed template to an existing path', () => {
    for (const template of listAuthorizationTemplates()) {
      assert.ok(template.template_path, `${template.artifact_type} missing template path`);
      assert.equal(
        existsSync(path.join(ROOT, template.template_path)),
        true,
        `${template.artifact_type} path missing: ${template.template_path}`,
      );
    }
  });

  it('reports complete coverage for the current repo', () => {
    const coverage = authorizationTemplateCoverage(ROOT);
    assert.equal(coverage.complete, true);
    assert.deepEqual(coverage.missing_templates, []);
    assert.deepEqual(coverage.missing_metadata_fields, []);
    assert.deepEqual(coverage.missing_template_paths, []);
  });
});
