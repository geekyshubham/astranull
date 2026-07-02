import { existsSync } from 'node:fs';
import path from 'node:path';
import {
  ARTIFACT_PROOF_FIELDS,
  REQUIRED_ARTIFACT_TYPES,
} from '../lib/highScalePolicy.mjs';

export const AUTHORIZATION_TEMPLATE_DISCLAIMER =
  'AstraNull templates are operational starting points, not legal advice. Customer counsel, provider policy owners, and AstraNull SOC/legal reviewers must approve production use.';

const TEMPLATE_PACK_PATH = 'docs/templates/high-scale-authorization-pack.md';

function template({
  artifact_type,
  title,
  purpose,
  required_metadata_fields = [],
  required_sections = [],
  retention_classification = 'high_scale_authorization',
  legal_review_required = false,
  template_path = TEMPLATE_PACK_PATH,
}) {
  const proofFields = ARTIFACT_PROOF_FIELDS[artifact_type] ?? [];
  return Object.freeze({
    artifact_type,
    title,
    purpose,
    required_metadata_fields: Object.freeze([...new Set([...proofFields, ...required_metadata_fields])]),
    required_sections: Object.freeze(required_sections),
    retention_classification,
    legal_review_required,
    template_path,
    disclaimer: AUTHORIZATION_TEMPLATE_DISCLAIMER,
  });
}

export const AUTHORIZATION_TEMPLATE_CATALOG = Object.freeze([
  template({
    artifact_type: 'customer_authorization_letter',
    title: 'Customer Authorization Letter',
    purpose: 'Customer confirms that AstraNull SOC is authorized to coordinate the bounded validation.',
    required_metadata_fields: ['approved_targets', 'approved_scenario_families'],
    required_sections: ['customer legal entity', 'declared target groups', 'approved window', 'constraints', 'signature'],
    legal_review_required: true,
  }),
  template({
    artifact_type: 'target_ownership_confirmation',
    title: 'Target Ownership Confirmation',
    purpose: 'Customer confirms declared targets are owned, controlled, or explicitly authorized.',
    required_metadata_fields: ['approved_targets'],
    required_sections: ['ownership basis', 'declared targets', 'approver'],
    legal_review_required: true,
  }),
  template({
    artifact_type: 'emergency_contacts',
    title: 'Emergency Contacts',
    purpose: 'Defines customer, SOC, and provider stop/escalation contacts during the window.',
    required_sections: ['primary contacts', 'backup contacts', 'stop path', 'availability confirmation'],
  }),
  template({
    artifact_type: 'stop_criteria',
    title: 'Stop Criteria',
    purpose: 'Documents thresholds and authorities that pause or stop the validation.',
    required_sections: ['customer stop authority', 'provider stop authority', 'technical thresholds', 'SOC stop authority'],
  }),
  template({
    artifact_type: 'test_plan',
    title: 'Test Plan',
    purpose: 'Defines scenario families, observations, monitoring, and completion criteria.',
    required_metadata_fields: ['approved_targets'],
    required_sections: ['scope', 'scenario families', 'monitoring', 'completion criteria'],
  }),
  template({
    artifact_type: 'business_approval',
    title: 'Business Approval',
    purpose: 'Business owner accepts the timing, risk, communications, and recovery expectations.',
    required_sections: ['business owner', 'risk acceptance', 'customer communications', 'approval reference'],
    legal_review_required: true,
  }),
  template({
    artifact_type: 'legal_approval',
    title: 'Legal and Policy Approval',
    purpose: 'Legal/security owner confirms the validation is authorized under customer and provider rules.',
    required_sections: ['legal reviewer', 'approved scope', 'policy references', 'retention instructions'],
    retention_classification: 'legal_hold_candidate',
    legal_review_required: true,
  }),
  template({
    artifact_type: 'scope_and_rate_plan',
    title: 'Scope and Rate Plan',
    purpose: 'Locks target scope, rate labels, duration caps, and change-control boundaries.',
    required_metadata_fields: ['approved_targets'],
    required_sections: ['target scope', 'rate and duration limits', 'maintenance window', 'change-control link'],
    legal_review_required: true,
  }),
  template({
    artifact_type: 'abort_criteria',
    title: 'Abort Criteria',
    purpose: 'Documents immediate abort conditions, customer/provider authority, and recovery steps.',
    required_sections: ['abort triggers', 'decision authority', 'notification sequence', 'recovery confirmation'],
  }),
  template({
    artifact_type: 'provider_approval',
    title: 'Provider Approval',
    purpose: 'Captures cloud, CDN, carrier, partner, or lab approval metadata without requiring credentials.',
    required_metadata_fields: [
      'provider_name',
      'approval_reference',
      'valid_window',
      'approved_targets',
      'approved_scenario_families',
      'approved_limits',
      'contact_path',
      'emergency_stop_path',
      'provider_specific_evidence',
    ],
    required_sections: ['provider path', 'approval reference', 'approved scope', 'stop bridge', 'provider evidence'],
    retention_classification: 'provider_authorization',
    legal_review_required: true,
  }),
]);

const CATALOG_BY_TYPE = Object.freeze(
  Object.fromEntries(AUTHORIZATION_TEMPLATE_CATALOG.map((entry) => [entry.artifact_type, entry])),
);

export function listAuthorizationTemplates() {
  return AUTHORIZATION_TEMPLATE_CATALOG;
}

export function getAuthorizationTemplate(type) {
  return CATALOG_BY_TYPE[type] ?? null;
}

export function authorizationTemplateCoverage(rootDir = process.cwd()) {
  const expected = [...REQUIRED_ARTIFACT_TYPES, 'provider_approval'];
  const missing_templates = expected.filter((type) => !getAuthorizationTemplate(type));
  const missing_metadata_fields = [];
  const missing_template_paths = [];

  for (const type of expected) {
    const entry = getAuthorizationTemplate(type);
    if (!entry) continue;
    const proofFields = ARTIFACT_PROOF_FIELDS[type] ?? [];
    const fields = new Set(entry.required_metadata_fields);
    const missing = proofFields.filter((field) => !fields.has(field));
    if (missing.length > 0) {
      missing_metadata_fields.push({ artifact_type: type, fields: missing });
    }
    if (entry.template_path && !existsSync(path.join(rootDir, entry.template_path))) {
      missing_template_paths.push({ artifact_type: type, template_path: entry.template_path });
    }
  }

  return {
    expected_artifact_types: Object.freeze(expected),
    missing_templates: Object.freeze(missing_templates),
    missing_metadata_fields: Object.freeze(missing_metadata_fields),
    missing_template_paths: Object.freeze(missing_template_paths),
    complete:
      missing_templates.length === 0
      && missing_metadata_fields.length === 0
      && missing_template_paths.length === 0,
  };
}
