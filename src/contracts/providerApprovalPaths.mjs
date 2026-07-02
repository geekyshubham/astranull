const COMMON_REQUIRED_FIELDS = Object.freeze([
  'approval_reference',
  'valid_window',
  'approved_targets',
  'approved_scenario_families',
  'contact_path',
  'approved_limits',
  'provider_specific_evidence',
  'emergency_stop_path',
]);

function profile(def) {
  return Object.freeze({
    required_artifact_fields: [...COMMON_REQUIRED_FIELDS],
    ...def,
    accepted_test_paths: Object.freeze([...(def.accepted_test_paths ?? [])]),
    required_artifact_fields: Object.freeze([
      ...(def.required_artifact_fields ?? COMMON_REQUIRED_FIELDS),
    ]),
    required_limits: Object.freeze([...(def.required_limits ?? [])]),
    required_stop_controls: Object.freeze([...(def.required_stop_controls ?? [])]),
    required_evidence: Object.freeze([...(def.required_evidence ?? [])]),
  });
}

export const PROVIDER_APPROVAL_PATHS = Object.freeze({
  aws: profile({
    provider_key: 'aws',
    display_name: 'AWS',
    category: 'cloud',
    approval_path: 'provider_fire_drill',
    accepted_test_paths: ['AWS-approved DDoS simulation partner path', 'Shield/edge readiness drill metadata'],
    required_limits: ['approved_rate_or_intensity_label', 'approved_duration_minutes', 'approved_region_or_edge_scope'],
    required_stop_controls: ['SOC kill switch', 'AWS/provider stop reference', 'customer emergency contact'],
    required_evidence: ['approval case/reference', 'approved target scope', 'approved window', 'provider stop path'],
    customer_action_summary: 'Open and retain the required AWS/provider simulation approval before SOC scheduling.',
    soc_review_summary: 'Verify approval scope, dates, scenario family, limits, and provider stop path before start.',
  }),
  azure: profile({
    provider_key: 'azure',
    display_name: 'Azure',
    category: 'cloud',
    approval_path: 'provider_fire_drill',
    accepted_test_paths: ['Azure-approved DDoS simulation partner path', 'DDoS Protection fire-drill metadata'],
    required_limits: ['approved_rate_or_intensity_label', 'approved_duration_minutes', 'approved_subscription_scope'],
    required_stop_controls: ['SOC kill switch', 'Azure/provider stop reference', 'customer emergency contact'],
    required_evidence: ['approval case/reference', 'approved resource scope', 'approved window', 'provider stop path'],
    customer_action_summary: 'Retain Azure/provider simulation approval and resource scope metadata.',
    soc_review_summary: 'Confirm the approved resource scope, window, limits, and stop contacts match the request.',
  }),
  gcp: profile({
    provider_key: 'gcp',
    display_name: 'Google Cloud',
    category: 'cloud',
    approval_path: 'provider_fire_drill',
    accepted_test_paths: ['Google Cloud Armor readiness drill metadata', 'approved partner simulation path'],
    required_limits: ['approved_rate_or_intensity_label', 'approved_duration_minutes', 'approved_project_or_edge_scope'],
    required_stop_controls: ['SOC kill switch', 'provider stop reference', 'customer emergency contact'],
    required_evidence: ['approval case/reference', 'approved target scope', 'approved window', 'provider stop path'],
    customer_action_summary: 'Document Google/provider approval, project/resource scope, and stop contacts.',
    soc_review_summary: 'Verify provider approval metadata aligns to declared target group and requested scenario.',
  }),
  cloudflare: profile({
    provider_key: 'cloudflare',
    display_name: 'Cloudflare',
    category: 'cdn',
    approval_path: 'provider_fire_drill',
    accepted_test_paths: ['CDN edge readiness drill metadata', 'approved partner DDoS simulation path'],
    required_limits: ['approved_rps_or_intensity_label', 'approved_duration_minutes', 'zone_or_service_scope'],
    required_stop_controls: ['SOC kill switch', 'provider or partner stop bridge', 'customer emergency contact'],
    required_evidence: ['approval/ticket reference', 'approved zone/service scope', 'approved window', 'stop path'],
    customer_action_summary: 'Provide CDN approval or partner ticket covering the declared zone/service and window.',
    soc_review_summary: 'Check zone/service scope, approved scenario family, and provider stop bridge before start.',
  }),
  akamai: profile({
    provider_key: 'akamai',
    display_name: 'Akamai',
    category: 'cdn',
    approval_path: 'provider_fire_drill',
    accepted_test_paths: ['Akamai/partner-approved edge readiness drill metadata'],
    required_limits: ['approved_rps_or_intensity_label', 'approved_duration_minutes', 'property_or_service_scope'],
    required_stop_controls: ['SOC kill switch', 'provider or partner stop bridge', 'customer emergency contact'],
    required_evidence: ['approval/ticket reference', 'approved property scope', 'approved window', 'stop path'],
    customer_action_summary: 'Provide provider/partner approval covering property scope, limits, and dates.',
    soc_review_summary: 'Confirm property scope and approved limits match the request before scheduling.',
  }),
  cdn_other: profile({
    provider_key: 'cdn_other',
    display_name: 'Other CDN/WAF Provider',
    category: 'cdn',
    approval_path: 'manual_coordination',
    accepted_test_paths: ['provider-approved edge readiness drill metadata'],
    required_limits: ['approved_intensity_label', 'approved_duration_minutes', 'edge_or_service_scope'],
    required_stop_controls: ['SOC kill switch', 'provider stop contact', 'customer emergency contact'],
    required_evidence: ['provider approval reference', 'approved scope', 'approved window', 'stop path'],
    customer_action_summary: 'Attach provider approval metadata for the declared CDN/WAF service.',
    soc_review_summary: 'Verify scope, contacts, approved limits, and stop path with the provider.',
  }),
  isp_carrier: profile({
    provider_key: 'isp_carrier',
    display_name: 'ISP / Carrier',
    category: 'network_provider',
    approval_path: 'manual_coordination',
    accepted_test_paths: ['carrier-approved network readiness drill metadata'],
    required_limits: ['approved_intensity_label', 'approved_duration_minutes', 'circuit_or_prefix_scope'],
    required_stop_controls: ['SOC kill switch', 'carrier NOC stop contact', 'customer emergency contact'],
    required_evidence: ['carrier approval reference', 'approved prefixes/circuits', 'approved window', 'stop path'],
    customer_action_summary: 'Provide carrier/NOC approval for the exact prefixes or circuits under test.',
    soc_review_summary: 'Confirm carrier NOC contact, approved prefixes/circuits, and stop path.',
  }),
  on_prem_lab: profile({
    provider_key: 'on_prem_lab',
    display_name: 'On-Prem / Private Lab',
    category: 'private_lab',
    approval_path: 'internal_lab',
    accepted_test_paths: ['isolated lab readiness drill metadata'],
    required_limits: ['approved_intensity_label', 'approved_duration_minutes', 'lab_scope'],
    required_stop_controls: ['SOC kill switch', 'lab operator stop path', 'customer emergency contact'],
    required_evidence: ['lab authorization reference', 'approved scope', 'approved window', 'stop path'],
    customer_action_summary: 'Provide lab authorization and isolation proof for the declared scope.',
    soc_review_summary: 'Confirm lab isolation, stop path, and approved duration before scheduling.',
  }),
  partner_lab: profile({
    provider_key: 'partner_lab',
    display_name: 'Approved Partner Lab',
    category: 'partner',
    approval_path: 'partner_adapter',
    accepted_test_paths: ['approved partner lab readiness drill metadata'],
    required_limits: ['approved_intensity_label', 'approved_duration_minutes', 'partner_scope'],
    required_stop_controls: ['SOC kill switch', 'partner stop bridge', 'customer emergency contact'],
    required_evidence: ['partner approval reference', 'approved scope', 'approved window', 'stop path'],
    customer_action_summary: 'Attach partner authorization with declared targets, dates, limits, and stop bridge.',
    soc_review_summary: 'Verify partner approval scope and stop bridge before adapter start.',
  }),
  generic: profile({
    provider_key: 'generic',
    display_name: 'Generic Provider',
    category: 'generic',
    approval_path: 'manual_coordination',
    accepted_test_paths: ['provider-approved readiness drill metadata'],
    required_limits: ['approved_intensity_label', 'approved_duration_minutes', 'declared_scope'],
    required_stop_controls: ['SOC kill switch', 'provider stop contact', 'customer emergency contact'],
    required_evidence: ['approval reference', 'approved scope', 'approved window', 'stop path'],
    customer_action_summary: 'Provide provider approval metadata covering scope, dates, limits, and stop path.',
    soc_review_summary: 'Confirm approval metadata is complete before SOC scheduling.',
  }),
});

const PROVIDER_ALIASES = Object.freeze({
  amazon: 'aws',
  'amazon web services': 'aws',
  aws: 'aws',
  microsoft: 'azure',
  azure: 'azure',
  'microsoft azure': 'azure',
  gcp: 'gcp',
  google: 'gcp',
  'google cloud': 'gcp',
  'google cloud platform': 'gcp',
  cloudflare: 'cloudflare',
  akamai: 'akamai',
  cdn: 'cdn_other',
  'other cdn': 'cdn_other',
  fastly: 'cdn_other',
  isp: 'isp_carrier',
  carrier: 'isp_carrier',
  telco: 'isp_carrier',
  'on prem': 'on_prem_lab',
  'on-prem': 'on_prem_lab',
  onprem: 'on_prem_lab',
  lab: 'on_prem_lab',
  partner: 'partner_lab',
  'partner lab': 'partner_lab',
});

function valueFromProviderInput(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value !== 'object') return String(value);
  return String(
    value.provider_key ??
      value.provider_name ??
      value.provider ??
      value.name ??
      value.display_name ??
      '',
  );
}

export function normalizeProviderKey(value) {
  const raw = valueFromProviderInput(value).trim().toLowerCase();
  if (!raw) return 'generic';
  if (PROVIDER_APPROVAL_PATHS[raw]) return raw;
  return PROVIDER_ALIASES[raw] ?? 'generic';
}

export function getProviderApprovalPath(value) {
  return PROVIDER_APPROVAL_PATHS[normalizeProviderKey(value)] ?? PROVIDER_APPROVAL_PATHS.generic;
}

export function listProviderApprovalPaths() {
  return Object.values(PROVIDER_APPROVAL_PATHS).map((p) => ({ ...p }));
}

function hasField(item, field) {
  const value = item?.[field];
  if (value == null) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === 'object') {
    if (field === 'valid_window') {
      return Boolean(value.valid_to ?? value.end ?? value.window_end);
    }
    return Object.keys(value).length > 0;
  }
  return String(value).trim() !== '';
}

export function providerApprovalMissingFields(item) {
  const profile = getProviderApprovalPath(item?.provider_key ?? item?.provider_name ?? item);
  return profile.required_artifact_fields.filter((field) => !hasField(item, field));
}

export function buildProviderApprovalMetadata(descriptor = {}) {
  const profile = getProviderApprovalPath(descriptor.provider_key ?? descriptor.provider_name ?? descriptor);
  const base = {
    provider_key: profile.provider_key,
    provider_display_name: profile.display_name,
    provider_category: profile.category,
    approval_path: profile.approval_path,
    accepted_test_paths: [...profile.accepted_test_paths],
    required_artifact_fields: [...profile.required_artifact_fields],
    required_limits: [...profile.required_limits],
    required_stop_controls: [...profile.required_stop_controls],
    required_evidence: [...profile.required_evidence],
    customer_action_summary: profile.customer_action_summary,
    soc_review_summary: profile.soc_review_summary,
  };
  return {
    ...base,
    missing_fields: providerApprovalMissingFields({ ...descriptor, ...base }),
  };
}
