export const GOVERNED_ADAPTER_TYPES = Object.freeze([
  'partner_adapter',
  'provider_fire_drill',
  'internal_lab',
  'manual_coordination',
]);

export const GOVERNED_ADAPTER_REQUIRED_CAPABILITIES = Object.freeze([
  'validate_scope_hash',
  'dry_run',
  'start_with_soc_token',
  'stop_or_abort',
  'status',
  'metrics_metadata',
  'evidence_export',
  'audit_events',
  'kill_switch_stop_path',
]);

export const GOVERNED_ADAPTER_REQUIRED_FIELDS = Object.freeze([
  'adapter_id',
  'adapter_type',
  'owner',
  'approved_provider_path',
  'scope_validation',
  'soc_token_binding',
  'stop_path',
  'kill_switch_integration',
  'evidence_export',
  'audit_event_contract',
  'staging_validation_uri',
  'reviewed_at',
]);

const FORBIDDEN_ADAPTER_KEYS = new Set([
  'api_key',
  'apikey',
  'attack_profile',
  'attack_script',
  'authorization',
  'body',
  'credential',
  'credentials',
  'generator',
  'headers',
  'password',
  'payload',
  'raw_command',
  'raw_headers',
  'raw_log',
  'secret',
  `traffic_${'generator'}`,
  'token',
]);

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function collectForbiddenKeys(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenKeys(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeKey(key);
    if (FORBIDDEN_ADAPTER_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenKeys(nested, keyPath));
  }
  return findings;
}

export function validateGovernedAdapterRegistration(registration) {
  const missing_fields = GOVERNED_ADAPTER_REQUIRED_FIELDS.filter(
    (field) => !hasValue(registration?.[field]),
  );
  const invalid_fields = [];
  const forbidden_fields = collectForbiddenKeys(registration);

  if (
    hasValue(registration?.adapter_type)
    && !GOVERNED_ADAPTER_TYPES.includes(registration.adapter_type)
  ) {
    invalid_fields.push({
      field: 'adapter_type',
      reason: 'unsupported_adapter_type',
      allowed: GOVERNED_ADAPTER_TYPES,
    });
  }

  const capabilities = new Set(registration?.capabilities ?? []);
  const missing_capabilities = GOVERNED_ADAPTER_REQUIRED_CAPABILITIES.filter(
    (capability) => !capabilities.has(capability),
  );

  return {
    ok:
      missing_fields.length === 0
      && invalid_fields.length === 0
      && missing_capabilities.length === 0
      && forbidden_fields.length === 0,
    missing_fields,
    invalid_fields,
    missing_capabilities,
    forbidden_fields,
  };
}

export function governedAdapterProductionReadiness(registration) {
  const validation = validateGovernedAdapterRegistration(registration);
  return {
    ready: validation.ok,
    adapter_id: registration?.adapter_id ?? null,
    adapter_type: registration?.adapter_type ?? null,
    validation,
  };
}
