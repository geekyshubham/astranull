import { newId } from './ids.mjs';
import { redactObject, redactString } from './redact.mjs';
import {
  buildProviderApprovalMetadata,
  providerApprovalMissingFields,
} from '../contracts/providerApprovalPaths.mjs';

export const STATES = [
  'draft',
  'submitted',
  'under_review',
  'approved',
  'scheduled',
  'running',
  'stopped',
  'closed',
  'rejected',
];

export const REQUIRED_ARTIFACT_TYPES = [
  'customer_authorization_letter',
  'target_ownership_confirmation',
  'emergency_contacts',
  'stop_criteria',
  'test_plan',
  'business_approval',
  'legal_approval',
  'scope_and_rate_plan',
  'abort_criteria',
];

export const ARTIFACT_PROOF_FIELDS = {
  customer_authorization_letter: ['approval_reference', 'approver', 'valid_window'],
  target_ownership_confirmation: ['approval_reference', 'approver'],
  emergency_contacts: ['emergency_contacts'],
  stop_criteria: ['abort_criteria'],
  test_plan: ['approved_scenario_families', 'valid_window'],
  business_approval: ['approval_reference', 'approver'],
  legal_approval: ['approval_reference', 'approver'],
  scope_and_rate_plan: ['max_rate', 'max_duration_minutes', 'approved_scenario_families', 'valid_window'],
  abort_criteria: ['abort_criteria'],
};

export const TELEMETRY_CATEGORIES = new Set([
  'external_availability',
  'agent_health',
  'service_health',
  'mitigation',
  'stop_evidence',
  'adapter_metric',
]);

export const TELEMETRY_LIVE_STATUSES = new Set([
  'stable',
  'mitigating',
  'degraded',
  'breached_threshold',
  'stopping',
  'stopped',
  'inconclusive',
]);

export const TELEMETRY_ACTIVE_STATES = new Set(['scheduled', 'running', 'stopped', 'closed']);

const KNOWN_ADAPTER_MODES = new Set(['disabled', 'dry-run', 'governed-adapter']);

/**
 * @param {string | undefined} adapterMode
 * @returns {{ error: string, status: number } | null}
 */
export function evaluateHighScaleAdapterStartGate(adapterMode) {
  const mode = adapterMode ?? 'dry-run';
  if (mode === 'dry-run') return null;
  if (mode === 'disabled') return { error: 'adapter_disabled', status: 409 };
  if (mode === 'governed-adapter') {
    return { error: 'governed_adapter_not_configured', status: 503 };
  }
  if (!KNOWN_ADAPTER_MODES.has(mode)) {
    return { error: 'invalid_adapter_mode', status: 500 };
  }
  return null;
}

const TELEMETRY_METRICS_DENYLIST = new Set([
  'packet_payload',
  'raw_packet',
  'raw_packets',
  'packet_data',
  'packets',
  'payload',
  'body',
  'headers',
  'authorization',
  'cookie',
  'raw_log',
  'log_line',
]);

export function telemetryObjectContainsForbiddenKeys(value) {
  if (value == null) return false;
  if (Array.isArray(value)) {
    for (const item of value) {
      if (telemetryObjectContainsForbiddenKeys(item)) return true;
    }
    return false;
  }
  if (typeof value !== 'object') return false;
  for (const key of Object.keys(value)) {
    if (TELEMETRY_METRICS_DENYLIST.has(key.toLowerCase())) return true;
    if (telemetryObjectContainsForbiddenKeys(value[key])) return true;
  }
  return false;
}

export function parseObservedAt(raw) {
  if (raw == null || raw === '') {
    return { ok: true, value: new Date().toISOString() };
  }
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) {
    return { ok: false, error: 'invalid_observed_at', status: 400 };
  }
  return { ok: true, value: d.toISOString() };
}

export function summarizeTelemetryForReport(telemetryItems) {
  const items = telemetryItems ?? [];
  const category_counts = {};
  for (const cat of TELEMETRY_CATEGORIES) {
    category_counts[cat] = 0;
  }
  let latest_live_status = null;
  let latest_live_status_at = null;
  for (const rec of items) {
    category_counts[rec.category] = (category_counts[rec.category] ?? 0) + 1;
    if (rec.live_status) {
      const at = rec.observed_at ?? rec.created_at;
      if (!latest_live_status_at || at > latest_live_status_at) {
        latest_live_status_at = at;
        latest_live_status = rec.live_status;
      }
    }
  }
  return {
    record_count: items.length,
    category_counts,
    latest_live_status,
    latest_live_status_at,
  };
}

export function summarizeArtifacts(req) {
  return (req.artifacts ?? []).map((a) => ({
    id: a.id,
    type: a.type,
    status: a.status,
    reviewed_at: a.reviewed_at ?? null,
  }));
}

export function summarizeSocNotes(notes) {
  return (notes ?? []).map((n) => ({
    id: n.id,
    body: redactString(n.body ?? ''),
    created_at: n.created_at,
    author: n.author ?? n.created_by ?? null,
  }));
}

export function summarizeAdapter(req) {
  const adapter = req.adapter ?? { status: 'idle', traffic_generated: false };
  return {
    status: adapter.status,
    started_at: adapter.started_at ?? null,
    stopped_at: adapter.stopped_at ?? null,
    stop_reason: adapter.stop_reason != null ? redactString(String(adapter.stop_reason)) : null,
    traffic_generated: adapter.traffic_generated === true ? true : false,
    last_action: adapter.last_action ?? null,
  };
}

export function buildTimeline(req) {
  return (req.audit_trail ?? []).map((e) => ({
    action: e.action,
    at: e.at,
    by: e.by,
    metadata: redactObject(e.metadata ?? {}),
  }));
}

const SOC_REPORT_SUMMARY_KEYS = [
  'impact_summary',
  'recommendations',
  'customer_summary',
  'residual_risk',
  'next_steps',
  'attachments',
  'evidence_ids',
];

const SOC_REPORT_SUMMARY_DEFAULTS = {
  impact_summary: '',
  recommendations: '',
  customer_summary: '',
  residual_risk: '',
  next_steps: '',
  attachments: [],
  evidence_ids: [],
};

export function bodySummaryFields(body, existingReport = null) {
  const raw = body ?? {};
  const redacted = redactObject(raw);
  const out = {};
  for (const key of SOC_REPORT_SUMMARY_KEYS) {
    const defaultVal = SOC_REPORT_SUMMARY_DEFAULTS[key];
    if (existingReport && !Object.hasOwn(raw, key)) {
      out[key] = existingReport[key] ?? defaultVal;
      continue;
    }
    out[key] = redacted[key] ?? defaultVal;
  }
  return out;
}

export function isWithinScheduledWindow(window) {
  if (!window?.window_start || !window?.window_end) return false;
  const now = Date.now();
  const start = new Date(window.window_start).getTime();
  const end = new Date(window.window_end).getTime();
  return now >= start && now <= end;
}

function acceptedArtifacts(req) {
  return (req.artifacts ?? []).filter((a) => a.status === 'accepted');
}

function artifactFieldPresent(artifact, field) {
  if (!artifact) return false;
  const value = artifact[field];
  switch (field) {
    case 'valid_window':
      return validWindowEndMs(value) != null;
    case 'emergency_contacts':
      return Array.isArray(value) && value.length > 0;
    case 'abort_criteria':
      return value != null && typeof value === 'object' && Object.keys(value).length > 0;
    case 'approved_scenario_families':
      return Array.isArray(value) && value.length > 0;
    case 'max_rate':
      return value != null && String(value).trim() !== '';
    case 'max_duration_minutes': {
      const n = Number(value);
      return Number.isFinite(n) && n > 0;
    }
    case 'approval_reference':
    case 'approver':
      return value != null && String(value).trim() !== '';
    default:
      return value != null && value !== '';
  }
}

function artifactProofMissingFields(artifact) {
  if (!artifact) return [...(ARTIFACT_PROOF_FIELDS[artifact?.type] ?? [])];
  const required = ARTIFACT_PROOF_FIELDS[artifact.type] ?? [];
  return required.filter((field) => !artifactFieldPresent(artifact, field));
}

function artifactProofExpired(artifact) {
  if (!artifact || artifact.status !== 'accepted') return false;
  if (!artifact.valid_window) return false;
  return isValidWindowExpired(artifact.valid_window);
}

function bestArtifactForType(req, type) {
  const arts = (req.artifacts ?? []).filter((a) => a.type === type);
  const accepted = arts.find((a) => a.status === 'accepted' && !artifactProofExpired(a));
  if (accepted) return accepted;
  const pending = arts.find((a) => a.status === 'pending_review');
  if (pending) return pending;
  const rejected = arts.filter((a) => a.status === 'rejected');
  return rejected[rejected.length - 1] ?? null;
}

function requirementStatusForArtifact(type, artifact) {
  if (!artifact) {
    return {
      type,
      status: 'missing',
      artifact_id: null,
      missing_fields: ARTIFACT_PROOF_FIELDS[type] ?? [],
      reviewed_at: null,
    };
  }
  const missing_fields = artifactProofMissingFields(artifact);
  let status =
    artifact.status === 'accepted' ? 'accepted' : artifact.status === 'rejected' ? 'rejected' : 'pending_review';
  if (artifact.status === 'accepted' && artifactProofExpired(artifact)) status = 'expired';
  else if (artifact.status === 'accepted' && missing_fields.length > 0) status = 'partial';
  else if (artifact.status === 'pending_review' && missing_fields.length > 0) status = 'partial';
  return {
    type,
    status,
    artifact_id: artifact.id,
    missing_fields,
    reviewed_at: artifact.reviewed_at ?? null,
  };
}

export function buildAuthorizationRequirementStatuses(req) {
  return REQUIRED_ARTIFACT_TYPES.map((type) =>
    requirementStatusForArtifact(type, bestArtifactForType(req, type)),
  );
}

function summarizeProviderChecklistForPack(req) {
  return (req.provider_approval_checklist ?? []).map((item) => ({
    provider_name: item.provider_name,
    status: effectiveProviderChecklistStatus(item),
    artifact_id: item.artifact_id ?? null,
    required: item.required !== false,
  }));
}

function summarizeRetainedArtifacts(req) {
  const items = (req.artifacts ?? []).map((a) => ({
    id: a.id,
    type: a.type,
    status: a.status,
    reference_uri_redacted: a.reference_uri_redacted ?? 'metadata://redacted',
    retention_policy: a.retention_policy ?? null,
  }));
  return { count: items.length, items };
}

function computeAuthorizationPackOverall(req, requirements, providerSummary) {
  const reqStatuses = requirements.map((r) => r.status);
  if (providerSummary.some((p) => p.required !== false && p.status === 'expired')) return 'expired';
  if (reqStatuses.some((s) => s === 'expired')) return 'expired';
  if (reqStatuses.some((s) => s === 'rejected')) return 'rejected';

  const providerOk = providerApprovalPackSatisfied(req);
  const allAccepted =
    providerOk && requirements.every((r) => r.status === 'accepted' && (r.missing_fields?.length ?? 0) === 0);

  if (allAccepted) return 'accepted';
  if (reqStatuses.some((s) => s === 'pending_review')) return 'under_review';
  if (reqStatuses.every((s) => s === 'missing')) return 'missing';
  return 'partial';
}

export function refreshAuthorizationPackStatus(req) {
  const requirements = buildAuthorizationRequirementStatuses(req);
  const provider_checklist = summarizeProviderChecklistForPack(req);
  const retained_artifacts = summarizeRetainedArtifacts(req);
  const overall = computeAuthorizationPackOverall(req, requirements, provider_checklist);
  req.authorization_pack_status = {
    overall,
    requirements,
    provider_checklist,
    retained_artifacts,
    updated_at: new Date().toISOString(),
  };
  return req.authorization_pack_status;
}

function validWindowEndMs(validWindow) {
  if (!validWindow || typeof validWindow !== 'object') return null;
  const raw = validWindow.valid_to ?? validWindow.end ?? validWindow.window_end;
  if (raw == null || raw === '') return null;
  const ms = new Date(raw).getTime();
  return Number.isNaN(ms) ? null : ms;
}

function isValidWindowExpired(validWindow) {
  const endMs = validWindowEndMs(validWindow);
  if (endMs == null) return false;
  return Date.now() > endMs;
}

function effectiveProviderChecklistStatus(item) {
  if (isValidWindowExpired(item.valid_window)) return 'expired';
  if ((providerApprovalMissingFields(item).length ?? 0) > 0) return 'partial';
  return item.status ?? 'missing';
}

function providerNameKey(name) {
  return String(name ?? '').trim().toLowerCase();
}

function findChecklistItemByProvider(req, providerName) {
  const key = providerNameKey(providerName);
  if (!key) return null;
  return (
    (req.provider_approval_checklist ?? []).find((item) => providerNameKey(item.provider_name) === key) ?? null
  );
}

function collectProviderDescriptors(body) {
  const descriptors = [];
  const seen = new Set();
  const pushDescriptor = (rawName, meta = {}) => {
    const name = rawName != null && String(rawName).trim() !== '' ? String(rawName).trim() : null;
    if (!name) return;
    const key = providerNameKey(name);
    if (seen.has(key)) return;
    seen.add(key);
    descriptors.push({ provider_name: name, ...meta });
  };

  if (Array.isArray(body?.provider_approvals)) {
    for (const entry of body.provider_approvals) {
      if (entry == null || typeof entry !== 'object') continue;
      pushDescriptor(entry.provider_name ?? entry.provider ?? entry.name, entry);
    }
  }

  const pc = body?.provider_context;
  if (pc && typeof pc === 'object') {
    if (Array.isArray(pc.providers)) {
      for (const entry of pc.providers) {
        if (typeof entry === 'string') pushDescriptor(entry);
        else if (entry && typeof entry === 'object') {
          pushDescriptor(entry.provider_name ?? entry.provider ?? entry.name, entry);
        }
      }
    }
    pushDescriptor(pc.provider_name ?? pc.provider ?? pc.name, pc);
    if (pc.requires_provider_approval === true && descriptors.length === 0) {
      pushDescriptor('unspecified_provider');
    }
  }

  return descriptors;
}

function newProviderChecklistItem(descriptor) {
  const providerName = descriptor.provider_name ?? 'unspecified_provider';
  const providerMetadata = buildProviderApprovalMetadata({ ...descriptor, provider_name: providerName });
  const item = {
    id: newId('pchk'),
    provider_name: redactString(String(providerName)),
    ...providerMetadata,
    required: true,
    status: 'missing',
    approval_reference:
      descriptor.approval_reference != null
        ? redactString(String(descriptor.approval_reference))
        : descriptor.provider_ref != null
          ? redactString(String(descriptor.provider_ref))
          : null,
    valid_window: descriptor.valid_window ?? null,
    approved_targets: descriptor.approved_targets ?? [],
    approved_scenario_families: descriptor.approved_scenario_families ?? descriptor.approved_scenarios ?? [],
    contact_path: descriptor.contact_path != null ? redactString(String(descriptor.contact_path)) : null,
    approved_limits:
      descriptor.approved_limits != null
        ? redactObject(descriptor.approved_limits)
        : descriptor.limits != null
          ? redactObject(descriptor.limits)
          : null,
    provider_specific_evidence:
      descriptor.provider_specific_evidence != null
        ? redactObject(descriptor.provider_specific_evidence)
        : descriptor.provider_evidence != null
          ? redactObject(descriptor.provider_evidence)
          : null,
    emergency_stop_path:
      descriptor.emergency_stop_path != null
        ? redactString(String(descriptor.emergency_stop_path))
        : descriptor.stop_path != null
          ? redactString(String(descriptor.stop_path))
          : null,
    artifact_id: null,
    reviewed_at: null,
    reviewed_by: null,
  };
  item.missing_fields = providerApprovalMissingFields(item);
  return item;
}

export function buildProviderApprovalChecklist(body) {
  return collectProviderDescriptors(body ?? {}).map((d) => newProviderChecklistItem(d));
}

export function syncChecklistFromProviderArtifact(req, artifact, body = {}) {
  if (!req.provider_approval_checklist) req.provider_approval_checklist = [];
  const providerName = artifact.provider_name ?? body.provider_name ?? 'unspecified_provider';
  let item = findChecklistItemByProvider(req, providerName);
  if (!item) {
    item = newProviderChecklistItem({ provider_name: providerName });
    req.provider_approval_checklist.push(item);
  }
  const validWindow = artifact.valid_window ?? body.valid_window ?? item.valid_window;
  item.provider_name = redactString(String(providerName));
  const providerMetadata = buildProviderApprovalMetadata({
    provider_name: providerName,
    provider_key: item.provider_key,
  });
  Object.assign(item, providerMetadata);
  item.approval_reference =
    artifact.provider_ref != null
      ? redactString(String(artifact.provider_ref))
      : body.approval_reference != null
        ? redactString(String(body.approval_reference))
        : item.approval_reference;
  item.valid_window = validWindow;
  item.approved_targets = artifact.approved_targets ?? body.approved_targets ?? item.approved_targets;
  item.approved_scenario_families =
    artifact.approved_scenario_families ?? body.approved_scenario_families ?? item.approved_scenario_families;
  if (body.contact_path != null) {
    item.contact_path = redactString(String(body.contact_path));
  }
  item.approved_limits =
    artifact.approved_limits ?? body.approved_limits ?? item.approved_limits ?? null;
  item.provider_specific_evidence =
    artifact.provider_specific_evidence ??
    body.provider_specific_evidence ??
    item.provider_specific_evidence ??
    null;
  item.emergency_stop_path =
    artifact.emergency_stop_path != null
      ? redactString(String(artifact.emergency_stop_path))
      : body.emergency_stop_path != null
        ? redactString(String(body.emergency_stop_path))
        : item.emergency_stop_path;
  item.artifact_id = artifact.id;
  item.reviewed_at = null;
  item.reviewed_by = null;
  item.missing_fields = providerApprovalMissingFields(item);
  item.status = isValidWindowExpired(validWindow) ? 'expired' : 'pending_review';
}

export function syncChecklistFromProviderArtifactReview(req, artifact) {
  const checklist = req.provider_approval_checklist ?? [];
  let item =
    checklist.find((i) => i.artifact_id === artifact.id) ??
    findChecklistItemByProvider(req, artifact.provider_name);
  if (!item) return;
  item.reviewed_at = artifact.reviewed_at;
  item.reviewed_by = artifact.reviewed_by;
  if (isValidWindowExpired(item.valid_window ?? artifact.valid_window)) {
    item.status = 'expired';
  } else if (providerApprovalMissingFields(item).length > 0) {
    item.missing_fields = providerApprovalMissingFields(item);
    item.status = 'partial';
  } else {
    item.status = artifact.status === 'accepted' ? 'accepted' : 'rejected';
  }
  item.missing_fields = providerApprovalMissingFields(item);
}

function providerApprovalPackSatisfied(req) {
  const checklist = req.provider_approval_checklist;
  if (Array.isArray(checklist) && checklist.length > 0) {
    for (const item of checklist) {
      if (item.required !== false && effectiveProviderChecklistStatus(item) !== 'accepted') {
        return false;
      }
      if (item.required !== false && providerApprovalMissingFields(item).length > 0) return false;
    }
    return true;
  }
  if (req.provider_context?.requires_provider_approval) {
    const types = new Set(acceptedArtifacts(req).map((a) => a.type));
    if (!types.has('provider_approval')) return false;
  }
  return true;
}

export function authorizationPackComplete(req) {
  refreshAuthorizationPackStatus(req);
  return req.authorization_pack_status?.overall === 'accepted';
}

export function authorizationPackIncompleteResponse(req) {
  refreshAuthorizationPackStatus(req);
  const pack = req.authorization_pack_status;
  const missingTypes = (pack?.requirements ?? []).filter((r) => r.status !== 'accepted').map((r) => r.type);
  return {
    error: 'authorization_pack_incomplete',
    status: 409,
    required: REQUIRED_ARTIFACT_TYPES,
    authorization_pack_status: pack,
    requirements: pack?.requirements ?? [],
    missing_types: missingTypes,
  };
}

function providerContextPresent(pc) {
  if (!pc || typeof pc !== 'object') return false;
  if (pc.requires_provider_approval === true) return true;
  const direct = pc.provider_name ?? pc.provider ?? pc.name;
  if (direct != null && String(direct).trim() !== '') return true;
  if (Array.isArray(pc.providers) && pc.providers.length > 0) return true;
  return false;
}

function normalizeRequestedWindow(raw) {
  if (!raw || typeof raw !== 'object') return { ok: false, kind: 'missing' };
  const startRaw = raw.window_start ?? raw.start;
  const endRaw = raw.window_end ?? raw.end;
  if (startRaw == null || startRaw === '' || endRaw == null || endRaw === '') {
    return { ok: false, kind: 'missing' };
  }
  const start = new Date(startRaw);
  const end = new Date(endRaw);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
    return { ok: false, kind: 'invalid' };
  }
  if (start.getTime() >= end.getTime()) {
    return { ok: false, kind: 'invalid' };
  }
  const normalized = {
    window_start: start.toISOString(),
    window_end: end.toISOString(),
  };
  if (raw.timezone != null && String(raw.timezone).trim() !== '') {
    normalized.timezone = redactString(String(raw.timezone).trim());
  }
  return { ok: true, value: normalized };
}

function normalizeEmergencyContacts(raw) {
  if (!Array.isArray(raw) || raw.length === 0) return { ok: false };
  const value = raw.map((entry) => {
    if (entry == null || typeof entry !== 'object') {
      return { contact: redactString(String(entry)) };
    }
    return redactObject(entry);
  });
  return { ok: true, value };
}

function normalizeRequestedLimits(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false };
  const max_rate =
    raw.max_rate != null && String(raw.max_rate).trim() !== '' ? redactString(String(raw.max_rate).trim()) : null;
  const max_duration_minutes = Number(raw.max_duration_minutes);
  const hasDuration = Number.isFinite(max_duration_minutes) && max_duration_minutes > 0;
  if (!max_rate && !hasDuration) return { ok: false };
  const value = {};
  if (max_rate) value.max_rate = max_rate;
  if (hasDuration) value.max_duration_minutes = max_duration_minutes;
  return { ok: true, value };
}

function normalizeScenarioFamilies(raw) {
  if (!Array.isArray(raw) || raw.length === 0) return { ok: false };
  return { ok: true, value: raw.map((f) => redactString(String(f))) };
}

function normalizeStopCriteria(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false };
  const keys = Object.keys(raw);
  if (keys.length === 0) return { ok: false };
  return { ok: true, value: redactObject(raw) };
}

export function validateHighScaleIntakeFields(body) {
  const missing = [];
  const reasonOrObjective = String(body?.reason ?? body?.objective ?? '').trim();
  if (!reasonOrObjective) missing.push('reason_or_objective');

  const windowParsed = normalizeRequestedWindow(body?.requested_window);
  if (!windowParsed.ok && windowParsed.kind === 'missing') missing.push('requested_window');

  if (!normalizeEmergencyContacts(body?.emergency_contacts).ok) missing.push('emergency_contacts');

  if (!providerContextPresent(body?.provider_context)) missing.push('provider_context');

  if (body?.scope_confirmation !== true) missing.push('scope_confirmation');

  if (body?.environment == null || String(body.environment).trim() === '') missing.push('environment');
  if (body?.business_criticality == null || String(body.business_criticality).trim() === '') {
    missing.push('business_criticality');
  }
  if (!normalizeScenarioFamilies(body?.requested_scenario_families).ok) {
    missing.push('requested_scenario_families');
  }
  if (!normalizeRequestedLimits(body?.requested_limits).ok) missing.push('requested_limits');
  if (!normalizeStopCriteria(body?.stop_criteria).ok) missing.push('stop_criteria');
  if (!normalizeStopCriteria(body?.abort_criteria).ok) missing.push('abort_criteria');

  if (missing.length > 0) {
    return { error: 'missing_high_scale_request_fields', status: 400, missing };
  }

  if (!windowParsed.ok) {
    return { error: 'invalid_requested_window', status: 400 };
  }

  const contacts = normalizeEmergencyContacts(body.emergency_contacts);
  const scenarioFamilies = normalizeScenarioFamilies(body.requested_scenario_families);
  const requestedLimits = normalizeRequestedLimits(body.requested_limits);
  const stopCriteria = normalizeStopCriteria(body.stop_criteria);
  const abortCriteria = normalizeStopCriteria(body.abort_criteria);
  return {
    ok: true,
    reasonOrObjective,
    requested_window: windowParsed.value,
    emergency_contacts: contacts.value,
    environment: redactString(String(body.environment).trim()),
    business_criticality: redactString(String(body.business_criticality).trim()),
    requested_scenario_families: scenarioFamilies.value,
    requested_limits: requestedLimits.value,
    stop_criteria: stopCriteria.value,
    abort_criteria: abortCriteria.value,
  };
}

export function storeOptionalHighScaleFields(body) {
  const optional = {};
  if (body.environment != null && String(body.environment).trim() !== '') {
    optional.environment = redactString(String(body.environment).trim());
  }
  if (body.business_criticality != null && String(body.business_criticality).trim() !== '') {
    optional.business_criticality = redactString(String(body.business_criticality).trim());
  }
  if (body.requested_limits != null && typeof body.requested_limits === 'object') {
    const limits = normalizeRequestedLimits(body.requested_limits);
    if (limits.ok) optional.requested_limits = limits.value;
  }
  if (body.maintenance_approval != null && typeof body.maintenance_approval === 'object') {
    optional.maintenance_approval = redactObject(body.maintenance_approval);
  }
  if (Array.isArray(body.provider_contacts) && body.provider_contacts.length > 0) {
    optional.provider_contacts = body.provider_contacts.map((c) =>
      c != null && typeof c === 'object' ? redactObject(c) : { contact: redactString(String(c)) },
    );
  }
  return optional;
}

export function persistArtifactProofMetadata(body) {
  const proof = {};
  if (body.approval_reference != null) {
    proof.approval_reference = redactString(String(body.approval_reference));
  }
  if (body.approver != null) proof.approver = redactString(String(body.approver));
  if (body.valid_window != null && typeof body.valid_window === 'object') {
    proof.valid_window = redactObject(body.valid_window);
  }
  if (Array.isArray(body.approved_targets)) {
    proof.approved_targets = body.approved_targets.map((t) => redactString(String(t)));
  }
  if (Array.isArray(body.approved_scenario_families)) {
    proof.approved_scenario_families = body.approved_scenario_families.map((f) => redactString(String(f)));
  }
  if (body.max_rate != null) proof.max_rate = redactString(String(body.max_rate));
  if (body.max_duration_minutes != null) {
    const n = Number(body.max_duration_minutes);
    if (Number.isFinite(n) && n > 0) proof.max_duration_minutes = n;
  }
  if (Array.isArray(body.emergency_contacts)) {
    proof.emergency_contacts = body.emergency_contacts.map((entry) =>
      entry != null && typeof entry === 'object' ? redactObject(entry) : { contact: redactString(String(entry)) },
    );
  }
  if (body.abort_criteria != null && typeof body.abort_criteria === 'object') {
    proof.abort_criteria = redactObject(body.abort_criteria);
  }
  if (body.retention_policy != null && typeof body.retention_policy === 'object') {
    proof.retention_policy = redactObject(body.retention_policy);
  }
  if (body.retained_artifact_metadata != null && typeof body.retained_artifact_metadata === 'object') {
    proof.retained_artifact_metadata = redactObject(body.retained_artifact_metadata);
  }
  if (body.approved_limits != null && typeof body.approved_limits === 'object') {
    proof.approved_limits = redactObject(body.approved_limits);
  }
  if (body.provider_specific_evidence != null && typeof body.provider_specific_evidence === 'object') {
    proof.provider_specific_evidence = redactObject(body.provider_specific_evidence);
  }
  if (body.emergency_stop_path != null) {
    proof.emergency_stop_path = redactString(String(body.emergency_stop_path));
  }
  return proof;
}

export function buildArtifactFromUpload(ctx, body) {
  const proof = persistArtifactProofMetadata(body);
  return {
    id: newId('art'),
    type: body.type,
    status: 'pending_review',
    provider_name: body.provider_name ?? null,
    provider_ref: body.provider_ref ?? null,
    valid_window: proof.valid_window ?? body.valid_window ?? null,
    approved_targets: proof.approved_targets ?? body.approved_targets ?? [],
    approved_scenario_families: proof.approved_scenario_families ?? body.approved_scenario_families ?? [],
    contact_path: body.contact_path != null ? redactString(String(body.contact_path)) : null,
    approval_reference: proof.approval_reference ?? null,
    approver: proof.approver ?? null,
    max_rate: proof.max_rate ?? null,
    max_duration_minutes: proof.max_duration_minutes ?? null,
    emergency_contacts: proof.emergency_contacts ?? null,
    abort_criteria: proof.abort_criteria ?? null,
    retention_policy: proof.retention_policy ?? null,
    retained_artifact_metadata: proof.retained_artifact_metadata ?? null,
    approved_limits: proof.approved_limits ?? null,
    provider_specific_evidence: proof.provider_specific_evidence ?? null,
    emergency_stop_path: proof.emergency_stop_path ?? null,
    uploader: ctx.userId,
    reference_uri_redacted: body.reference_uri
      ? redactString(String(body.reference_uri))
      : 'metadata://redacted',
    created_at: new Date().toISOString(),
  };
}

export function distinctSocApprovalCount(req) {
  return new Set((req.soc_approvals ?? []).map((a) => a.user_id)).size;
}

export function applyDryRunAdapterStart(req) {
  req.adapter = {
    status: 'stub_running',
    started_at: new Date().toISOString(),
    traffic_generated: false,
    last_action: 'start',
  };
}

export function applyDryRunAdapterStop(req, reason) {
  req.adapter = {
    ...(req.adapter ?? {}),
    status: 'stub_stopped',
    stopped_at: new Date().toISOString(),
    stop_reason: reason ?? null,
    traffic_generated: false,
    last_action: 'stop',
  };
}

export function buildIntakeRiskReviewJson(intake, body, optionalFields) {
  return {
    environment: intake.environment,
    business_criticality: intake.business_criticality,
    requested_scenario_families: intake.requested_scenario_families,
    requested_limits: intake.requested_limits,
    stop_criteria: intake.stop_criteria,
    abort_criteria: intake.abort_criteria,
    ...optionalFields,
  };
}

export function mergeRiskReviewOntoRequest(mapped, riskReview) {
  const risk = riskReview ?? {};
  if (risk.environment != null) mapped.environment = risk.environment;
  if (risk.business_criticality != null) mapped.business_criticality = risk.business_criticality;
  if (risk.requested_scenario_families != null) mapped.requested_scenario_families = risk.requested_scenario_families;
  if (risk.requested_limits != null) mapped.requested_limits = risk.requested_limits;
  if (risk.stop_criteria != null) mapped.stop_criteria = risk.stop_criteria;
  if (risk.abort_criteria != null) mapped.abort_criteria = risk.abort_criteria;
  if (risk.maintenance_approval != null) mapped.maintenance_approval = risk.maintenance_approval;
  if (risk.provider_contacts != null) mapped.provider_contacts = risk.provider_contacts;
  if (risk.authorization_pack_status != null) mapped.authorization_pack_status = risk.authorization_pack_status;
  return mapped;
}
