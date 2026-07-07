const HIGH_SCALE_ACTIONS = ['approve', 'schedule', 'stop', 'close'];

/**
 * API routes that still depend on the dev JSON store (or lack a Postgres service adapter).
 * Auth must run before returning postgres_route_not_wired.
 *
 * @param {string} path
 * @param {string} method
 */
export function isNotificationManagementRoute(path, method) {
  return path === '/v1/notifications' && (method === 'GET' || method === 'POST');
}

/**
 * @param {string} path
 * @param {string} method
 */
export function isAgentUpdateRoute(path, method) {
  if (method === 'GET' && /^\/v1\/agents\/[^/]+\/update$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/agents\/[^/]+\/update-status$/.test(path)) return true;
  if (path === '/v1/agent-update-trust-keys' && (method === 'GET' || method === 'POST')) return true;
  if (method === 'POST' && /^\/v1\/agent-update-trust-keys\/[^/]+\/revoke$/.test(path)) return true;
  if (path === '/v1/agent-updates' && (method === 'GET' || method === 'POST')) return true;
  if (method === 'POST' && /^\/v1\/agent-updates\/[^/]+\/rollback$/.test(path)) return true;
  return false;
}

/**
 * @param {string} path
 * @param {string} method
 * @returns {readonly string[]}
 */
export function requiredAgentUpdateServiceMethods(path, method) {
  if (method === 'GET' && /^\/v1\/agents\/[^/]+\/update$/.test(path)) {
    return ['pollAgentUpdate'];
  }
  if (method === 'POST' && /^\/v1\/agents\/[^/]+\/update-status$/.test(path)) {
    return ['recordAgentUpdateStatus'];
  }
  if (path === '/v1/agent-update-trust-keys' && method === 'POST') {
    return ['createAgentUpdateTrustKey'];
  }
  if (path === '/v1/agent-update-trust-keys' && method === 'GET') {
    return ['listAgentUpdateTrustKeys'];
  }
  if (method === 'POST' && /^\/v1\/agent-update-trust-keys\/[^/]+\/revoke$/.test(path)) {
    return ['revokeAgentUpdateTrustKey'];
  }
  if (path === '/v1/agent-updates' && method === 'POST') {
    return ['createAgentUpdateRelease'];
  }
  if (path === '/v1/agent-updates' && method === 'GET') {
    return ['listAgentUpdateReleases'];
  }
  if (method === 'POST' && /^\/v1\/agent-updates\/[^/]+\/rollback$/.test(path)) {
    return ['requestAgentUpdateRollback'];
  }
  return [];
}

export function isHighScaleRoute(path, method) {
  if (path === '/v1/high-scale-requests' && (method === 'GET' || method === 'POST')) return true;
  if (/^\/v1\/high-scale-requests\/[^/]+\/artifacts$/.test(path) && (method === 'GET' || method === 'POST')) {
    return true;
  }
  if (method === 'POST' && /^\/internal\/soc\/high-scale\/[^/]+\/artifacts\/[^/]+\/review$/.test(path)) {
    return true;
  }
  if (/^\/internal\/soc\/high-scale\/[^/]+\/notes$/.test(path) && (method === 'GET' || method === 'POST')) {
    return true;
  }
  if (method === 'GET' && /^\/internal\/soc\/high-scale\/[^/]+\/adapter-status$/.test(path)) return true;
  if (method === 'POST' && /^\/internal\/soc\/high-scale\/[^/]+\/telemetry\/ingest$/.test(path)) {
    return true;
  }
  if (/^\/internal\/soc\/high-scale\/[^/]+\/telemetry$/.test(path) && (method === 'GET' || method === 'POST')) {
    return true;
  }
  if (/^\/internal\/soc\/high-scale\/[^/]+\/post-test-report$/.test(path) && (method === 'GET' || method === 'POST')) {
    return true;
  }
  if (method === 'POST' && /^\/internal\/soc\/high-scale\/[^/]+\/start$/.test(path)) return true;
  for (const action of HIGH_SCALE_ACTIONS) {
    if (method === 'POST' && new RegExp(`^/internal/soc/high-scale/[^/]+/${action}$`).test(path)) {
      return true;
    }
  }
  if (method === 'POST' && path === '/internal/soc/kill-switch') return true;
  return false;
}

/**
 * @param {string} path
 * @param {string} method
 * @returns {readonly string[]}
 */
export function requiredHighScaleServiceMethods(path, method) {
  if (path === '/v1/high-scale-requests' && method === 'POST') return ['createHighScaleRequest'];
  if (path === '/v1/high-scale-requests' && method === 'GET') return ['listHighScaleRequests'];
  if (/^\/v1\/high-scale-requests\/[^/]+\/artifacts$/.test(path) && method === 'POST') return ['addArtifact'];
  if (/^\/v1\/high-scale-requests\/[^/]+\/artifacts$/.test(path) && method === 'GET') return ['listArtifacts'];
  if (method === 'POST' && /^\/internal\/soc\/high-scale\/[^/]+\/artifacts\/[^/]+\/review$/.test(path)) {
    return ['reviewArtifact'];
  }
  if (/^\/internal\/soc\/high-scale\/[^/]+\/notes$/.test(path) && method === 'POST') return ['addSocNote'];
  if (/^\/internal\/soc\/high-scale\/[^/]+\/notes$/.test(path) && method === 'GET') return ['listSocNotes'];
  if (method === 'GET' && /^\/internal\/soc\/high-scale\/[^/]+\/adapter-status$/.test(path)) {
    return ['getAdapterStatus'];
  }
  if (method === 'POST' && /^\/internal\/soc\/high-scale\/[^/]+\/telemetry\/ingest$/.test(path)) {
    return ['ingestGovernedAdapterTelemetry'];
  }
  if (/^\/internal\/soc\/high-scale\/[^/]+\/telemetry$/.test(path) && method === 'POST') {
    return ['recordHighScaleTelemetry'];
  }
  if (/^\/internal\/soc\/high-scale\/[^/]+\/telemetry$/.test(path) && method === 'GET') {
    return ['listHighScaleTelemetry'];
  }
  if (/^\/internal\/soc\/high-scale\/[^/]+\/post-test-report$/.test(path) && method === 'POST') {
    return ['upsertPostTestReport'];
  }
  if (/^\/internal\/soc\/high-scale\/[^/]+\/post-test-report$/.test(path) && method === 'GET') {
    return ['getPostTestReport'];
  }
  if (method === 'POST' && /^\/internal\/soc\/high-scale\/[^/]+\/start$/.test(path)) {
    return ['transitionHighScale'];
  }
  for (const action of HIGH_SCALE_ACTIONS) {
    if (method === 'POST' && new RegExp(`^/internal/soc/high-scale/[^/]+/${action}$`).test(path)) {
      return ['transitionHighScale'];
    }
  }
  if (method === 'POST' && path === '/internal/soc/kill-switch') return ['setKillSwitch'];
  return [];
}

export function isPlacementRoute(path, method) {
  return method === 'GET' && path === '/v1/placement/reviews';
}

/**
 * @param {string} path
 * @param {string} method
 * @returns {readonly string[]}
 */
export function requiredPlacementServiceMethods(path, method) {
  if (isPlacementRoute(path, method)) return ['listPlacementReviews'];
  return [];
}

export function isPostgresUnwiredRoute(path, method) {
  return false;
}

/**
 * Portal revamp routes (BE-REV-01) registered in src/server.mjs.
 *
 * @param {string} path
 * @param {string} method
 */
export function isPortalRevampRoute(path, method) {
  if (method === 'GET' && /^\/v1\/target-groups\/[^/]+\/dns-ownership$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/dns-ownership\/issue$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/dns-ownership\/verify$/.test(path)) return true;
  if (method === 'GET' && /^\/v1\/targets\/[^/]+$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/loa$/.test(path)) return true;
  if (method === 'GET' && /^\/v1\/target-groups\/[^/]+\/loa$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/loa\/[^/]+\/revoke$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/targets\/[^/]+:confirm$/.test(path)) {
    return true;
  }
  if (method === 'GET' && /^\/v1\/target-groups\/[^/]+\/verification-ladder$/.test(path)) return true;
  if (method === 'GET' && /^\/v1\/connectors\/[^/]+\/inventory$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/targets:bulk-import$/.test(path)) {
    return true;
  }
  if (method === 'GET' && path === '/v1/waf/coverage/summary') return true;
  if (method === 'GET' && /^\/v1\/findings\/[^/]+\/evidence$/.test(path)) return true;
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/restore$/.test(path)) return true;
  if (method === 'GET' && /^\/v1\/signup-requests\/[^/]+\/events$/.test(path)) return true;
  return false;
}

/**
 * Service bindings required for a portal revamp route in postgres mode.
 *
 * @param {string} path
 * @param {string} method
 * @returns {readonly { service: string, methods: readonly string[] }[]}
 */
export function requiredPortalRevampServiceBindings(path, method) {
  if (method === 'GET' && /^\/v1\/target-groups\/[^/]+\/dns-ownership$/.test(path)) {
    return [{ service: 'dnsOwnership', methods: ['listChallenges'] }];
  }
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/dns-ownership\/issue$/.test(path)) {
    return [{ service: 'dnsOwnership', methods: ['issueDnsOwnershipChallenge'] }];
  }
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/dns-ownership\/verify$/.test(path)) {
    return [{ service: 'dnsOwnership', methods: ['verifyDnsOwnership'] }];
  }
  if (method === 'GET' && /^\/v1\/targets\/[^/]+$/.test(path)) {
    return [{ service: 'targetDetail', methods: ['getTargetDetail'] }];
  }
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/loa$/.test(path)) {
    return [{ service: 'loa', methods: ['sign'] }];
  }
  if (method === 'GET' && /^\/v1\/target-groups\/[^/]+\/loa$/.test(path)) {
    return [{ service: 'loa', methods: ['getActive'] }];
  }
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/loa\/[^/]+\/revoke$/.test(path)) {
    return [{ service: 'loa', methods: ['revoke'] }];
  }
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/targets\/[^/]+:confirm$/.test(path)) {
    return [{ service: 'ownershipVerification', methods: ['confirmTarget'] }];
  }
  if (method === 'GET' && /^\/v1\/target-groups\/[^/]+\/verification-ladder$/.test(path)) {
    return [{ service: 'ownershipVerification', methods: ['getLadder'] }];
  }
  if (method === 'GET' && /^\/v1\/connectors\/[^/]+\/inventory$/.test(path)) {
    return [{ service: 'wafPosture', methods: ['getConnectorInventory'] }];
  }
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/targets:bulk-import$/.test(path)) {
    return [{ service: 'targetGroups', methods: ['bulkImportTargets'] }];
  }
  if (method === 'GET' && path === '/v1/waf/coverage/summary') {
    return [{ service: 'wafPosture', methods: ['getCoverageSummary'] }];
  }
  if (method === 'GET' && /^\/v1\/findings\/[^/]+\/evidence$/.test(path)) {
    return [{ service: 'findings', methods: ['getEvidenceBundle'] }];
  }
  if (method === 'POST' && /^\/v1\/target-groups\/[^/]+\/restore$/.test(path)) {
    return [{ service: 'targetGroups', methods: ['restoreArchived'] }];
  }
  if (method === 'GET' && /^\/v1\/signup-requests\/[^/]+\/events$/.test(path)) {
    return [{ service: 'signupIntake', methods: ['listEvents'] }];
  }
  return [];
}

/**
 * @param {string} path
 * @param {string} method
 * @returns {readonly string[]}
 */
export function requiredPortalRevampServiceMethods(path, method) {
  const bindings = requiredPortalRevampServiceBindings(path, method);
  const methods = new Set();
  for (const binding of bindings) {
    for (const name of binding.methods) methods.add(name);
  }
  return [...methods];
}

/**
 * @param {Record<string, unknown>} serviceDeps
 * @param {string} path
 * @param {string} method
 */
export function portalRevampServicesWired(serviceDeps, path, method) {
  const bindings = requiredPortalRevampServiceBindings(path, method);
  if (!bindings.length) return true;
  return bindings.every((binding) => {
    const svc = serviceDeps[binding.service];
    return binding.methods.every((name) => typeof svc?.[name] === 'function');
  });
}