import http from 'node:http';
import { loadRuntimeConfig } from './config.mjs';
import { requireAgentAuth } from './lib/agentAuth.mjs';
import { resolveHumanApiAuth } from './context.mjs';
import { HttpBodyError, json, parseUrl, readBodyText, readJsonBody, serveStatic, text } from './lib/http.mjs';
import { isProbeWorkerRoute } from './context.mjs';
import * as probeCoordinator from './services/probeCoordinator.mjs';
import { requirePermission } from './rbac.mjs';
import { seedIfEmpty } from './seed.mjs';
import { getStore } from './store.mjs';
import * as agents from './services/agents.mjs';
import * as agentUpdates from './services/agentUpdates.mjs';
import * as highScale from './services/highScale.mjs';
import * as reports from './services/reports.mjs';
import * as targetGroups from './services/targetGroups.mjs';
import * as testRuns from './services/testRuns.mjs';
import * as tokens from './services/tokens.mjs';
import * as serviceAccounts from './services/serviceAccounts.mjs';
import * as secretVault from './services/secretVault.mjs';
import * as state from './services/state.mjs';
import * as findings from './services/findings.mjs';
import * as tenants from './services/tenants.mjs';
import * as events from './services/events.mjs';
import * as evidence from './services/evidence.mjs';
import * as productionReleaseEvidence from './services/productionReleaseEvidence.mjs';
import * as custodyVerification from './services/custodyVerification.mjs';
import * as wafPosture from './services/wafPosture.mjs';
import * as cvePipeline from './services/cvePipeline.mjs';
import * as externalDiscovery from './services/externalDiscovery.mjs';
import * as supplyChainRisk from './services/supplyChainRisk.mjs';
import * as notifications from './services/notifications.mjs';
import {
  metricsPlaintext,
  observabilityFromState,
  observabilityJson,
  incMetric,
} from './lib/metrics.mjs';
import { createFixedWindowRateLimiter, deriveClientKey } from './lib/rateLimit.mjs';
import * as adapterStub from './services/executionAdapterStub.mjs';
import {
  isAgentUpdateRoute,
  isNotificationManagementRoute,
  isHighScaleRoute,
  requiredAgentUpdateServiceMethods,
  requiredHighScaleServiceMethods,
} from './lib/postgresRouteGuard.mjs';

function defaultServiceDeps() {
  return {
    tenants,
    targetGroups,
    tokens,
    serviceAccounts,
    agents,
    agentAuth: { requireAgentAuth },
    testRuns,
    evidence,
    findings: {
      listFindings: findings.listFindings,
      getFinding: findings.getFinding,
      patchFinding: findings.patchFinding,
    },
    reports,
    secretVault,
    events,
    notifications,
    productionReleaseEvidence,
    custodyVerification,
    wafPosture,
    cvePipeline,
    externalDiscovery,
    supplyChainRisk,
  };
}

function buildServiceDeps(runtimeConfig, injectedServices) {
  if (runtimeConfig.persistenceMode === 'postgres') {
    return {
      agentAuth: { requireAgentAuth },
      custodyVerification,
      ...(injectedServices ?? {}),
    };
  }
  return { ...defaultServiceDeps(), ...(injectedServices ?? {}) };
}

function respondPostgresRouteNotWired(res) {
  return json(res, 503, { error: 'postgres_route_not_wired' });
}

function isWafPostureRoute(path) {
  return path.startsWith('/v1/waf/') || path === '/v1/connectors' || path.startsWith('/v1/connectors/');
}

function blockWafFeatureDisabled(runtimeConfig, path, res) {
  if (!isWafPostureRoute(path)) return false;
  if (runtimeConfig.featureFlags.wafPostureEnabled === true) return false;
  json(res, 404, { error: 'waf_feature_disabled' });
  return true;
}

function isDiscoveryRoute(path) {
  return path.startsWith('/v1/discovery/');
}

function blockDiscoveryFeatureDisabled(runtimeConfig, path, res) {
  if (!isDiscoveryRoute(path)) return false;
  if (runtimeConfig.featureFlags.externalDiscoveryEnabled === true) return false;
  json(res, 404, { error: 'discovery_feature_disabled' });
  return true;
}

function blockPostgresWafPostureRoute(runtimeConfig, serviceDeps, path, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isWafPostureRoute(path)) return false;
  if (serviceDeps.wafPosture) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function resolveWafPostureService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.wafPosture;
  return wafPosture;
}

function resolveCvePipelineService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.cvePipeline;
  return cvePipeline;
}

function resolveExternalDiscoveryService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.externalDiscovery;
  return externalDiscovery;
}

function resolveSupplyChainRiskService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.supplyChainRisk;
  return supplyChainRisk;
}

function resolveHighScaleService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.highScale;
  return highScale;
}

function blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isHighScaleRoute(path, method)) return false;
  const required = requiredHighScaleServiceMethods(path, method);
  const svc = serviceDeps.highScale;
  if (required.every((name) => typeof svc?.[name] === 'function')) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function isSecretVaultRoute(path, method) {
  if (path === '/v1/secrets' && (method === 'GET' || method === 'POST')) return true;
  return method === 'POST' && /^\/v1\/secrets\/[^/]+\/rotate$/.test(path);
}

function blockPostgresSecretVaultRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isSecretVaultRoute(path, method)) return false;
  if (serviceDeps.secretVault) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function isReportRoute(path, method) {
  if (path === '/v1/reports' && method === 'POST') return true;
  if (method === 'GET' && /^\/v1\/reports\/[^/]+$/.test(path)) return true;
  if (method === 'GET' && /^\/v1\/reports\/[^/]+\/export$/.test(path)) return true;
  return method === 'POST' && /^\/v1\/findings\/[^/]+\/export$/.test(path);
}

function blockPostgresReportRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isReportRoute(path, method)) return false;
  if (serviceDeps.reports) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresAuditLogRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (method !== 'GET' || path !== '/v1/audit-log') return false;
  if (typeof serviceDeps.audit?.listAuditEntries === 'function') return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresEventsRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (method !== 'POST' || path !== '/v1/events') return false;
  if (typeof serviceDeps.events?.ingestEvent === 'function') return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresNotificationRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isNotificationManagementRoute(path, method)) return false;
  if (typeof serviceDeps.notifications?.listNotifications === 'function'
    && typeof serviceDeps.notifications?.createNotificationRule === 'function') {
    return false;
  }
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresStateRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (method !== 'GET' || path !== '/v1/state') return false;
  if (typeof serviceDeps.state?.getState === 'function') return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isAgentUpdateRoute(path, method)) return false;
  const required = requiredAgentUpdateServiceMethods(path, method);
  const svc = serviceDeps.agentUpdates;
  if (required.every((name) => typeof svc?.[name] === 'function')) {
    return false;
  }
  respondPostgresRouteNotWired(res);
  return true;
}

function blockPostgresProbeJobsRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isProbeWorkerRoute(path, method)) return false;
  const svc = serviceDeps.probeJobs;
  if (
    typeof svc?.listPendingProbeJobsForWorker === 'function' &&
    typeof svc?.ingestProbeResult === 'function'
  ) {
    return false;
  }
  respondPostgresRouteNotWired(res);
  return true;
}

function isProductionReleaseEvidenceAttestationRoute(path, method) {
  return method === 'GET' && path === '/v1/production-release-evidence/attestation';
}

function isProductionReleaseEvidenceRoute(path, method) {
  if (isProductionReleaseEvidenceAttestationRoute(path, method)) return true;
  if (path === '/v1/production-release-evidence' && (method === 'GET' || method === 'POST')) {
    return true;
  }
  return method === 'GET' && /^\/v1\/production-release-evidence\/[^/]+$/.test(path);
}

function blockPostgresProductionReleaseEvidenceRoute(runtimeConfig, serviceDeps, path, method, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isProductionReleaseEvidenceRoute(path, method)) return false;
  const svc = serviceDeps.productionReleaseEvidence;
  if (isProductionReleaseEvidenceAttestationRoute(path, method)) {
    if (typeof svc?.getProductionReleaseEvidenceAttestation === 'function') return false;
    respondPostgresRouteNotWired(res);
    return true;
  }
  if (
    typeof svc?.listProductionReleaseEvidence === 'function' &&
    typeof svc?.recordProductionReleaseEvidence === 'function' &&
    typeof svc?.getProductionReleaseEvidence === 'function'
  ) {
    return false;
  }
  respondPostgresRouteNotWired(res);
  return true;
}

function resolveProbeJobsService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') {
    return serviceDeps.probeJobs;
  }
  return probeCoordinator;
}

function resolveAgentUpdateService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') {
    return serviceDeps.agentUpdates;
  }
  return agentUpdates;
}

async function assessControlPlaneReadiness(runtimeConfig, runtimeHealth) {
  if (runtimeConfig.persistenceMode === 'postgres') {
    if (typeof runtimeHealth !== 'function') {
      return { ok: false, reason: 'postgres_health_unavailable' };
    }
    try {
      await runtimeHealth();
      return { ok: true, persistence: 'postgres' };
    } catch {
      return { ok: false, reason: 'postgres_unhealthy' };
    }
  }
  try {
    const store = getStore();
    if (!store || !Array.isArray(store.tenants)) {
      return { ok: false, reason: 'store_unavailable' };
    }
    return { ok: true, persistence: runtimeConfig.persistenceMode };
  } catch {
    return { ok: false, reason: 'store_unavailable' };
  }
}

function respondRateLimited(res, retryAfterSeconds) {
  const payload = JSON.stringify({ error: 'rate_limited' });
  res.writeHead(429, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Retry-After': String(retryAfterSeconds),
  });
  res.end(payload);
}

export function createServer(options = {}) {
  const runtimeConfig =
    options.runtimeConfig ?? loadRuntimeConfig(options.env ?? process.env);
  const serviceDeps = buildServiceDeps(runtimeConfig, options.services);
  const runtimeHealth = options.runtimeHealth ?? options.persistenceRuntime?.health;
  if (runtimeConfig.persistenceMode !== 'postgres') {
    seedIfEmpty();
  }

  const rateLimiter = runtimeConfig.rateLimit.disabled
    ? null
    : createFixedWindowRateLimiter({
        windowMs: runtimeConfig.rateLimit.windowMs,
        maxRequests: runtimeConfig.rateLimit.maxRequests,
      });

  const server = http.createServer(async (req, res) => {
    const url = parseUrl(req);

    try {
      if (req.method === 'GET' && url.pathname === '/health') {
        incMetric('http_requests_total');
        json(res, 200, { status: 'ok', service: 'astranull' });
        return;
      }

      if (req.method === 'GET' && url.pathname === '/ready') {
        incMetric('http_requests_total');
        const check = await assessControlPlaneReadiness(runtimeConfig, runtimeHealth);
        const timestamp = new Date().toISOString();
        if (!check.ok) {
          json(res, 503, {
            status: 'not_ready',
            service: 'astranull',
            reason: check.reason,
            auth_mode: runtimeConfig.authMode,
            persistence: runtimeConfig.persistenceMode,
            timestamp,
          });
          return;
        }
        json(res, 200, {
          status: 'ready',
          service: 'astranull',
          auth_mode: runtimeConfig.authMode,
          persistence: check.persistence,
          probe_mode: runtimeConfig.probeMode,
          probe_worker_secret_configured: runtimeConfig.probeWorkerSecretConfigured,
          timestamp,
        });
        return;
      }

      if (req.method === 'GET' && url.pathname === '/metrics') {
        text(res, 200, metricsPlaintext());
        return;
      }

      if (url.pathname.startsWith('/v1') || url.pathname.startsWith('/internal')) {
        if (rateLimiter) {
          const decision = rateLimiter.check(
            deriveClientKey(req, { trustProxyHeaders: runtimeConfig.rateLimit.trustProxyHeaders }),
          );
          if (!decision.allowed) {
            incMetric('api_rate_limited_total');
            respondRateLimited(res, decision.retryAfterSeconds);
            return;
          }
        }
        let probeBodyText = '';
        if (
          isProbeWorkerRoute(url.pathname, req.method) &&
          req.method === 'POST' &&
          /^\/internal\/probe\/jobs\/[^/]+\/result$/.test(url.pathname)
        ) {
          probeBodyText = await readBodyText(req, runtimeConfig.maxJsonBodyBytes);
        }
        const auth = await resolveHumanApiAuth(req.headers, url.pathname, req.method, runtimeConfig, {
          bodyText: probeBodyText,
          services: serviceDeps,
        });
        if (!auth.ok) {
          json(res, auth.status, auth.body);
          return;
        }
        const authCtx = auth.ctx ?? { tenantId: null, userId: null, role: 'viewer' };
        const ctx =
          runtimeConfig.persistenceMode === 'postgres'
            ? { ...authCtx, persistenceMode: 'postgres', auditService: serviceDeps.audit }
            : authCtx;
        await handleApi(req, res, url, ctx, runtimeConfig, {
          probeBodyText,
          services: serviceDeps,
        });
        return;
      }

      if (req.method === 'GET') {
        const served = await serveStatic(req, res, url);
        if (served) return;
        text(res, 404, 'Not found');
        return;
      }

      text(res, 404, 'Not found');
    } catch (err) {
      if (err instanceof HttpBodyError) {
        json(res, err.status, { error: err.code });
        return;
      }
      json(res, 500, { error: 'internal_error', message: err.message });
    }
  });

  return server;
}

async function handleApi(req, res, url, ctx, runtimeConfig, options = {}) {
  const path = url.pathname;
  const method = req.method;
  const serviceDeps = options.services ?? defaultServiceDeps();
  incMetric('http_requests_total');

  if (method === 'GET' && path === '/v1/observability') {
    const gate = requirePermission(ctx, 'tenant:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (runtimeConfig.persistenceMode === 'postgres') {
      if (typeof serviceDeps.state?.getState !== 'function') {
        return respondPostgresRouteNotWired(res);
      }
      const tenantState = await serviceDeps.state.getState(ctx);
      return json(res, 200, observabilityFromState(tenantState));
    }
    return json(res, 200, observabilityJson());
  }

  if (method === 'GET' && path === '/v1/tenants/current') {
    const gate = requirePermission(ctx, 'tenant:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const t = await serviceDeps.tenants.getCurrentTenant(ctx);
    if (!t) return json(res, 404, { error: 'not_found' });
    return json(res, 200, t);
  }
  if (method === 'PATCH' && path === '/v1/tenants/current') {
    const gate = requirePermission(ctx, 'tenant:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const t = await serviceDeps.tenants.patchCurrentTenant(ctx, body);
    if (!t) return json(res, 404, { error: 'not_found' });
    return json(res, 200, t);
  }
  if (method === 'GET' && path === '/v1/environments') {
    const gate = requirePermission(ctx, 'environment:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.tenants.listEnvironments(ctx) });
  }
  if (method === 'POST' && path === '/v1/environments') {
    const gate = requirePermission(ctx, 'environment:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    return json(res, 201, await serviceDeps.tenants.createEnvironment(ctx, body));
  }
  const envMatch = path.match(/^\/v1\/environments\/([^/]+)$/);
  if (envMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'environment:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const env = await serviceDeps.tenants.patchEnvironment(ctx, envMatch[1], body);
    if (!env) return json(res, 404, { error: 'not_found' });
    return json(res, 200, env);
  }

  if (method === 'POST' && path === '/v1/events') {
    const gate = requirePermission(ctx, 'event:ingest');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresEventsRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.events.ingestEvent(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, result.duplicate ? 200 : 201, result);
  }
  if (method === 'GET' && path === '/v1/evidence') {
    const gate = requirePermission(ctx, 'evidence:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.evidence.listEvidence(ctx) });
  }
  const evMatch = path.match(/^\/v1\/evidence\/([^/]+)$/);
  if (evMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'evidence:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const item = await serviceDeps.evidence.getEvidence(ctx, evMatch[1]);
    if (!item) return json(res, 404, { error: 'not_found' });
    return json(res, 200, item);
  }

  if (blockDiscoveryFeatureDisabled(runtimeConfig, path, res)) return;
  const discoverySvc = resolveExternalDiscoveryService(runtimeConfig, serviceDeps);

  if (method === 'GET' && path === '/v1/discovery/entities') {
    const gate = requirePermission(ctx, 'discovery:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = discoverySvc.listEntities(ctx);
    if (result?.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { items: result });
  }
  if (method === 'POST' && path === '/v1/discovery/entities') {
    const gate = requirePermission(ctx, 'discovery:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = discoverySvc.createEntity(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  if (method === 'GET' && path === '/v1/discovery/candidates') {
    const gate = requirePermission(ctx, 'discovery:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = discoverySvc.listCandidates(ctx);
    if (result?.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { items: result });
  }
  if (method === 'POST' && path === '/v1/discovery/candidates') {
    const gate = requirePermission(ctx, 'discovery:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = discoverySvc.createCandidate(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  if (method === 'GET' && path === '/v1/discovery/inbox') {
    const gate = requirePermission(ctx, 'discovery:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = discoverySvc.getDiscoveryInbox(ctx);
    if (result?.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const discoveryApproveMatch = path.match(/^\/v1\/discovery\/candidates\/([^/]+)\/approve$/);
  if (discoveryApproveMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'discovery:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = discoverySvc.approveCandidateToTarget(ctx, discoveryApproveMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const discoveryRejectMatch = path.match(/^\/v1\/discovery\/candidates\/([^/]+)\/reject$/);
  if (discoveryRejectMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'discovery:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = discoverySvc.rejectCandidate(ctx, discoveryRejectMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }

  if (blockWafFeatureDisabled(runtimeConfig, path, res)) return;
  if (blockPostgresWafPostureRoute(runtimeConfig, serviceDeps, path, res)) return;
  const wafSvc = resolveWafPostureService(runtimeConfig, serviceDeps);
  const cveSvc = resolveCvePipelineService(runtimeConfig, serviceDeps);
  const supplyChainSvc = resolveSupplyChainRiskService(runtimeConfig, serviceDeps);

  if (method === 'GET' && path === '/v1/waf/assets') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await wafSvc.listWafAssets(ctx) });
  }
  if (method === 'POST' && path === '/v1/waf/assets') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.createWafAsset(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, { asset: result.asset });
  }
  const wafAssetMatch = path.match(/^\/v1\/waf\/assets\/([^/]+)$/);
  if (wafAssetMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const payload = await wafSvc.getWafAsset(ctx, wafAssetMatch[1]);
    if (!payload) return json(res, 404, { error: 'waf_asset_not_found' });
    return json(res, 200, payload);
  }
  if (wafAssetMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.patchWafAsset(ctx, wafAssetMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { asset: result.asset });
  }
  if (method === 'GET' && path === '/v1/waf/coverage') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, await wafSvc.getWafCoverage(ctx));
  }
  if (method === 'POST' && path === '/v1/waf/validations') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.createWafValidation(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, { validation_run: result.validation_run });
  }
  if (method === 'GET' && path === '/v1/waf/validations') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await wafSvc.listWafValidations(ctx) });
  }
  const wafValidationMatch = path.match(/^\/v1\/waf\/validations\/([^/]+)$/);
  if (wafValidationMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const payload = await wafSvc.getWafValidation(ctx, wafValidationMatch[1]);
    if (!payload) return json(res, 404, { error: 'waf_asset_not_found' });
    return json(res, 200, payload);
  }
  const wafFinalizeMatch = path.match(/^\/v1\/waf\/validations\/([^/]+)\/finalize$/);
  if (wafFinalizeMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.finalizeWafValidation(ctx, wafFinalizeMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (method === 'GET' && path === '/v1/waf/drift-events') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await wafSvc.listWafDriftEvents(ctx) });
  }
  const wafDriftMatch = path.match(/^\/v1\/waf\/drift-events\/([^/]+)$/);
  if (wafDriftMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.patchWafDriftEvent(ctx, wafDriftMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { drift_event: result.drift_event });
  }

  if (method === 'GET' && path === '/v1/connectors') {
    const gate = requirePermission(ctx, 'waf:connector_read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await wafSvc.listConnectors(ctx) });
  }
  if (method === 'POST' && path === '/v1/connectors') {
    const gate = requirePermission(ctx, 'waf:connector_write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.createConnector(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, { connector: result.connector });
  }
  const connectorValidateMatch = path.match(/^\/v1\/connectors\/([^/]+)\/validate$/);
  if (connectorValidateMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:connector_write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await wafSvc.validateConnector(ctx, connectorValidateMatch[1]);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const connectorPollMatch = path.match(/^\/v1\/connectors\/([^/]+)\/poll$/);
  if (connectorPollMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:connector_write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.pollConnector(ctx, connectorPollMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 202, { poll_job: result.poll_job, snapshots: result.snapshots });
  }
  const connectorSnapshotsMatch = path.match(/^\/v1\/connectors\/([^/]+)\/snapshots$/);
  if (connectorSnapshotsMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'waf:connector_read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await wafSvc.listConnectorSnapshots(ctx, connectorSnapshotsMatch[1]);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { items: Array.isArray(result) ? result : result.items });
  }
  const connectorDisableMatch = path.match(/^\/v1\/connectors\/([^/]+)\/disable$/);
  if (connectorDisableMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:connector_write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await wafSvc.disableConnector(ctx, connectorDisableMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { connector: result.connector });
  }

  if (method === 'GET' && path === '/v1/waf/cve-pipeline') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = cveSvc.listCvePipelineItems(ctx);
    if (result?.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (method === 'POST' && path === '/v1/waf/cve-pipeline') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = cveSvc.createCvePipelineItem(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  const cveTriageMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/triage$/);
  if (cveTriageMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = cveSvc.triageCvePipelineItem(ctx, cveTriageMatch[1]);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const cveMatchMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/match$/);
  if (cveMatchMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = cveSvc.matchCveAssets(ctx, cveMatchMatch[1]);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const cveRecommendMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/recommend$/);
  if (cveRecommendMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = cveSvc.createRecommendation(ctx, cveRecommendMatch[1], body.vendor);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  const cveStageMatch = path.match(/^\/v1\/waf\/cve-pipeline\/([^/]+)\/stage$/);
  if (cveStageMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = cveSvc.patchCveItemStage(ctx, cveStageMatch[1], body.stage);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }

  if (method === 'GET' && path === '/v1/waf/supply-chain/risks') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = supplyChainSvc.listSupplyChainRisks(ctx);
    if (result?.error) return json(res, result.status ?? 400, result);
    return json(res, 200, { items: result });
  }
  if (method === 'POST' && path === '/v1/waf/supply-chain/risks') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = supplyChainSvc.createSupplyChainRisk(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  if (method === 'POST' && path === '/v1/waf/supply-chain/assess/dangling-cname') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = supplyChainSvc.assessDanglingCname(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  if (method === 'POST' && path === '/v1/waf/supply-chain/assess/dangling-dependency') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = supplyChainSvc.assessDanglingDependency(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const supplyChainStateMatch = path.match(/^\/v1\/waf\/supply-chain\/risks\/([^/]+)\/state$/);
  if (supplyChainStateMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = supplyChainSvc.patchRiskState(ctx, supplyChainStateMatch[1], body.state, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }
  const supplyChainTicketMatch = path.match(/^\/v1\/waf\/supply-chain\/risks\/([^/]+)\/ticket$/);
  if (supplyChainTicketMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = supplyChainSvc.createRemediationTicket(ctx, supplyChainTicketMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }

  if (method === 'GET' && path === '/v1/waf/action-items') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: wafSvc.listActionItems(ctx) });
  }
  if (method === 'POST' && path === '/v1/waf/action-items') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const findingId = body.finding_id ?? body.findingId;
    const finding = findingId ? await serviceDeps.findings.getFinding(ctx, findingId) : null;
    if (!finding) return json(res, 404, { error: 'not_found' });
    const result = wafSvc.createActionItemFromFinding(ctx, finding, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, result.created ? 201 : 200, result);
  }
  const actionItemMatch = path.match(/^\/v1\/waf\/action-items\/([^/]+)$/);
  if (actionItemMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'waf:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = wafSvc.patchActionItemStatus(ctx, actionItemMatch[1], body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 200, result);
  }

  if (method === 'GET' && path === '/v1/production-release-evidence') {
    const gate = requirePermission(ctx, 'release_evidence:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresProductionReleaseEvidenceRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    return json(res, 200, {
      items: await serviceDeps.productionReleaseEvidence.listProductionReleaseEvidence(ctx),
    });
  }
  if (method === 'POST' && path === '/v1/production-release-evidence') {
    const gate = requirePermission(ctx, 'release_evidence:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresProductionReleaseEvidenceRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.productionReleaseEvidence.recordProductionReleaseEvidence(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, { evidence: result });
  }
  if (method === 'GET' && path === '/v1/production-release-evidence/attestation') {
    const gate = requirePermission(ctx, 'release_evidence:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresProductionReleaseEvidenceRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const payload = await serviceDeps.productionReleaseEvidence.getProductionReleaseEvidenceAttestation(ctx);
    return json(res, 200, payload);
  }
  const releaseEvidenceMatch = path.match(/^\/v1\/production-release-evidence\/([^/]+)$/);
  if (releaseEvidenceMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'release_evidence:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresProductionReleaseEvidenceRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const item = await serviceDeps.productionReleaseEvidence.getProductionReleaseEvidence(
      ctx,
      releaseEvidenceMatch[1],
    );
    if (!item) return json(res, 404, { error: 'not_found' });
    return json(res, 200, item);
  }

  if (method === 'GET' && path === '/v1/notifications') {
    const gate = requirePermission(ctx, 'notification:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresNotificationRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const listFn = serviceDeps.notifications?.listNotifications ?? notifications.listNotifications;
    const payload = await listFn(ctx);
    return json(res, 200, payload);
  }
  if (method === 'POST' && path === '/v1/notifications') {
    const gate = requirePermission(ctx, 'notification:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresNotificationRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const createFn =
      serviceDeps.notifications?.createNotificationRule ?? notifications.createNotificationRule;
    const result = await createFn(ctx, body);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }

  if (method === 'GET' && path === '/v1/state') {
    const gate = requirePermission(ctx, 'tenant:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresStateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const getStateFn =
      runtimeConfig.persistenceMode === 'postgres' ? serviceDeps.state.getState : state.getState;
    const payload = await getStateFn(ctx);
    return json(res, 200, payload);
  }

  if (path === '/v1/target-groups' && method === 'GET') {
    const gate = requirePermission(ctx, 'target_group:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.targetGroups.listTargetGroups(ctx) });
  }
  if (path === '/v1/target-groups' && method === 'POST') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    return json(res, 201, await serviceDeps.targetGroups.createTargetGroup(ctx, body));
  }
  const tgMatch = path.match(/^\/v1\/target-groups\/([^/]+)$/);
  if (tgMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'target_group:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const g = await serviceDeps.targetGroups.getTargetGroup(ctx, tgMatch[1]);
    if (!g) return json(res, 404, { error: 'not_found' });
    return json(res, 200, g);
  }
  const tgtMatch = path.match(/^\/v1\/target-groups\/([^/]+)\/targets$/);
  if (tgtMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'target_group:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const t = await serviceDeps.targetGroups.addTarget(ctx, tgtMatch[1], body);
    if (!t) return json(res, 404, { error: 'not_found' });
    return json(res, 201, t);
  }

  if (path === '/v1/bootstrap-tokens' && method === 'POST') {
    const gate = requirePermission(ctx, 'bootstrap_token:create');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const { token, secret } = await serviceDeps.tokens.createBootstrapToken(ctx, body);
    const { token_hash, token_salt, ...meta } = token;
    return json(res, 201, { ...meta, secret });
  }
  if (path === '/v1/bootstrap-tokens' && method === 'GET') {
    const gate = requirePermission(ctx, 'bootstrap_token:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.tokens.listBootstrapTokens(ctx) });
  }
  const revokeTok = path.match(/^\/v1\/bootstrap-tokens\/([^/]+)\/revoke$/);
  if (revokeTok && method === 'POST') {
    const gate = requirePermission(ctx, 'bootstrap_token:revoke');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const t = await serviceDeps.tokens.revokeBootstrapToken(ctx, revokeTok[1]);
    if (!t) return json(res, 404, { error: 'not_found' });
    return json(res, 200, t);
  }

  if (path === '/v1/service-accounts' && method === 'POST') {
    const gate = requirePermission(ctx, 'service_account:create');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.serviceAccounts.createServiceAccount(ctx, body);
    if (result.error) {
      return json(res, result.status ?? 400, { error: result.error, message: result.message });
    }
    const { account, secret } = result;
    const { secret_salt, secret_hash, ...meta } = account;
    return json(res, 201, { ...meta, secret });
  }
  if (path === '/v1/service-accounts' && method === 'GET') {
    const gate = requirePermission(ctx, 'service_account:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.serviceAccounts.listServiceAccounts(ctx) });
  }
  const revokeSvc = path.match(/^\/v1\/service-accounts\/([^/]+)\/revoke$/);
  if (revokeSvc && method === 'POST') {
    const gate = requirePermission(ctx, 'service_account:revoke');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const acct = await serviceDeps.serviceAccounts.revokeServiceAccount(ctx, revokeSvc[1]);
    if (!acct) return json(res, 404, { error: 'not_found' });
    return json(res, 200, acct);
  }
  const rotateSvc = path.match(/^\/v1\/service-accounts\/([^/]+)\/rotate$/);
  if (rotateSvc && method === 'POST') {
    const gate = requirePermission(ctx, 'service_account:rotate');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await serviceDeps.serviceAccounts.rotateServiceAccount(ctx, rotateSvc[1]);
    if (result === null) return json(res, 404, { error: 'not_found' });
    if (result.error) {
      return json(res, result.status ?? 400, { error: result.error, message: result.message });
    }
    const { account, secret } = result;
    const { secret_salt, secret_hash, ...meta } = account;
    return json(res, 200, { ...meta, secret });
  }

  if (path === '/v1/secrets' && method === 'POST') {
    const gate = requirePermission(ctx, 'secret:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresSecretVaultRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.secretVault.storeEncryptedSecret(
      ctx,
      body,
      runtimeConfig.secretEncryptionKey,
    );
    if (result.error) {
      return json(res, result.status ?? 400, { error: result.error, message: result.message });
    }
    return json(res, 201, result);
  }
  if (path === '/v1/secrets' && method === 'GET') {
    const gate = requirePermission(ctx, 'secret:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresSecretVaultRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    return json(res, 200, { items: await serviceDeps.secretVault.listEncryptedSecrets(ctx) });
  }
  const rotateSecret = path.match(/^\/v1\/secrets\/([^/]+)\/rotate$/);
  if (rotateSecret && method === 'POST') {
    const gate = requirePermission(ctx, 'secret:rotate');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresSecretVaultRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.secretVault.rotateEncryptedSecret(
      ctx,
      rotateSecret[1],
      body,
      runtimeConfig.secretEncryptionKey,
    );
    if (result === null) return json(res, 404, { error: 'not_found' });
    if (result.error) {
      return json(res, result.status ?? 400, { error: result.error, message: result.message });
    }
    return json(res, 200, result);
  }

  if (path === '/v1/agents/register' && method === 'POST') {
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const tenantId =
      runtimeConfig.authMode === 'dev-headers' ? ctx.tenantId : null;
    const result = await serviceDeps.agents.registerAgent(body, tenantId);
    if (result.error) return json(res, result.status ?? 400, { error: result.error });
    return json(res, 201, result);
  }
  if (path === '/v1/agents' && method === 'GET') {
    const gate = requirePermission(ctx, 'agent:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.agents.listAgents(ctx) });
  }
  const agentRevokeMatch = path.match(/^\/v1\/agents\/([^/]+)\/revoke$/);
  if (agentRevokeMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'agent:revoke');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await serviceDeps.agents.revokeAgent(ctx, agentRevokeMatch[1]);
    if (!result) return json(res, 404, { error: 'not_found' });
    return json(res, 200, result);
  }
  const hbMatch = path.match(/^\/v1\/agents\/([^/]+)\/heartbeat$/);
  if (hbMatch && method === 'POST') {
    const auth = await serviceDeps.agentAuth.requireAgentAuth(req.headers, hbMatch[1], runtimeConfig);
    if (auth.error) return json(res, auth.status, { error: auth.error });
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.agents.heartbeatAgent(auth.agent, body);
    return json(res, 200, result);
  }
  const jobsMatch = path.match(/^\/v1\/agents\/([^/]+)\/jobs$/);
  if (jobsMatch && method === 'GET') {
    const auth = await serviceDeps.agentAuth.requireAgentAuth(req.headers, jobsMatch[1], runtimeConfig);
    if (auth.error) return json(res, auth.status, { error: auth.error });
    const poll = await serviceDeps.agents.pollJobs(auth.agent, 3000);
    return json(res, 200, { jobs: poll.jobs });
  }
  const ackMatch = path.match(/^\/v1\/agents\/([^/]+)\/jobs\/([^/]+)\/ack$/);
  if (ackMatch && method === 'POST') {
    const auth = await serviceDeps.agentAuth.requireAgentAuth(req.headers, ackMatch[1], runtimeConfig);
    if (auth.error) return json(res, auth.status, { error: auth.error });
    const job = await serviceDeps.agents.ackJob(auth.agent, ackMatch[2]);
    if (!job) return json(res, 404, { error: 'not_found' });
    return json(res, 200, { job });
  }
  const obsMatch = path.match(/^\/v1\/agents\/([^/]+)\/observations$/);
  if (obsMatch && method === 'POST') {
    const auth = await serviceDeps.agentAuth.requireAgentAuth(req.headers, obsMatch[1], runtimeConfig);
    if (auth.error) return json(res, auth.status, { error: auth.error });
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const agentCtx = {
      ...ctx,
      tenantId: auth.agent.tenant_id,
      userId: 'agent',
      role: 'agent',
    };
    const result = await serviceDeps.testRuns.ingestObservation(agentCtx, auth.agent.id, body);
    if (result.error) return json(res, result.status, { error: result.error });
    return json(res, 201, result);
  }
  const agentUpdateSvc = resolveAgentUpdateService(runtimeConfig, serviceDeps);
  const agentUpdatePollMatch = path.match(/^\/v1\/agents\/([^/]+)\/update$/);
  if (agentUpdatePollMatch && method === 'GET') {
    const auth = await serviceDeps.agentAuth.requireAgentAuth(req.headers, agentUpdatePollMatch[1], runtimeConfig);
    if (auth.error) return json(res, auth.status, { error: auth.error });
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    return json(res, 200, await agentUpdateSvc.pollAgentUpdate(auth.agent));
  }
  const agentUpdateStatusMatch = path.match(/^\/v1\/agents\/([^/]+)\/update-status$/);
  if (agentUpdateStatusMatch && method === 'POST') {
    const auth = await serviceDeps.agentAuth.requireAgentAuth(req.headers, agentUpdateStatusMatch[1], runtimeConfig);
    if (auth.error) return json(res, auth.status, { error: auth.error });
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await agentUpdateSvc.recordAgentUpdateStatus(auth.agent, body);
    if (result.error) return json(res, result.status ?? 400, { error: result.error });
    return json(res, 201, result);
  }

  if (path === '/v1/agent-update-trust-keys' && method === 'POST') {
    const gate = requirePermission(ctx, 'agent_update:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await agentUpdateSvc.createAgentUpdateTrustKey(ctx, body);
    if (result.error) return json(res, result.status ?? 400, { error: result.error });
    return json(res, 201, result);
  }
  if (path === '/v1/agent-update-trust-keys' && method === 'GET') {
    const gate = requirePermission(ctx, 'agent_update:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    return json(res, 200, { items: await agentUpdateSvc.listAgentUpdateTrustKeys(ctx) });
  }
  const agentUpdateTrustKeyRevokeMatch = path.match(/^\/v1\/agent-update-trust-keys\/([^/]+)\/revoke$/);
  if (agentUpdateTrustKeyRevokeMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'agent_update:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const result = await agentUpdateSvc.revokeAgentUpdateTrustKey(ctx, agentUpdateTrustKeyRevokeMatch[1]);
    if (result.error) return json(res, result.status ?? 400, { error: result.error });
    return json(res, 200, result);
  }

  if (path === '/v1/agent-updates' && method === 'POST') {
    const gate = requirePermission(ctx, 'agent_update:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await agentUpdateSvc.createAgentUpdateRelease(ctx, body);
    if (result.error) return json(res, result.status ?? 400, { error: result.error });
    return json(res, 201, result);
  }
  if (path === '/v1/agent-updates' && method === 'GET') {
    const gate = requirePermission(ctx, 'agent_update:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    return json(res, 200, { items: await agentUpdateSvc.listAgentUpdateReleases(ctx) });
  }
  const agentUpdateRollbackMatch = path.match(/^\/v1\/agent-updates\/([^/]+)\/rollback$/);
  if (agentUpdateRollbackMatch && method === 'POST') {
    const gate = requirePermission(ctx, 'agent_update:rollback');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAgentUpdateRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const result = await agentUpdateSvc.requestAgentUpdateRollback(ctx, agentUpdateRollbackMatch[1]);
    if (result.error) return json(res, result.status ?? 400, { error: result.error });
    return json(res, 200, result);
  }

  if (path === '/v1/checks' && method === 'GET') {
    return json(res, 200, { items: await serviceDeps.testRuns.listChecks() });
  }
  if (path === '/v1/test-runs' && method === 'POST') {
    const gate = requirePermission(ctx, 'test_run:start');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.testRuns.startTestRun(ctx, body, runtimeConfig);
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  if (path === '/v1/test-runs' && method === 'GET') {
    const gate = requirePermission(ctx, 'test_run:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.testRuns.listTestRuns(ctx) });
  }
  const runMatch = path.match(/^\/v1\/test-runs\/([^/]+)$/);
  if (runMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'test_run:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const run = await serviceDeps.testRuns.getTestRun(ctx, runMatch[1]);
    if (!run) return json(res, 404, { error: 'not_found' });
    return json(res, 200, run);
  }
  const runEvents = path.match(/^\/v1\/test-runs\/([^/]+)\/events$/);
  if (runEvents && method === 'GET') {
    const gate = requirePermission(ctx, 'test_run:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const events = await serviceDeps.testRuns.getRunEvents(ctx, runEvents[1]);
    if (events === null) return json(res, 404, { error: 'not_found' });
    return json(res, 200, { items: events });
  }
  const runFinalize = path.match(/^\/v1\/test-runs\/([^/]+)\/finalize$/);
  if (runFinalize && method === 'POST') {
    const gate = requirePermission(ctx, 'test_run:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await serviceDeps.testRuns.finalizeTestRun(ctx, runFinalize[1]);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 409, { error: result.error });
    return json(res, 200, result);
  }
  const runCancel = path.match(/^\/v1\/test-runs\/([^/]+)\/cancel$/);
  if (runCancel && method === 'POST') {
    const gate = requirePermission(ctx, 'test_run:start');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const result = await serviceDeps.testRuns.cancelTestRun(ctx, runCancel[1]);
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 409, { error: result.error });
    return json(res, 200, result.run);
  }

  if (path === '/v1/findings' && method === 'GET') {
    const gate = requirePermission(ctx, 'finding:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    return json(res, 200, { items: await serviceDeps.findings.listFindings(ctx) });
  }
  const fMatch = path.match(/^\/v1\/findings\/([^/]+)$/);
  if (fMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'finding:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const f = await serviceDeps.findings.getFinding(ctx, fMatch[1]);
    if (!f) return json(res, 404, { error: 'not_found' });
    return json(res, 200, f);
  }
  if (fMatch && method === 'PATCH') {
    const gate = requirePermission(ctx, 'finding:write');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const f = await serviceDeps.findings.patchFinding(ctx, fMatch[1], body);
    if (!f) return json(res, 404, { error: 'not_found' });
    return json(res, 200, f);
  }

  if (path === '/v1/reports' && method === 'POST') {
    const gate = requirePermission(ctx, 'report:create');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresReportRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    return json(res, 201, await serviceDeps.reports.createReport(ctx, body));
  }
  const rptMatch = path.match(/^\/v1\/reports\/([^/]+)$/);
  if (rptMatch && method === 'GET') {
    const gate = requirePermission(ctx, 'report:create');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresReportRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const r = await serviceDeps.reports.getReport(ctx, rptMatch[1]);
    if (!r) return json(res, 404, { error: 'not_found' });
    return json(res, 200, r);
  }
  const rptExport = path.match(/^\/v1\/reports\/([^/]+)\/export$/);
  if (rptExport && method === 'GET') {
    const gate = requirePermission(ctx, 'report:create');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresReportRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const format = url.searchParams.get('format') || 'json';
    const out = await serviceDeps.reports.exportReport(ctx, rptExport[1], format);
    if (!out) return json(res, 404, { error: 'not_found' });
    if (format === 'markdown') {
      text(res, 200, out.content, 'text/markdown; charset=utf-8');
      return;
    }
    if (format === 'html') {
      text(res, 200, out.content, 'text/html; charset=utf-8');
      return;
    }
    return json(res, 200, out);
  }
  const findingExport = path.match(/^\/v1\/findings\/([^/]+)\/export$/);
  if (findingExport && method === 'POST') {
    const gate = requirePermission(ctx, 'finding:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresReportRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const out = await serviceDeps.reports.exportFinding(ctx, findingExport[1]);
    if (!out) return json(res, 404, { error: 'not_found' });
    return json(res, 200, out);
  }

  if (path === '/v1/custody/verify' && method === 'POST') {
    const gate = requirePermission(ctx, 'audit:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await serviceDeps.custodyVerification.verifyCustodyExport(ctx, body);
    return json(res, 200, result);
  }

  if (path === '/v1/audit-log' && method === 'GET') {
    const gate = requirePermission(ctx, 'audit:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresAuditLogRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    if (runtimeConfig.persistenceMode === 'postgres') {
      const items = await serviceDeps.audit.listAuditEntries(ctx, { limit: 200 });
      return json(res, 200, { items });
    }
    const items = getStore().auditLog.filter((a) => a.tenant_id === ctx.tenantId).slice(-200);
    return json(res, 200, { items });
  }

  const hsSvc = resolveHighScaleService(runtimeConfig, serviceDeps);
  if (path === '/v1/high-scale-requests' && method === 'POST') {
    const gate = requirePermission(ctx, 'high_scale:request');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const created = await Promise.resolve(hsSvc.createHighScaleRequest(ctx, body));
    if (created?.error) return json(res, created.status ?? 400, created);
    return json(res, 201, created);
  }
  if (path === '/v1/high-scale-requests' && method === 'GET') {
    const gate = requirePermission(ctx, 'high_scale:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const items = await Promise.resolve(hsSvc.listHighScaleRequests(ctx));
    return json(res, 200, { items });
  }
  const hsArtPost = path.match(/^\/v1\/high-scale-requests\/([^/]+)\/artifacts$/);
  if (hsArtPost && method === 'POST') {
    const gate = requirePermission(ctx, 'high_scale:request');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const art = await Promise.resolve(hsSvc.addArtifact(ctx, hsArtPost[1], body));
    if (!art) return json(res, 404, { error: 'not_found' });
    return json(res, 201, art);
  }
  if (hsArtPost && method === 'GET') {
    const gate = requirePermission(ctx, 'high_scale:read');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const items = await Promise.resolve(hsSvc.listArtifacts(ctx, hsArtPost[1]));
    if (items === null) return json(res, 404, { error: 'not_found' });
    return json(res, 200, { items });
  }
  const hsArtReview = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/artifacts\/([^/]+)\/review$/);
  if (hsArtReview && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await Promise.resolve(hsSvc.reviewArtifact(ctx, hsArtReview[1], hsArtReview[2], body));
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status, result);
    return json(res, 200, result);
  }
  const hsNotes = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/notes$/);
  if (hsNotes && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const note = await Promise.resolve(hsSvc.addSocNote(ctx, hsNotes[1], body));
    if (!note) return json(res, 404, { error: 'not_found' });
    return json(res, 201, note);
  }
  if (hsNotes && method === 'GET') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const items = await Promise.resolve(hsSvc.listSocNotes(ctx, hsNotes[1]));
    if (items === null) return json(res, 404, { error: 'not_found' });
    return json(res, 200, { items });
  }
  const hsAdapter = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/adapter-status$/);
  if (hsAdapter && method === 'GET') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const status =
      runtimeConfig.persistenceMode === 'postgres'
        ? await hsSvc.getAdapterStatus(ctx, hsAdapter[1])
        : adapterStub.status(ctx, hsAdapter[1]);
    if (!status) return json(res, 404, { error: 'not_found' });
    return json(res, 200, status);
  }
  const hsTelemetry = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/telemetry$/);
  if (hsTelemetry && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await Promise.resolve(hsSvc.recordHighScaleTelemetry(ctx, hsTelemetry[1], body));
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 400, result);
    return json(res, 201, result);
  }
  if (hsTelemetry && method === 'GET') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const items = await Promise.resolve(hsSvc.listHighScaleTelemetry(ctx, hsTelemetry[1]));
    if (items === null) return json(res, 404, { error: 'not_found' });
    return json(res, 200, { items });
  }
  const hsPostTestReport = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/post-test-report$/);
  if (hsPostTestReport && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const result = await Promise.resolve(hsSvc.upsertPostTestReport(ctx, hsPostTestReport[1], body));
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 409, result);
    return json(res, result.created ? 201 : 200, result.report);
  }
  if (hsPostTestReport && method === 'GET') {
    const gate = requirePermission(ctx, 'soc:high_scale');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const result = await Promise.resolve(hsSvc.getPostTestReport(ctx, hsPostTestReport[1]));
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 404, result);
    return json(res, 200, result);
  }

  const socStart = path.match(/^\/internal\/soc\/high-scale\/([^/]+)\/start$/);
  if (socStart && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:high_scale', { resource_type: 'high_scale', metadata: { action: 'start' } });
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const result = await Promise.resolve(
      hsSvc.transitionHighScale(ctx, socStart[1], 'start', {
        adapter_mode: runtimeConfig.highScaleAdapterMode,
      }),
    );
    if (!result) return json(res, 404, { error: 'not_found' });
    if (result.error) return json(res, result.status ?? 409, result);
    return json(res, 200, result);
  }
  for (const action of ['approve', 'schedule', 'stop', 'close']) {
    const m = path.match(new RegExp(`^/internal/soc/high-scale/([^/]+)/${action}$`));
    if (m && method === 'POST') {
      const gate = requirePermission(ctx, 'soc:high_scale');
      if (!gate.ok) return json(res, gate.status, gate.body);
      if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
      const body = action === 'schedule' ? await readJsonBody(req, runtimeConfig.maxJsonBodyBytes) : {};
      const result = await Promise.resolve(hsSvc.transitionHighScale(ctx, m[1], action, body));
      if (!result) return json(res, 404, { error: 'not_found' });
      if (result.error) return json(res, result.status ?? 409, result);
      return json(res, 200, result);
    }
  }
  if (path === '/internal/soc/kill-switch' && method === 'POST') {
    const gate = requirePermission(ctx, 'soc:kill_switch');
    if (!gate.ok) return json(res, gate.status, gate.body);
    if (blockPostgresHighScaleRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const body = await readJsonBody(req, runtimeConfig.maxJsonBodyBytes);
    const ks = await Promise.resolve(hsSvc.setKillSwitch(ctx, Boolean(body.active), body.reason));
    return json(res, 200, ks);
  }

  const probeJobsSvc = resolveProbeJobsService(runtimeConfig, serviceDeps);
  if (path === '/internal/probe/jobs' && method === 'GET') {
    if (!ctx.workerId) return json(res, 401, { error: 'unauthorized' });
    if (blockPostgresProbeJobsRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    const jobs = await probeJobsSvc.listPendingProbeJobsForWorker(ctx, runtimeConfig);
    return json(res, 200, { jobs });
  }
  const probeResultMatch = path.match(/^\/internal\/probe\/jobs\/([^/]+)\/result$/);
  if (probeResultMatch && method === 'POST') {
    if (!ctx.workerId) return json(res, 401, { error: 'unauthorized' });
    if (blockPostgresProbeJobsRoute(runtimeConfig, serviceDeps, path, method, res)) return;
    let body;
    try {
      const raw = options.probeBodyText ?? '';
      body = raw.trim() ? JSON.parse(raw) : {};
    } catch {
      return json(res, 400, { error: 'invalid_json' });
    }
    const result = await probeJobsSvc.ingestProbeResult(
      ctx,
      probeResultMatch[1],
      body,
      runtimeConfig,
    );
    if (result.error) return json(res, result.status ?? 400, result);
    const finalizeFn = serviceDeps.testRuns?.maybeFinalizeRunAfterProbeIngest;
    if (typeof finalizeFn === 'function') {
      if (result.tenant_id) {
        await finalizeFn(
          { tenantId: result.tenant_id, userId: 'probe_worker', role: 'probe_worker' },
          result.run_id,
        );
      } else {
        await finalizeFn(result.run_id);
      }
    }
    return json(res, 201, result);
  }

  json(res, 404, { error: 'not_found' });
}
