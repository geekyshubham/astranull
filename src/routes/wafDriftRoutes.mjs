import { json } from '../lib/http.mjs';
import { requirePermission } from '../rbac.mjs';
import * as wafDriftWorker from '../services/wafDriftWorker.mjs';

export function isWafDriftScanRoute(path) {
  return path === '/v1/waf/drift-scans/run' || path === '/v1/waf/drift-scans/latest';
}

function respondPostgresRouteNotWired(res) {
  return json(res, 503, { error: 'postgres_route_not_wired' });
}

export function blockPostgresWafDriftScanRoute(runtimeConfig, serviceDeps, path, res) {
  if (runtimeConfig.persistenceMode !== 'postgres') return false;
  if (!isWafDriftScanRoute(path)) return false;
  if (serviceDeps.wafDrift) return false;
  respondPostgresRouteNotWired(res);
  return true;
}

function resolveWafDriftService(runtimeConfig, serviceDeps) {
  if (runtimeConfig.persistenceMode === 'postgres') return serviceDeps.wafDrift;
  return wafDriftWorker;
}

/**
 * Handle WAF drift scan API routes.
 * @returns {Promise<boolean>} true when the request was handled.
 */
export async function tryHandleWafDriftScanRoutes(req, res, url, ctx, runtimeConfig, serviceDeps) {
  const method = req.method ?? 'GET';
  const path = url.pathname;
  if (!isWafDriftScanRoute(path)) return false;

  const wafDriftSvc = resolveWafDriftService(runtimeConfig, serviceDeps);
  if (!wafDriftSvc) {
    respondPostgresRouteNotWired(res);
    return true;
  }

  if (method === 'POST' && path === '/v1/waf/drift-scans/run') {
    const gate = requirePermission(ctx, 'waf:run');
    if (!gate.ok) {
      json(res, gate.status, gate.body);
      return true;
    }
    const result = await wafDriftSvc.runDriftScan(ctx);
    if (result?.skipped) {
      json(res, 404, { error: result.reason ?? 'waf_feature_disabled' });
      return true;
    }
    if (result?.error) {
      json(res, result.status ?? 400, result);
      return true;
    }
    json(res, 200, { scan_result: result.scan_result });
    return true;
  }

  if (method === 'GET' && path === '/v1/waf/drift-scans/latest') {
    const gate = requirePermission(ctx, 'waf:read');
    if (!gate.ok) {
      json(res, gate.status, gate.body);
      return true;
    }
    const result = await wafDriftSvc.getLastScanResult(ctx);
    if (result?.skipped) {
      json(res, 404, { error: result.reason ?? 'waf_feature_disabled' });
      return true;
    }
    if (result?.error) {
      json(res, result.status ?? 400, result);
      return true;
    }
    json(res, 200, { scan_result: result.scan_result });
    return true;
  }

  return false;
}