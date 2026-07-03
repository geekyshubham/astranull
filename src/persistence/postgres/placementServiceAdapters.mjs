import { computePlacementDiagnosticsFromData } from '../../lib/placementDiagnosticsCompute.mjs';
import {
  buildPlacementReviewsPayload,
} from '../../services/placement.mjs';

const TEST_RUN_LIST_LIMIT = 500;
const RUN_EVENTS_LIMIT = 1000;
const RUN_EVENT_FETCH_RUN_LIMIT = 30;

/** @type {readonly string[]} */
export const PLACEMENT_CORE_CATALOG_REPOSITORY_METHODS = Object.freeze(['listTargetGroups']);

/** @type {readonly string[]} */
export const PLACEMENT_AGENT_CONTROL_REPOSITORY_METHODS = Object.freeze(['listAgents']);

/** @type {readonly string[]} */
export const PLACEMENT_VALIDATION_EVIDENCE_REPOSITORY_METHODS = Object.freeze([
  'listTestRuns',
  'listRunEvents',
]);

/** @type {readonly string[]} */
export const POSTGRES_PLACEMENT_SERVICE_METHODS = Object.freeze(['listPlacementReviews']);

function assertPlacementRepositories(repositories) {
  const coreCatalog = repositories?.coreCatalog;
  const agentControl = repositories?.agentControl;
  const validationEvidence = repositories?.validationEvidence;
  for (const [name, repo, methods] of [
    ['coreCatalog', coreCatalog, PLACEMENT_CORE_CATALOG_REPOSITORY_METHODS],
    ['agentControl', agentControl, PLACEMENT_AGENT_CONTROL_REPOSITORY_METHODS],
    ['validationEvidence', validationEvidence, PLACEMENT_VALIDATION_EVIDENCE_REPOSITORY_METHODS],
  ]) {
    if (!repo) {
      throw new Error(`Postgres placement service requires repositories.${name}.`);
    }
    for (const method of methods) {
      if (typeof repo[method] !== 'function') {
        throw new Error(`Postgres placement service requires repositories.${name}.${method}.`);
      }
    }
  }
}

function sortRunsNewestFirst(runs) {
  return [...runs].sort((a, b) => {
    const aMs = new Date(a.created_at ?? a.updated_at ?? 0).getTime();
    const bMs = new Date(b.created_at ?? b.updated_at ?? 0).getTime();
    return bMs - aMs;
  });
}

/**
 * @param {{
 *   coreCatalog?: Record<string, unknown>,
 *   agentControl?: Record<string, unknown>,
 *   validationEvidence?: Record<string, unknown>,
 * }} repositories
 * @param {{ now?: () => Date }} [options]
 */
export function createPostgresPlacementServices(repositories, options = {}) {
  assertPlacementRepositories(repositories);
  const coreCatalog = repositories.coreCatalog;
  const agentControl = repositories.agentControl;
  const validationEvidence = repositories.validationEvidence;
  const nowFn = options.now ?? (() => new Date());

  return {
    async listPlacementReviews(ctx, query = {}) {
      const tenantId = ctx.tenantId;
      const nowMs = nowFn().getTime();
      const targetGroupId =
        query.target_group_id != null && String(query.target_group_id).trim() !== ''
          ? String(query.target_group_id).trim()
          : null;

      const [groups, agents, runs] = await Promise.all([
        coreCatalog.listTargetGroups(ctx),
        agentControl.listAgents(ctx),
        validationEvidence.listTestRuns(ctx, { limit: TEST_RUN_LIST_LIMIT }),
      ]);

      const sortedRuns = sortRunsNewestFirst(runs);
      const eventFetchRuns = sortedRuns.slice(0, RUN_EVENT_FETCH_RUN_LIMIT);
      const eventLists = await Promise.all(
        eventFetchRuns.map((run) =>
          validationEvidence.listRunEvents(ctx, run.id, { limit: RUN_EVENTS_LIMIT }),
        ),
      );
      const events = eventLists.flat();

      const diagnostics = computePlacementDiagnosticsFromData({
        tenantId,
        groups,
        agents,
        runs,
        events,
        nowMs,
      });

      if (targetGroupId) {
        const match = diagnostics.groups.find((g) => g.target_group_id === targetGroupId);
        if (!match) {
          return { error: 'not_found', status: 404 };
        }
        const filtered = {
          ...diagnostics,
          groups: [match],
        };
        return {
          target_group_id: targetGroupId,
          ...buildPlacementReviewsPayload(filtered),
        };
      }

      return buildPlacementReviewsPayload(diagnostics);
    },
  };
}