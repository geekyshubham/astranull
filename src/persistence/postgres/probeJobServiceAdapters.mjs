import { newId } from '../../lib/ids.mjs';
import { validateProbeResultBody } from '../../lib/probeResultValidation.mjs';
import { enrichProbeMetadataWithWafCatalog } from '../../lib/wafProductCatalog.mjs';

/** @type {readonly string[]} */
export const PROBE_JOB_REPOSITORY_METHODS = Object.freeze([
  'leasePendingJobsForWorker',
  'getJobById',
  'claimPendingJobForWorker',
  'markJobCompleted',
  'createProbeJob',
  'cancelOpenProbeJobsForTestRuns',
]);

/** @type {readonly string[]} */
export const POSTGRES_PROBE_JOB_SERVICE_METHODS = Object.freeze([
  'listPendingProbeJobsForWorker',
  'ingestProbeResult',
]);

const VALIDATION_PROBE_METHODS = Object.freeze([
  'getTestRun',
  'listRunEvents',
  'appendProbeResultEventIdempotent',
  'appendEvidence',
  'updateTestRun',
]);

function assertProbeJobRepositories(repositories) {
  const probeJobs = repositories?.probeJobs;
  if (!probeJobs || typeof probeJobs !== 'object') {
    throw new Error('Postgres probe job service adapter requires repositories.probeJobs.');
  }
  for (const method of PROBE_JOB_REPOSITORY_METHODS) {
    if (typeof probeJobs[method] !== 'function') {
      throw new Error(`Postgres probe job service adapter requires probeJobs.${method}().`);
    }
  }

  const validationEvidence = repositories?.validationEvidence;
  if (!validationEvidence || typeof validationEvidence !== 'object') {
    throw new Error('Postgres probe job service adapter requires repositories.validationEvidence.');
  }
  for (const method of VALIDATION_PROBE_METHODS) {
    if (typeof validationEvidence[method] !== 'function') {
      throw new Error(
        `Postgres probe job service adapter requires validationEvidence.${method}().`,
      );
    }
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit !== 'object') {
    throw new Error('Postgres probe job service adapter requires repositories.audit.');
  }
  if (typeof audit.appendAuditEvent !== 'function') {
    throw new Error('Postgres probe job service adapter requires audit.appendAuditEvent().');
  }
}

async function findDuplicateProbeEvent(validationEvidence, ctx, runId, nonceHash) {
  const events = await validationEvidence.listRunEvents(ctx, runId, {
    signalType: 'probe_result',
    limit: 1000,
  });
  return events.find((e) => e.signal_type === 'probe_result' && e.nonce_hash === nonceHash) ?? null;
}

/**
 * @param {{
 *   probeJobs?: Record<string, unknown>,
 *   validationEvidence?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{ now?: () => Date, newId?: typeof newId }} [options]
 */
export function createPostgresProbeJobServices(repositories, options = {}) {
  assertProbeJobRepositories(repositories);
  const probeJobs = repositories.probeJobs;
  const validationEvidence = repositories.validationEvidence;
  const audit = repositories.audit;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async listPendingProbeJobsForWorker(ctx) {
      const workerId = ctx.workerId;
      if (!workerId) {
        return [];
      }
      return probeJobs.leasePendingJobsForWorker(ctx, workerId);
    },

    async ingestProbeResult(ctx, jobId, body) {
      const workerId = ctx.workerId;
      const job = await probeJobs.getJobById(ctx, jobId);
      if (!job) return { error: 'job_not_found', status: 404 };

      const evidenceCtx = { tenantId: ctx.tenantId, userId: 'probe_worker', role: 'probe_worker' };
      const run = await validationEvidence.getTestRun(evidenceCtx, job.test_run_id);

      if (job.status === 'completed') {
        const dupProbe = run
          ? await findDuplicateProbeEvent(validationEvidence, evidenceCtx, run.id, job.nonce_hash)
          : null;
        if (dupProbe) {
          return { error: 'probe_already_ingested', status: 409 };
        }
        return { error: 'job_not_open', status: 409 };
      }

      if (job.status === 'leased' && job.leased_by !== workerId) {
        return {
          error: 'job_leased_to_another_worker',
          status: 403,
          message: 'This probe job is leased to a different worker.',
        };
      }

      if (job.status !== 'pending' && job.status !== 'leased') {
        return { error: 'job_not_open', status: 409 };
      }

      const validated = validateProbeResultBody(body, job.constraints ?? {});
      if (!validated.ok) {
        return {
          error: validated.error,
          status: validated.status,
          message: validated.message,
        };
      }
      const { externalResult, safetyAttestation, workerMetadata } = validated;

      if (!run) return { error: 'run_not_found', status: 404 };

      const existingProbe = await findDuplicateProbeEvent(
        validationEvidence,
        evidenceCtx,
        run.id,
        job.nonce_hash,
      );
      if (existingProbe) {
        return { error: 'probe_already_ingested', status: 409 };
      }

      const nowIso = nowFn().toISOString();
      if (job.status === 'pending') {
        await probeJobs.claimPendingJobForWorker(ctx, job.id, workerId, nowIso);
      }

      const probeMetadata = enrichProbeMetadataWithWafCatalog(
        {
          ...workerMetadata,
          external_result: externalResult,
          probe_worker_id: workerId,
          safety_attestation: safetyAttestation,
        },
        job.check_id,
      );

      const probeEvent = await validationEvidence.appendProbeResultEventIdempotent(evidenceCtx, {
        id: newIdFn('event'),
        test_run_id: run.id,
        target_id: job.target_id,
        check_id: job.check_id,
        source: 'probe_worker',
        signal_type: 'probe_result',
        timestamp: nowIso,
        nonce_hash: job.nonce_hash,
        metadata: probeMetadata,
      });

      await validationEvidence.appendEvidence(evidenceCtx, {
        id: newIdFn('ev'),
        test_run_id: run.id,
        label: 'probe_worker_evidence',
        metadata: enrichProbeMetadataWithWafCatalog(
          {
            probe_job_id: job.id,
            probe_event_id: probeEvent.id,
            external_result: externalResult,
            vector_family: job.vector_family,
            safety_attestation: safetyAttestation,
          },
          job.check_id,
        ),
        related_event_id: probeEvent.id,
        created_at: nowIso,
      });

      const correlation = { ...run.correlation, nonce_hash: job.nonce_hash };
      const runPatch = {
        correlation,
        probe_external_result: externalResult,
        awaiting_external_probe: false,
      };
      if (run.status === 'running') {
        runPatch.status = 'collecting';
      }
      await validationEvidence.updateTestRun(evidenceCtx, run.id, runPatch);

      await probeJobs.markJobCompleted(ctx, job.id, nowIso);

      await audit.appendAuditEvent({
        tenant_id: run.tenant_id,
        actor_user_id: workerId,
        actor_role: 'probe_worker',
        action: 'probe_job.result_ingested',
        resource_type: 'probe_job',
        resource_id: job.id,
        metadata: { test_run_id: run.id, external_result: externalResult },
      });

      return {
        probe_event: probeEvent,
        run_id: run.id,
        job_id: job.id,
        tenant_id: run.tenant_id,
      };
    },
  };
}