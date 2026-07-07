import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import {
  assertRlsPoliciesExist,
  ensureHarnessAppRole,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
  withTenantContextAsAppRole,
} from '../helpers/pg-harness.mjs';

const PORTAL_RLS_TABLES = [
  {
    table: 'dns_challenges',
    policy: 'dns_challenges_tenant_isolation',
    tenantARowId: 'dns_rls_a',
    tenantBProbeId: 'dns_rls_a',
    seedSql: `
      INSERT INTO dns_challenges (
        id, tenant_id, target_group_id, target_id, record_name, record_value, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, now() + interval '15 minutes')
    `,
    seedParams: (ids) => [
      'dns_rls_a',
      ids.tenantA,
      ids.targetGroupA,
      ids.targetA,
      '_astranull-challenge.example.com',
      'token-a',
    ],
    probeSql: (probeId) => ({
      text: `SELECT id FROM dns_challenges WHERE id = $1 OR tenant_id = $2`,
      params: [probeId, 'ten_rls_bypass'],
    }),
  },
  {
    table: 'target_verifications',
    policy: 'target_verifications_tenant_isolation',
    tenantARowId: 'tv_rls_a',
    tenantBProbeId: 'tv_rls_a',
    seedSql: `
      INSERT INTO target_verifications (
        id, tenant_id, target_id, state, source_kind, source_ref, transitioned_by, audit_entry_id
      ) VALUES ($1, $2, $3, 'pending', 'dns_txt', '{}'::jsonb, 'system', 'aud_rls_a')
    `,
    seedParams: (ids) => ['tv_rls_a', ids.tenantA, ids.targetA],
    probeSql: (probeId) => ({
      text: `SELECT id FROM target_verifications WHERE id = $1 OR tenant_id = $2`,
      params: [probeId, 'ten_rls_bypass'],
    }),
  },
  {
    table: 'loa_signatures',
    policy: 'loa_signatures_tenant_isolation',
    tenantARowId: 'loa_rls_a',
    tenantBProbeId: 'loa_rls_a',
    seedSql: `
      INSERT INTO loa_signatures (
        id, tenant_id, target_group_id, signer_name, signer_title, signer_email,
        emergency_contact, attested, scope_snapshot, custody_artifact_id,
        custody_digest_sha256, audit_entry_id
      ) VALUES (
        $1, $2, $3, 'Signer A', 'CISO', 'a@example.com',
        '{"name":"Ops","role":"SRE","phone":"+1","email":"ops@example.com"}'::jsonb,
        true, '{"targets":[]}'::jsonb, 'art_rls_a', 'sha256-a', 'aud_rls_loa_a'
      )
    `,
    seedParams: (ids) => ['loa_rls_a', ids.tenantA, ids.targetGroupA],
    probeSql: (probeId) => ({
      text: `SELECT id FROM loa_signatures WHERE id = $1 OR tenant_id = $2`,
      params: [probeId, 'ten_rls_bypass'],
    }),
  },
  {
    table: 'finding_remediations',
    policy: 'finding_remediations_tenant_isolation',
    tenantARowId: 'rem_rls_a',
    tenantBProbeId: 'rem_rls_a',
    seedSql: `
      INSERT INTO finding_remediations (
        id, tenant_id, finding_id, action_slug, owner_group, description, steps, audit_entry_id
      ) VALUES ($1, $2, $3, 'origin_restrict', 'edge-sre', 'Restrict origin', ARRAY['step'], 'aud_rls_rem_a')
    `,
    seedParams: (ids) => ['rem_rls_a', ids.tenantA, ids.findingA],
    probeSql: (probeId) => ({
      text: `SELECT id FROM finding_remediations WHERE id = $1 OR tenant_id = $2`,
      params: [probeId, 'ten_rls_bypass'],
    }),
  },
  {
    table: 'signup_queue_events',
    policy: 'signup_queue_events_tenant_isolation',
    tenantARowId: 'sqe_rls_a',
    tenantBProbeId: 'sqe_rls_a',
    seedSql: `
      INSERT INTO signup_queue_events (
        id, tenant_id, request_id, event_kind, actor, message
      ) VALUES ($1, $2, $3, 'submitted', 'system', 'submitted')
    `,
    seedParams: (ids) => ['sqe_rls_a', ids.tenantA, ids.signupRequestA],
    probeSql: (probeId) => ({
      text: `SELECT id FROM signup_queue_events WHERE id = $1 OR tenant_id = $2`,
      params: [probeId, 'ten_rls_bypass'],
    }),
  },
];

/**
 * @param {import('pg').PoolClient} client
 * @param {{
 *   tenantA: string,
 *   tenantB: string,
 *   environmentA: string,
 *   environmentB: string,
 *   targetGroupA: string,
 *   targetGroupB: string,
 *   targetA: string,
 *   targetB: string,
 *   findingA: string,
 *   signupRequestA: string,
 * }} ids
 */
async function seedBaseFixtures(client, ids) {
  await client.query(`INSERT INTO tenants (id, name) VALUES ($1, 'tenant A'), ($2, 'tenant B')`, [
    ids.tenantA,
    ids.tenantB,
  ]);
  await client.query(
    `INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, 'env A'), ($3, $4, 'env B')`,
    [ids.environmentA, ids.tenantA, ids.environmentB, ids.tenantB],
  );
  await client.query(
    `INSERT INTO target_groups (id, tenant_id, environment_id, name)
     VALUES ($1, $2, $3, 'group A'), ($4, $5, $6, 'group B')`,
    [
      ids.targetGroupA,
      ids.tenantA,
      ids.environmentA,
      ids.targetGroupB,
      ids.tenantB,
      ids.environmentB,
    ],
  );
  await client.query(
    `INSERT INTO targets (id, tenant_id, target_group_id, kind, value)
     VALUES ($1, $2, $3, 'fqdn', 'a.example'), ($4, $5, $6, 'fqdn', 'b.example')`,
    [ids.targetA, ids.tenantA, ids.targetGroupA, ids.targetB, ids.tenantB, ids.targetGroupB],
  );
  await client.query(
    `INSERT INTO findings (id, tenant_id, target_group_id, target_id, check_id, title, severity, status)
     VALUES ($1, $2, $3, $4, 'chk_rls', 'RLS finding', 's3', 'open')`,
    [ids.findingA, ids.tenantA, ids.targetGroupA, ids.targetA],
  );
  await client.query(
    `INSERT INTO signup_requests (
      id, organization_name, contact_email, contact_name, email_domain,
      requested_plan, intended_use, region, state
    ) VALUES ($1, 'Org A', 'a@example.com', 'Contact A', 'example.com', 'starter', 'eval', 'us', 'submitted')`,
    [ids.signupRequestA],
  );
}

describe('postgres portal RLS (FT-RLS-01)', () => {
  it('portal revamp tables expose tenant isolation policies', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      await ensureHarnessAppRole(pool);
      await assertRlsPoliciesExist(
        pool,
        PORTAL_RLS_TABLES.map((entry) => entry.policy),
      );

      const ids = {
        tenantA: 'ten_rls_a',
        tenantB: 'ten_rls_b',
        environmentA: 'env_rls_a',
        environmentB: 'env_rls_b',
        targetGroupA: 'tg_rls_a',
        targetGroupB: 'tg_rls_b',
        targetA: 'tgt_rls_a',
        targetB: 'tgt_rls_b',
        findingA: 'fnd_rls_a',
        signupRequestA: 'signup_rls_a',
      };

      await withTenantContext(pool, ids.tenantA, async (client) => {
        await seedBaseFixtures(client, ids);
        for (const entry of PORTAL_RLS_TABLES) {
          await client.query(entry.seedSql, entry.seedParams(ids));
        }
      });

      for (const entry of PORTAL_RLS_TABLES) {
        await withTenantContextAsAppRole(pool, ids.tenantA, async (client) => {
          const own = await client.query(`SELECT id FROM ${entry.table} WHERE id = $1`, [
            entry.tenantARowId,
          ]);
          assert.equal(own.rows.length, 1, `${entry.table}: tenant A should read own row`);
        });

        await withTenantContextAsAppRole(pool, ids.tenantB, async (client) => {
          const probe = entry.probeSql(entry.tenantBProbeId);
          const leaked = await client.query(probe.text, probe.params);
          assert.equal(
            leaked.rows.length,
            0,
            `${entry.table}: tenant B must not read tenant A rows via crafted WHERE`,
          );
        });
      }
    });
  });
});