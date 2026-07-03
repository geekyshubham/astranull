#!/usr/bin/env node
/**
 * Grant runtime privileges to the non-superuser application role after migrations.
 * Must run connected as the migration/admin role (table owner), not astranull_app.
 */

const DEFAULT_APP_ROLE = 'astranull_app';

/**
 * @param {import('pg').Pool | import('pg').PoolClient} db
 * @param {string} [roleName]
 */
export async function grantPostgresAppRolePrivileges(db, roleName = DEFAULT_APP_ROLE) {
  const normalized = String(roleName ?? '').trim();
  if (!/^[a-z_][a-z0-9_]*$/.test(normalized)) {
    throw new Error(`Invalid application role name: ${roleName}`);
  }

  const statements = [
    'GRANT USAGE ON SCHEMA public TO astranull_app',
    'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO astranull_app',
    'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO astranull_app',
    'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO astranull_app',
    'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO astranull_app',
  ].map((sql) => sql.replaceAll('astranull_app', normalized));

  for (const sql of statements) {
    await db.query(sql);
  }
}