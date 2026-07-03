-- Non-superuser application role for local Docker acceptance (superusers bypass RLS).
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'astranull_app') THEN
    CREATE ROLE astranull_app
      WITH LOGIN PASSWORD 'astranull_app_local_dev'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END
$$;