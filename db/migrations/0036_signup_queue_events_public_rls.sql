-- 0036_signup_queue_events_public_rls.sql
-- Pre-tenant signup events have NULL tenant_id; allow public read by request_id.

DROP POLICY IF EXISTS signup_queue_events_tenant_isolation ON signup_queue_events;
CREATE POLICY signup_queue_events_tenant_isolation ON signup_queue_events
  USING (
    tenant_id IS NULL
    OR tenant_id = current_setting('app.tenant_id', true)
  )
  WITH CHECK (
    tenant_id IS NULL
    OR tenant_id = current_setting('app.tenant_id', true)
  );