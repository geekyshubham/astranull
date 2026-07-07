-- 0031_signup_queue_events.sql
-- Portal revamp: customer-facing signup status polling events (§2.7) with tenant RLS.

CREATE TABLE IF NOT EXISTS signup_queue_events (
  id                TEXT PRIMARY KEY,
  tenant_id         TEXT REFERENCES tenants(id),
  request_id        TEXT NOT NULL REFERENCES signup_requests(id) ON DELETE CASCADE,
  event_kind        TEXT NOT NULL
                    CHECK (event_kind IN (
                      'submitted', 'review_started', 'info_requested',
                      'approved', 'rejected', 'provisioned'
                    )),
  actor             TEXT NOT NULL,
  message           TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS signup_queue_events_by_request
  ON signup_queue_events(request_id, created_at DESC);

ALTER TABLE signup_queue_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE signup_queue_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS signup_queue_events_tenant_isolation ON signup_queue_events;
CREATE POLICY signup_queue_events_tenant_isolation ON signup_queue_events
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));