-- 0010_waf_addon_postgres_parity.sql
-- Action-item dedupe by WAF asset id (parity with dev/json store).

ALTER TABLE waf_action_items ADD COLUMN IF NOT EXISTS waf_asset_id TEXT;

UPDATE waf_action_items
SET waf_asset_id = evidence_json -> 'asset' ->> 'id'
WHERE waf_asset_id IS NULL
  AND evidence_json -> 'asset' ->> 'id' IS NOT NULL;

DROP INDEX IF EXISTS uniq_waf_action_items_dedupe;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_waf_action_items_dedupe
  ON waf_action_items(tenant_id, waf_asset_id, primary_reason);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_waf_action_items_waf_asset_tenant'
  ) THEN
    ALTER TABLE waf_action_items ADD CONSTRAINT fk_waf_action_items_waf_asset_tenant
      FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
  END IF;
END $$;

-- Notification delivery attempts: persist retry/DLQ metadata (no destination secrets).

ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS attempt_number INT;
ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS max_attempts INT;
ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ;
ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS provider_error TEXT;
ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS exhausted BOOLEAN;
ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS provider_status INT;