-- 0030_target_group_archive_restore.sql
-- Portal revamp: soft-delete columns for target group archive/restore (§2.6).

ALTER TABLE target_groups
  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS deleted_by TEXT;

CREATE INDEX IF NOT EXISTS target_groups_archived
  ON target_groups(tenant_id) WHERE deleted_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS target_groups_active
  ON target_groups(tenant_id) WHERE deleted_at IS NULL;