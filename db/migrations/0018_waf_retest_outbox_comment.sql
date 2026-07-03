-- 0018_waf_retest_outbox_comment.sql
-- Align retest outbox column comment with acceptance catalog markers.

COMMENT ON COLUMN waf_retest_requests.delegated_jobs_json IS
  'Delegated retest safe test runs. Each entry may include status pending_start (reserved before startTestRun), starting (startTestRun succeeded, finalize pending), delegated (persisted with test_run_id), or failed (reconciled or start failure). Legacy entries without status are treated as delegated when test_run_id is present.';