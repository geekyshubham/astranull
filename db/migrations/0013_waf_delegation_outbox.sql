-- 0013_waf_delegation_outbox.sql
-- Crash-safe WAF delegation outbox contract stored in delegated_jobs_json.
-- Status values: pending_start | starting | delegated | failed

COMMENT ON COLUMN waf_validation_plans.delegated_jobs_json IS
  'Delegated safe test runs. Each entry may include status pending_start (reserved before startTestRun), starting (startTestRun succeeded, finalize pending), delegated (persisted with test_run_id), or failed (reconciled or start failure). Legacy entries without status are treated as delegated when test_run_id is present.';

COMMENT ON COLUMN waf_retest_requests.delegated_jobs_json IS
  'Delegated retest safe test runs. Same status contract as waf_validation_plans.delegated_jobs_json.';