-- CRYPTARCH-100: restores belong to a database's IDENTITY, not to its name.
--
-- This is CRYPTARCH-86 finished. That task moved `backups` off `db_name` onto
-- `database_id` because names are freed on delete and reusable, so "the next
-- person to take a name inherited the previous owner's backup list". The fix
-- reached `restore::enqueue` — which scopes its backup lookup with
-- `AND database_id = $2` and cites CRYPTARCH-86 in a comment — and stopped
-- there. `restore::get` and `restore::history`, 240 lines further down the same
-- file, still keyed on `target_name`, so a tenant who took a freed name was
-- shown the previous owner's restore jobs: `requested_by`, and a job page
-- carrying blob filenames, sizes and `pg_restore` stderr from a database they
-- never had access to.
--
-- `target_name` STAYS. It is the denormalised record that must outlive the row
-- it describes, for the same reason `backups.db_name` does: a restore of a
-- since-deleted database still has to be able to say what it was. The name is
-- what the record REPORTS; the id is what authorisation READS. Those were the
-- same field, and that was the bug.
ALTER TABLE restores ADD COLUMN IF NOT EXISTS database_id UUID
    REFERENCES databases(id) ON DELETE SET NULL;

-- Backfill, deliberately conservative on the one case that matters.
--
-- Matching on name alone would re-commit the very error being fixed: where a
-- name has already been recycled, it would hand the previous owner's restores
-- to the current holder and stamp that attribution into a column that now reads
-- as authoritative. The `created_at` guard blocks exactly that — a database
-- cannot have been the target of a restore that predates its own creation.
--
-- Anything that does not match stays NULL and becomes invisible to tenants,
-- reachable only as an operator-owned record. For a fix whose whole subject is
-- over-exposure, unattributed is the safe direction to fail.
UPDATE restores r
   SET database_id = d.id
  FROM databases d
 WHERE r.database_id IS NULL
   AND d.name = r.target_name
   AND d.created_at < r.created_at;

-- The per-target lock gains the identity key and KEEPS the name key.
--
-- Both, deliberately, and an earlier draft of this migration dropped the name
-- index on the reasoning that "two live databases cannot share a name, so
-- identity is strictly stronger". That is false, and this file's own
-- `ON DELETE SET NULL` is what makes it false:
--
--   1. A restore of `foo` (database_id = X) is running; the job executes
--      against the NAME (`restore.rs` hands `job.db_name` to `restore_stream`),
--      and a large dump takes minutes.
--   2. `foo` is deleted. The FK above NULLs that running row's database_id.
--   3. The partial unique index no longer covers the row — NULLs do not
--      conflict — so the lock silently disappears WHILE THE JOB IS STILL
--      RUNNING.
--   4. Someone provisions `foo` again (the name is free) and restores into it.
--      No unique violation.
--   5. Two `pg_restore` pipelines now run concurrently against the same
--      physical database.
--
-- The name index alone had a LIVENESS bug (a wedged `running` row blocks that
-- name forever). Trading it for a SAFETY bug is the wrong trade: keeping both
-- costs one index, and the liveness problem is properly fixed by a sweep that
-- settles abandoned restore rows — which is CRYPTARCH-113, and which backups
-- already have in `sweep_abandoned`.
CREATE UNIQUE INDEX IF NOT EXISTS idx_restores_one_running_per_database
    ON restores(database_id) WHERE status = 'running';
-- Unchanged from 0015, restated here so this file reads as the whole story of
-- the lock rather than a diff against another migration.
CREATE UNIQUE INDEX IF NOT EXISTS idx_restores_one_running_per_target
    ON restores(target_name) WHERE status = 'running';

-- Serves `restore::history`, which lists one database's restores newest-first.
-- Named for the column it actually leads on, so it cannot drift from its query
-- the way `idx_backups_db_name_created` did.
CREATE INDEX IF NOT EXISTS idx_restores_database_id_created
    ON restores(database_id, created_at DESC);
DROP INDEX IF EXISTS idx_restores_target_created;
