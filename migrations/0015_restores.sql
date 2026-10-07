-- CRYPTARCH-69: restore jobs, and the two new kinds of row in `databases`.
--
-- `databases` has always meant "a tenant database", and every query over it
-- assumed that silently. Restore introduces two rows that are NOT that:
--
--   'restoring' — a name reserved before CREATE DATABASE runs, so the target is
--                 held against both another restore and ordinary provisioning,
--                 and so a crash mid-restore leaves a record pointing at the
--                 orphan it created. It is not yet a database anyone may use.
--   'aside'     — the previous contents of a replaced database, kept so the
--                 replace can be undone. Real data, deliberately retained, but
--                 not a database the owner provisioned.
--
-- Neither is ever 'active', which is what keeps the quota promise: provision.rs
-- counts `status = 'active'` only, so transient rows reserve names without
-- consuming a slot. That invariant is load-bearing for "replace is never
-- blocked by quota" and must not be weakened by making either status active.
CREATE TABLE IF NOT EXISTS restores (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backup_id    UUID NOT NULL REFERENCES backups(id) ON DELETE RESTRICT,
    -- Denormalised for the same reason backups denormalise: a restore's record
    -- must outlive the rows it refers to.
    source_name  TEXT NOT NULL,
    target_name  TEXT NOT NULL,
    -- 'new' (restore under a different name) | 'replace' (swap into place)
    mode         TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at  TIMESTAMPTZ,
    status       TEXT NOT NULL DEFAULT 'running',
    -- Which of the seven stages is in flight, so the page can show progress
    -- rather than a spinner.
    stage        TEXT NOT NULL DEFAULT 'checking',
    error        TEXT,
    log          TEXT NOT NULL DEFAULT '',
    -- Set once a replace has swapped; names the database holding the previous
    -- contents, which is what "undo this restore" needs.
    aside_name   TEXT,
    CONSTRAINT restores_status_check CHECK (status IN ('running', 'ok', 'failed')),
    CONSTRAINT restores_mode_check CHECK (mode IN ('new', 'replace'))
);

CREATE INDEX IF NOT EXISTS idx_restores_target_created ON restores(target_name, created_at DESC);

-- The same insert-as-lock primitive the backup runner uses: at most one restore
-- in flight per target, enforced in the schema so two clicks race inside
-- Postgres rather than in a check-then-insert window.
CREATE UNIQUE INDEX IF NOT EXISTS idx_restores_one_running_per_target
    ON restores(target_name) WHERE status = 'running';
