-- CRYPTARCH-55: per-database logical backups (doc-cryptarch-backup-spec).
--
-- The load-bearing decision here is what this table does NOT do: it does not
-- CASCADE off databases. "Restore the database I deleted" is the whole point of
-- a backup, so the history has to outlive the row it describes — a cascade
-- would erase the record at exactly the moment it becomes valuable. The
-- reference is therefore nullable and set NULL on delete, and the identity
-- (name + server) is denormalized at backup time so a backup taken for a
-- since-deleted database still says what it was. Retention prunes old rows;
-- deletion never does.
--
-- db_name is deliberately not unique or foreign-keyed: names are freed on
-- delete and reusable, so a deleted `app` and a later new `app` can both have
-- rows here. The path carries the backup id for the same reason.
CREATE TABLE IF NOT EXISTS backups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id UUID REFERENCES databases(id) ON DELETE SET NULL,
    db_name     TEXT NOT NULL,
    server_id   UUID REFERENCES managed_servers(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    size_bytes  BIGINT,
    checksum    TEXT,                                -- sha256 of the sealed blob
    path        TEXT,                                -- relative to CRYPTARCH_BACKUP_DIR
    format      TEXT NOT NULL DEFAULT 'pgdump-custom-zstd-aesgcm',
    status      TEXT NOT NULL DEFAULT 'running',     -- 'running' | 'ok' | 'failed'
    error       TEXT,                                -- failure reason when status = 'failed'
    CONSTRAINT backups_status_check CHECK (status IN ('running', 'ok', 'failed'))
);

-- The db page lists a single database's history newest-first; the staleness
-- health check and the admin "last backup" column ask the same question across
-- every name.
CREATE INDEX IF NOT EXISTS idx_backups_db_name_created ON backups(db_name, created_at DESC);

-- The job runner's per-database lock: at most one backup may be in flight for a
-- given name. Enforced in the schema rather than in application code so two
-- fast clicks (or a manual click racing the scheduler) cannot both pass a
-- check-then-insert. Partial index — completed rows are unconstrained.
CREATE UNIQUE INDEX IF NOT EXISTS idx_backups_one_running_per_db
    ON backups(db_name) WHERE status = 'running';
