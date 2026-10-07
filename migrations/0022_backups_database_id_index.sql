-- CRYPTARCH-115: an index that exists FOR a query the query cannot use.
--
-- `backup::history` — the db page's Backups tab — reads
--
--     ... FROM backups WHERE database_id = $1 ORDER BY created_at DESC LIMIT 50
--
-- and the only index on the table is
--
--     idx_backups_db_name_created ON backups(db_name, created_at DESC)
--
-- whose leading column is `db_name`. A btree cannot serve a `database_id`
-- predicate from that, so the query is a sequential scan plus a sort of the
-- whole table.
--
-- The mismatch is not an oversight about indexing in general — 0011's comment
-- says that index is there because "the db page lists a single database's
-- history newest-first", which is precisely this query. It was built for it.
-- Then CRYPTARCH-86 re-keyed the query from the name to the id (correctly, and
-- for a security reason) and the index was left pointing at the old column.
--
-- It matters more than the row count suggests because of where it is read:
-- while a backup or restore is running, that tab re-fetches every 2-3 seconds.
CREATE INDEX IF NOT EXISTS idx_backups_database_id_created
    ON backups(database_id, created_at DESC);

-- The db_name index STAYS. It is not redundant: the staleness check and the
-- admin "last backup" column ask the same question across every name, and
-- orphaned rows (database_id NULLed by ON DELETE SET NULL) are reachable only
-- by name.
