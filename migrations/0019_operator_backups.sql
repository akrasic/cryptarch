-- CRYPTARCH-86 step 3: the backups a deleted database left behind.
--
-- A VIEW rather than a shared SQL fragment, and that is the whole point. The
-- predicate below is easy to get wrong in one specific way, and a helper
-- returning a string cannot stop the next query being written with a bare
-- `database_id IS NULL` -- the compiler is silent, and the mistake is exactly
-- the one the helper existed to prevent. Selecting FROM the predicate cannot be
-- forgotten.
--
-- WHAT MAKES IT EASY TO GET WRONG: `database_id IS NULL` means TWO different
-- things. A backup whose database was deleted is unlinked by the foreign key
-- (ON DELETE SET NULL, migration 0011) -- that is an orphan, now owned by the
-- operator. But `_cryptarch_meta` ALSO has a NULL database_id, for an unrelated
-- reason: it has no `databases` row at all, because it is not a provisioned
-- database. It is not an orphan and must never appear in a list whose purpose
-- is to offer a purge button. Losing the metadata backups would leave a
-- directory of sealed blobs with no record of which database, which server, or
-- which point in time any of them came from.
--
-- The name deliberately avoids "orphan": the entire bug class here is "NULL
-- reads as orphan", so a name built on that word invites the next reader to
-- assume it means `database_id IS NULL` and inline it back. This is named for
-- who owns the rows, not for how they got that way.
--
-- The sentinel is duplicated from `backup::METADATA_DB`, which is a real
-- source-of-truth risk; `the_view_excludes_the_metadata_database` pins the two
-- together so they cannot drift silently.
CREATE OR REPLACE VIEW operator_backups AS
SELECT id,
       db_name,
       server_id,
       created_at,
       finished_at,
       size_bytes,
       checksum,
       path,
       format,
       status,
       error,
       log,
       manifest,
       verified_at
FROM backups
WHERE database_id IS NULL
  AND db_name <> '_cryptarch_meta';
