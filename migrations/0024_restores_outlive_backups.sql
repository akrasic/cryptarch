-- CRYPTARCH-147: a restore's record outlives the backup it was restored from.
--
-- 0015 made `restores.backup_id` NOT NULL with ON DELETE RESTRICT, so a backup
-- that had ever been restored from could not lose its row. Both things that
-- remove backups unlink the file first and the row second — the operator's
-- purge and retention — so the row delete failed AFTER the file was gone,
-- every time: a row describing a file that no longer existed, and on the
-- retention side a row retried and refused on every pass.
--
-- The restore does not need the backup row. It denormalises what it reports
-- (`source_name`, its log, its own audit entry naming the backup id), for the
-- same reason `backups.db_name` does: the record has to outlive what it
-- describes. So the reference becomes a pointer that is cleared when the
-- backup goes, like `restores.database_id` (0020).
ALTER TABLE restores ALTER COLUMN backup_id DROP NOT NULL;
ALTER TABLE restores DROP CONSTRAINT IF EXISTS restores_backup_id_fkey;
ALTER TABLE restores ADD CONSTRAINT restores_backup_id_fkey
    FOREIGN KEY (backup_id) REFERENCES backups(id) ON DELETE SET NULL;
