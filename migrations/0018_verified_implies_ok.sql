-- D4 (probe, crypt-2): tier nesting for CRYPTARCH-82's Rule 1, made enforced
-- rather than coincidental.
--
-- Rule 1's "can only ever retain more" is a monotonicity argument, and it needs
-- the tiers nested: verified+present must be a SUBSET of sealed-ok+present.
-- That holds today only because `record_success` (backup.rs:807) is the single
-- writer of `verified_at` and sets `status='ok'` in the same statement. Nothing
-- says so. This does.
--
-- Plain ADD CONSTRAINT, deliberately not NOT VALID: an unvalidated constraint
-- is the looks-enforced-isn't trap this exists to kill. Migrations run at boot,
-- so a violating row means the portal will not start. Pre-flight:
--
--   SELECT id, db_name, status, verified_at FROM backups
--    WHERE verified_at IS NOT NULL AND status <> 'ok';
ALTER TABLE backups ADD CONSTRAINT backups_verified_implies_ok
    CHECK (verified_at IS NULL OR status = 'ok');
