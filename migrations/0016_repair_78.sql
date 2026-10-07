-- CRYPTARCH-78: freeze the repair worklist, and record what the repair saw.
--
-- This migration does NOT repair anything, and deliberately does not flip a
-- single `databases.status`. Suspend wrote to two systems -- `ALTER ROLE ...
-- NOLOGIN` on the managed server, and the metadata row -- and SQL reaches only
-- the second. A migration that set those rows back to 'active' would produce
-- databases the portal calls healthy whose role is still NOLOGIN: every
-- connection fails and nothing anywhere explains why. Strictly worse than the
-- current state, where at least the badge is honest.
--
-- What it does instead is FREEZE THE WORKLIST. Membership is captured now, at
-- the last moment when only Cryptarch's own (now-deleted) suspend path can
-- have written 'suspended'. Anything found disabled later is not on this list
-- and is therefore reported rather than repaired -- which is what stops the
-- repair re-enabling a lockout an administrator performs afterwards.
CREATE TABLE IF NOT EXISTS repair_worklist_78 (
    db_id       UUID PRIMARY KEY REFERENCES databases(id) ON DELETE CASCADE,
    db_name     TEXT NOT NULL,
    server_id   UUID NOT NULL REFERENCES managed_servers(id) ON DELETE CASCADE,
    frozen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Outcome of the one repair attempt, NULL until it runs. Recorded for
    -- every entry: the pass never silently consumes one.
    outcome     TEXT,
    detail      TEXT,
    settled_at  TIMESTAMPTZ
);

-- The `WHERE NOT EXISTS` is BELT-AND-BRACES. It is NOT what protects against a
-- replay, and an earlier version of this comment wrongly said it was.
--
-- Trace a metadata restore and it does not fire in the case that matters:
--
--   * restored from a backup taken BEFORE this migration -- the restored
--     database has neither the table nor the `_sqlx_migrations` row, so this
--     file re-runs, CREATE TABLE IF NOT EXISTS makes an EMPTY table, and
--     NOT EXISTS is trivially true. A second freeze IS taken.
--   * restored from a backup taken AFTER it -- the table and the migration
--     record both come back, so this file never re-runs and the guard is
--     irrelevant.
--
-- The same restore that rewinds `_sqlx_migrations` also rewinds this table, so
-- the guard cannot see the old freeze. It only fires if someone deletes the
-- migration row while keeping the table, which is tampering, not a supported
-- operation. Keeping it because it is free and covers that case.
--
-- WHAT ACTUALLY PREVENTS THE REPLAY is the marker role on each managed server:
-- Tier A calls claim_repair_attempt, gets Ok(false), and does nothing. That is
-- deliberately in a different backup domain from this database. Do not weaken
-- it on the strength of this guard.
--
-- KNOWN RESIDUAL (TM2, accepted): on a server that was never REACHED during the
-- original upgrade there is no marker, so a post-restore re-run would repair
-- against a stale freeze. That is the accepted hole -- such a server is
-- permanently Tier B by construction, so in practice the repair does not run
-- there at all; but the freeze itself is not protected.
INSERT INTO repair_worklist_78 (db_id, db_name, server_id)
SELECT d.id, d.name, d.server_id
  FROM databases d
 WHERE d.status = 'suspended'
   AND NOT EXISTS (SELECT 1 FROM repair_worklist_78);

-- Servers that could not be reached during the upgrade.
--
-- INFORMATIONAL ONLY. Eligibility for repair is STRUCTURAL -- Tier A exists on
-- the upgrade path and nowhere else, so a server that was never reached is
-- never repaired, by construction rather than by consulting this table.
-- NOTHING MAY BRANCH ON THESE ROWS. Wiring them up as a gate would move the
-- decision back into the metadata database, which is the one thing that can be
-- restored from backup independently of the managed servers it describes --
-- and that would silently replace the construction argument with a flag that
-- can be rewound.
CREATE TABLE IF NOT EXISTS repair_unreachable_78 (
    server_id   UUID PRIMARY KEY REFERENCES managed_servers(id) ON DELETE CASCADE,
    noticed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    detail      TEXT NOT NULL
);
