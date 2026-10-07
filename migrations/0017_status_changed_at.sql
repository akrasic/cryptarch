-- CRYPTARCH-80: when did this row enter its current status?
--
-- Needed to bound a HUMAN OBLIGATION. A delete that fails partway is never
-- retried automatically -- completing one destroys data, and an automated
-- process that cannot attribute a cause must not take an irreversible action.
-- But "nothing automatic retries it" silently also means "nothing guarantees
-- anything ever does", and a requested deletion that waits for an admin who
-- never opens the report waits forever. Where the request came from an erasure
-- obligation, "we started and nobody finished" is the worst available state.
--
-- Age is what turns that from a row on a page into an alert. Without a
-- timestamp, "stranded" and "stranded for a month" are the same fact.
--
-- Backfilled from created_at rather than left NULL: a NULL would make every
-- pre-existing row un-ageable, and "we cannot tell how old this is" would then
-- read as "it is not old yet" -- the same collapse this column exists to stop.
ALTER TABLE databases
    ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE databases SET status_changed_at = created_at WHERE status_changed_at > created_at;
