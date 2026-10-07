-- CRYPTARCH-107: prove, at boot, that this is the key that sealed this
-- deployment's data.
--
-- Nothing did. `Crypto::from_key_file` succeeds for ANY 32 valid hex bytes, so
-- booting with the wrong key looked exactly like booting with the right one:
--   * the seed managed server kept working, because ServerRegistry re-encrypts
--     its DSN with whatever key is loaded;
--   * other servers logged one error line and were skipped;
--   * backups kept SUCCEEDING, because each was sealed and then verified with
--     the same wrong key;
--   * the staleness check reads the `backups` table, never the blobs, so no
--     alert fired.
-- The operator therefore saw a full, verified backup history in which every
-- blob was noise, and found out only on the day they clicked Restore.
--
-- That is precisely the failure CLAUDE.md names as the worst kind: a check that
-- reports healthy because it cannot see. This gives it something to see.
CREATE TABLE IF NOT EXISTS key_canary (
    -- Exactly one row, ever. The CHECK is the constraint; the id is just the
    -- handle for the upsert.
    id            BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    -- A blob sealed with the key that was loaded when this row was written.
    -- Opening it is the test: the plaintext is known, so a successful open
    -- proves key identity and nothing else needs comparing.
    sealed        BYTEA NOT NULL,
    -- The same key's fingerprint, in the clear. Not the security mechanism —
    -- `sealed` is — but it lets an error message say WHICH key was expected
    -- instead of only that the wrong one is loaded, which is the difference
    -- between "your key is wrong" and "your key is wrong, here is what to look
    -- for in the password manager".
    fingerprint   TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Which key sealed each backup blob.
--
-- The blob header would be the other home for this, but its `aux` section is
-- already the manifest (CRYPTARCH-67) — putting a second field there is a
-- manifest format change, and the header is hashed into every frame's AAD, so
-- it is the most expensive place in the system to alter. The row answers the
-- operator's question ("can I restore this one?") without touching the format
-- at all. NULL means "written before this column existed", which is not the
-- same as "wrong key" and must not be reported as one.
ALTER TABLE backups ADD COLUMN IF NOT EXISTS key_fingerprint TEXT;
