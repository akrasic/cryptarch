-- CRYPTARCH-12 (review F1): edge sync state. A failed hba write/RELOAD must
-- never look like success — edge_dirty flags a server whose rendered edge
-- config may not match acl_entries, and every relevant page banners it
-- until a sync succeeds.
ALTER TABLE managed_servers
    ADD COLUMN IF NOT EXISTS edge_dirty     BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS edge_synced_at TIMESTAMPTZ;
