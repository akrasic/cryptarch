-- v0.3 bouncer knobs (CRYPTARCH-32): pool settings become portal-managed,
-- rendered into an %include'd ini fragment and RELOADed like the hba file.
--
-- These values end up in a bouncer config file, so the schema constrains
-- them hard: ints are ints, pool_mode is an allowlist. 0 means "unlimited"
-- for the two limit knobs (PgBouncer's own convention).

ALTER TABLE managed_servers
    ADD COLUMN IF NOT EXISTS default_pool_size    INTEGER NOT NULL DEFAULT 10
        CHECK (default_pool_size BETWEEN 1 AND 1000),
    ADD COLUMN IF NOT EXISTS max_client_conn      INTEGER NOT NULL DEFAULT 100
        CHECK (max_client_conn BETWEEN 1 AND 10000),
    ADD COLUMN IF NOT EXISTS max_db_connections   INTEGER NOT NULL DEFAULT 0
        CHECK (max_db_connections BETWEEN 0 AND 10000),
    ADD COLUMN IF NOT EXISTS max_user_connections INTEGER NOT NULL DEFAULT 0
        CHECK (max_user_connections BETWEEN 0 AND 10000);

-- Per-database overrides. Database name == role name by construction, so a
-- per-database limit is delivered as a [users] line at the edge — one knob
-- covers "per-db" and "per-user" for tenant traffic. NULL = inherit server.
ALTER TABLE databases
    ADD COLUMN IF NOT EXISTS pool_mode TEXT
        CHECK (pool_mode IN ('session', 'transaction')),
    ADD COLUMN IF NOT EXISTS max_connections INTEGER
        CHECK (max_connections BETWEEN 1 AND 10000);
