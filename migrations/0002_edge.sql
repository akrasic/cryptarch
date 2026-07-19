-- v0.2 edge groundwork (CRYPTARCH-8, spec: doc-cryptarch-edge-spec).
--
-- managed_servers grows the bouncer-fronted topology fields. The existing
-- host/port columns are the ADVERTISED address — what users see in connection
-- strings, i.e. the bouncer's listener once a server runs the edge topology.
-- Cryptarch's own DDL path uses the (encrypted) admin DSN, never host/port.

-- These values end up rendered into bouncer config files, so the schema
-- enforces them (a stray newline in a TEXT column is config injection).
ALTER TABLE managed_servers
    ADD COLUMN IF NOT EXISTS bouncer_admin_dsn_enc BYTEA NOT NULL DEFAULT ''::bytea,
    ADD COLUMN IF NOT EXISTS pool_mode             TEXT  NOT NULL DEFAULT 'session'
        CHECK (pool_mode IN ('session', 'transaction')),
    ADD COLUMN IF NOT EXISTS tls_mode              TEXT  NOT NULL DEFAULT 'off'
        CHECK (tls_mode IN ('off', 'edge')),
    ADD COLUMN IF NOT EXISTS backend_kind          TEXT  NOT NULL DEFAULT 'docker'
        CHECK (backend_kind IN ('docker', 'vm')),
    ADD COLUMN IF NOT EXISTS default_consumer_cidr CIDR;                    -- prefill for "Allowed from"

-- Per-database source ACL — the source of truth the bouncer hba file is
-- rendered from. MySQL user@host semantics, delivered at the edge.
-- A database with no rows here is unreachable (default-deny).
-- Native CIDR type: rejects garbage at the schema (no hostnames, no
-- injection), and normalises so '1.2.3.4' and '1.2.3.4/32' can't coexist
-- under the UNIQUE constraint. App layer validates again for friendlier
-- errors; this is the backstop.
CREATE TABLE IF NOT EXISTS acl_entries (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id UUID NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    cidr        CIDR NOT NULL,
    note        TEXT,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (database_id, cidr)
);
