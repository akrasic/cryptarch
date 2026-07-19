-- CRYPTARCH-14: additional per-server listener addresses.
--
-- managed_servers.host/port remains the PRIMARY dial address (the engine's
-- connection strings and connect-tests use it — single source of truth).
-- This table holds ADDITIONAL listeners: LAN IPs, public IPs, FQDNs, each
-- labeled. The creds page renders one connection string per address so the
-- user grabs whichever fits where the consumer lives. Listeners are where
-- you DIAL; acl_entries are where you ARRIVE FROM — orthogonal by design.
CREATE TABLE IF NOT EXISTS server_listeners (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id  UUID NOT NULL REFERENCES managed_servers(id) ON DELETE CASCADE,
    host       TEXT NOT NULL,          -- IP or FQDN (validated app-side)
    port       INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    label      TEXT NOT NULL,          -- 'local' | 'lan' | 'tailnet' | 'public' | free text
    position   INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, host, port)
);
