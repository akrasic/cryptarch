-- Named sources (CRYPTARCH-39): admin-defined, labeled ingress ranges per
-- managed server ("db network" → 172.18.0.0/16, "LAN" → 192.168.8.0/24).
-- The provision form offers them as opt-in checkboxes so users never need
-- CIDR literacy; is_default marks the ones pre-ticked.
--
-- Native CIDR type as everywhere: schema-level rejection of garbage, and
-- normalisation so equivalent spellings can't dodge the UNIQUE constraints.
CREATE TABLE IF NOT EXISTS server_sources (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id  UUID NOT NULL REFERENCES managed_servers(id) ON DELETE CASCADE,
    label      TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 32),
    cidr       CIDR NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, label),
    UNIQUE (server_id, cidr)
);
