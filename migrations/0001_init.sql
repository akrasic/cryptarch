-- Cryptarch metadata schema (the panel's own source of truth).
-- Lives in a dedicated `cryptarch` database, separate from the databases it
-- provisions. This is where "who owns what" and "how many is Alice allowed"
-- are answered. Provisioned databases live on managed servers, not here.

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,
    -- Argon2 hash of the login password. Local accounts in v0.1; LDAP later.
    password_hash TEXT NOT NULL,
    is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
    -- Per-user cap on active databases. Admin can override; global default in config.
    db_quota      INTEGER NOT NULL DEFAULT 3,
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A managed database server Cryptarch provisions onto. Admin creds are held
-- encrypted at rest (encryption handled in the app layer, not stored raw).
CREATE TABLE IF NOT EXISTS managed_servers (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT NOT NULL UNIQUE,
    engine         TEXT NOT NULL,                 -- 'postgres' | 'mysql'
    host           TEXT NOT NULL,
    port           INTEGER NOT NULL,
    admin_dsn_enc  BYTEA NOT NULL,                -- encrypted admin connection string
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One provisioned database, owned by a user, living on a managed server.
CREATE TABLE IF NOT EXISTS databases (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id         UUID NOT NULL REFERENCES managed_servers(id) ON DELETE RESTRICT,
    name              TEXT NOT NULL,              -- db + role name on the target server
    -- Argon2 hash of the generated password; the plaintext is shown once, never stored.
    password_hash     TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'active',  -- 'active' | 'suspended'
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, name)
);

CREATE INDEX IF NOT EXISTS idx_databases_owner ON databases(owner_id);

-- Append-only audit log. Every credential-issuing or destructive action lands
-- here before it returns. Never updated, never deleted.
CREATE TABLE IF NOT EXISTS audit_log (
    id         BIGSERIAL PRIMARY KEY,
    actor      TEXT NOT NULL,          -- username or 'system'
    action     TEXT NOT NULL,          -- 'create_db' | 'drop_db' | 'rotate' | 'suspend' | ...
    target     TEXT,                   -- db name / user / server affected
    detail     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
