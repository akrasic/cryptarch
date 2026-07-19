-- CRYPTARCH-11: server-init state.
--
-- bouncer_conf_dir: local path (from Cryptarch's vantage) of the bouncer's
-- config dir — the shared volume in compose, dev-bouncer/ in dev. NULL means
-- Cryptarch cannot write the edge config itself (e.g. bouncer on a remote
-- VM): rendered config is then offered for manual placement instead.
--
-- auth_pw_enc: encrypted password of the cryptarch_auth role this server's
-- bouncer uses for auth_query lookups. Generated at init, never shown after.
ALTER TABLE managed_servers
    ADD COLUMN IF NOT EXISTS bouncer_conf_dir TEXT,
    ADD COLUMN IF NOT EXISTS auth_pw_enc BYTEA NOT NULL DEFAULT ''::bytea,
    ADD COLUMN IF NOT EXISTS init_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (init_status IN ('pending', 'needs_bootstrap', 'ready', 'failed'));
