-- Cryptarch host bootstrap — everything Postgres-side that must exist BEFORE
-- the app's first boot, in one idempotent, re-runnable file.
--
-- Run as a superuser against the `postgres` database:
--
--   sudo -u postgres psql -d postgres \
--     -v cryptarch_pw='metadata-role-password' \
--     -v admin_pw='panel-role-password' \
--     -f scripts/bootstrap.sql
--
-- (Compose users don't need this: the container's POSTGRES_* env creates the
--  metadata side, and run-dev.sh / server-init handle the rest. This file is
--  for bare-metal / Chef deploys — see docs/deploy-systemd.md.)
--
-- What it creates:
--   1. `cryptarch` role + `cryptarch` database  — the app's own metadata
--      home (schema inside it is migrated automatically at app start).
--   2. `cryptarch_admin` role                   — the panel's role on the
--      managed server: CREATEDB CREATEROLE, NEVER superuser (the add-server
--      flow refuses superuser DSNs).
--   3. The superuser bootstrap server-init otherwise asks for: pg_shadow
--      grant + the `cryptarch` schema (in THIS database — auth_dbname) that
--      hosts the bouncer's auth_query shim.
--
-- Idempotency: existing roles are left untouched (passwords are NOT reset on
-- re-run — rotate via ALTER ROLE deliberately, not by re-converging).

\set ON_ERROR_STOP on

-- 1a. metadata role
SELECT format('CREATE ROLE cryptarch LOGIN PASSWORD %L', :'cryptarch_pw')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cryptarch')
\gexec

-- 1b. metadata database
SELECT 'CREATE DATABASE cryptarch OWNER cryptarch'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cryptarch')
\gexec

-- 2. panel role — deliberately not superuser; this is the security spine
SELECT format('CREATE ROLE cryptarch_admin LOGIN CREATEDB CREATEROLE PASSWORD %L', :'admin_pw')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cryptarch_admin')
\gexec

-- 3. superuser bootstrap for server-init (idempotent as-is)
GRANT SELECT ON pg_shadow TO cryptarch_admin;
CREATE SCHEMA IF NOT EXISTS cryptarch AUTHORIZATION cryptarch_admin;

\echo 'cryptarch bootstrap complete: roles cryptarch + cryptarch_admin, database cryptarch, shim schema ready.'
