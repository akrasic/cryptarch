# Cryptarch

**A self-service database provisioning portal for your homelab or small team.**
Users log in, create their *own* PostgreSQL databases (within a quota), and get
a connection string exactly once. Admins manage users, servers, access rules,
and pool settings — through the portal, not over SSH.

Think mini-RDS: deploy the stack once, then everything about the
Postgres + PgBouncer estate is managed from the web UI. The name is a Destiny
reference — the Cryptarch decodes engrams and hands you what's inside.

## What it does

- **Self-service provisioning** — pick a server, pick a name, click. Database,
  role, and access rules are born together in one transaction; the password is
  shown once and stored only as an Argon2 hash.
- **A PgBouncer edge as the only door** — Postgres is never network-facing.
  Access is per-database allowlists (`user@host` semantics, delivered as a
  rendered hba file + `RELOAD`), with **named sources** ("db network", "LAN")
  so nobody has to know a CIDR, and **listeners** so every database page shows
  the right connection string per network you dial from.
- **Pool settings in the portal** — pool mode, pool sizes, per-database and
  per-user connection limits, rendered into the bouncer's config and reloaded
  live. No SSH-to-fix.
- **Health + notifications** — a background loop probes the edge listener,
  Postgres, and config drift; transitions (down/recovered) alert via
  [ntfy](https://ntfy.sh) or webhook and land in the audit log.
- **Quotas, lifecycle, audit** — per-user caps enforced race-free, password
  reset / suspend / resume / typed-name delete, and an append-only audit log
  of every mutating action.
- **Engine-agnostic core** — everything above the `DbEngine` trait knows
  nothing about Postgres. MySQL/MariaDB is the next implementation, not a
  rewrite.

What it is **not**: a query editor or table browser (pair it with
[CloudBeaver](https://github.com/dbeaver/cloudbeaver)), a cluster manager, or
multi-tenant SaaS. Homelab and small-team scale, on purpose.

## Architecture

```
web UI (axum + maud + htmx, single binary)
  │
auth · quotas · ownership · audit          ← the actual product
  │
DbEngine trait ── PostgresEngine           ← MySQL next; the boundary is sacred
  │
managed servers (remote Postgres), each fronted by PgBouncer:
  consumers ─► bouncer :6432 ─► postgres (localhost/backend network only)
                  ▲ hba + pool config rendered by Cryptarch, RELOADed live
```

## Quick start (docker compose)

Requirements: docker with compose. The stack runs Postgres 18, PgBouncer, and
the Cryptarch binary; the compose network `db` is attachable so your app
containers can join it and reach their databases by service name.

```sh
git clone <this repo> && cd cryptarch

# 1. Secrets + settings
cp .env.example .env         # set POSTGRES_PASSWORD, CRYPTARCH_ADMIN_PASSWORD,
                             # CRYPTARCH_SEED_SERVER_* (see comments in the file)
(umask 077; openssl rand -hex 32 > cryptarch.key)

# 2. Up
docker compose up -d

# 3. One-time superuser bootstrap (the panel role is deliberately NOT
#    superuser, so a superuser grants it the minimum once):
docker compose exec -T db psql -U postgres -d postgres \
  -v cryptarch_pw=unused -v admin_pw='<cryptarch_admin password>' \
  -f - < scripts/bootstrap.sql

# 4. Log in at http://<host>:8080 (admin / CRYPTARCH_ADMIN_PASSWORD),
#    open Servers → your server → "Run server init" — watch it go green.
```

Provision a database, attach your app container to the `db` network
(`docker network connect db myapp` or `external: true` in its compose), paste
the "db network" connection string. Done.

Everything else — schema migrations, the admin account, the seed server row
(DSN encrypted at rest), the default "db network" source and listener, the
health loop — bootstraps itself on first boot.

## Bare metal / systemd

No docker required: the app is one binary that talks DSNs and writes bouncer
config files. See **[docs/deploy-systemd.md](docs/deploy-systemd.md)** for the
three-unit setup (distro PostgreSQL + PgBouncer + cryptarch.service),
including the Chef-friendly ownership boundaries.

## Development

```sh
./run-dev.sh          # throwaway Postgres + PgBouncer in docker, app on :8080
                      # (wipes dev data each run — that's the point)

# tests: unit tests run bare; integration tests need a throwaway Postgres
cargo test
CRYPTARCH_TEST_DSN=postgres://postgres:devpass@localhost:55432/postgres cargo test
```

Rust (edition 2021), axum, maud, htmx, sqlx. No JS build step. Server-rendered
everything; the portal works with JavaScript disabled.

## Security posture

- The panel's role on managed servers is `CREATEDB CREATEROLE`, **never
  superuser** — the add-server flow refuses superuser DSNs outright.
- Generated passwords: 32-char CSPRNG, shown once, stored only as Argon2
  hashes. The bouncer resolves tenant credentials via an `auth_query` shim —
  no password files.
- Default-deny at the edge: a database with no allowed sources is unreachable,
  localhost included.
- Every database name passes a strict allowlist before touching DDL; every
  mutating action writes the audit log before returning; deletes require
  typing the database name.

## Status

v0.3. Done: provisioning core, the PgBouncer edge (ACLs, named sources,
listeners, pool knobs), admin console, health + notifications, server
dashboard. Next: backup story, MySQL/MariaDB engine, TLS at the edge, LDAP.

See `SPEC.md` for the full design and rationale.
