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
SvelteKit SPA (compiled in) ─► JSON API /api/v1 (axum, single binary)
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
the Cryptarch binary. Managed servers must run **PostgreSQL 14 or newer** — older
servers are refused when you add them, because restores rely on features 14
introduced. The compose network `db` is attachable so your app
containers can join it and reach their databases by service name.

```sh
git clone <this repo> && cd cryptarch

# 1. Secrets + settings
cp .env.example .env         # POSTGRES_PASSWORD, CRYPTARCH_ADMIN_PASSWORD,
                             # BOUNCER_ADMIN_PASSWORD, BOUNCER_STATS_PASSWORD,
                             # CRYPTARCH_SEED_SERVER_* (see comments in the file)
                             # compose REFUSES to start if any of those is unset.
sudo install -d -m 700 /srv/cryptarch
(umask 077; sudo openssl rand -hex 32 > /srv/cryptarch/cryptarch.key)

# 1b. ⚠ COPY cryptarch.key SOMEWHERE OFF THIS MACHINE, NOW.
#     It encrypts every backup and every stored server credential. If this box
#     dies and the key died with it, your backups are unopenable noise. Put it
#     in a password manager before you continue. See "Backups" below.
#
#     Note it lives OUTSIDE this git clone on purpose, and so do the backups.
#     A key sitting next to the compose file is one `git add -A` from being
#     published, and this directory is one `git clean -fdx` — or one stack
#     re-clone, which is how Komodo redeploys — from being erased.

# 2. Up
docker compose up -d

# 3. One-time superuser bootstrap (the panel role is deliberately NOT
#    superuser, so a superuser grants it the minimum once):
docker compose exec -T db psql -U postgres -d postgres \
  -v cryptarch_pw=unused -v admin_pw='<cryptarch_admin password>' \
  -f - < scripts/bootstrap.sql

# 4. Log in at http://localhost:8080 (admin / CRYPTARCH_ADMIN_PASSWORD),
#    open Servers → your server → "Run server init" — watch it go green.
```

> **Reaching it from another machine?** Two things have to change together, and
> the failure mode if you only do one is nasty.
>
> The web port binds `127.0.0.1` by default (`APP_BIND`), so from another host
> there is nothing listening. And session cookies are marked `Secure`, so they
> work only over `https://` or `http://localhost` — over plain `http://` to a
> LAN address the browser **silently discards the cookie**, and login bounces
> you back to the sign-in page exactly as though the password were wrong. No
> error, nothing in the logs but the startup warning.
>
> There is no TLS in the stack yet (CRYPTARCH-22). Until there is, either put a
> reverse proxy with a certificate in front, or — on a network you trust — set
> `APP_BIND=0.0.0.0` **and** `CRYPTARCH_INSECURE_COOKIES=1`.
>
> With Secure cookies the session cookie is named `__Host-cryptarch_session`,
> which a browser accepts only from a secure origin — so a plain-http service
> or a sibling subdomain on the same host cannot plant a session in it. It
> cannot stop another **https** service on the same host (cookies do not
> separate by port): give Cryptarch its own hostname if you run others.

Provision a database, attach your app container to the `db` network
(`docker network connect db myapp` or `external: true` in its compose), paste
the "db network" connection string. Done.

Everything else — schema migrations, the admin account, the seed server row
(DSN encrypted at rest), the default "db network" source and listener, the
health loop — bootstraps itself on first boot.

## Backups

Cryptarch takes per-database logical dumps (`pg_dump`, compressed, then
encrypted with your key) and writes them to a directory you mount from the
host. **The compose stack has them ON by default**, writing to
`/srv/cryptarch/backups`.

To turn them off you must set `CRYPTARCH_BACKUP_DIR` to an empty value.
Commenting out `CRYPTARCH_BACKUP_DIR_HOST` does *not* disable backups — it only
moves the host mount, which is how you end up with nightly dumps of every
database accumulating, sealed with a key you never copied offline because you
believed the feature was idle.

```yaml
# docker-compose.yml — a host path, deliberately not a docker volume: you have
# to be able to rsync these off the box with ordinary tools.
services:
  app:
    environment:
      CRYPTARCH_BACKUP_DIR: /backups     # empty string = backups off
    volumes:
      - /srv/cryptarch/backups:/backups
```

Blobs land at `<root>/<database>/<UTC-timestamp>-<id>.dump.zst.enc`, mode 0600.
Back one up from the database's page in the portal ("Back up now"); the history
table shows what exists, and `/admin/databases` has a "Last backup" column so
you can see coverage across the fleet at a glance.

Backups also run on a schedule, and Cryptarch's own metadata database rides the
same pipeline (as `_cryptarch_meta`) so a rebuild has the who-owns-what ledger
to restore from:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CRYPTARCH_BACKUP_DIR` | `/backups` in compose; unset otherwise | Backup root. Empty or unset = backups off. The compose stack sets it, so backups are on unless you clear it. |
| `CRYPTARCH_BACKUP_INTERVAL_SECS` | `86400` | Sweep interval; `0` disables the loop (manual backups still work). |
| `CRYPTARCH_BACKUP_KEEP` | `7` | Successful backups kept per database; `0` keeps everything. Retention counts *successes*, so a run of failures can never age out your good backups. |
| `CRYPTARCH_BACKUP_STALE_AFTER_SECS` | `172800` | Alert when a database's newest good backup is older than this; `0` disables. Uses the same ntfy/webhook path as health. |

For cron or off-box runs, the same code is a subcommand:

```sh
cryptarch backup --all          # every database, plus the metadata database
cryptarch backup --db myapp     # just one
```

It exits non-zero if any backup failed, so a timer reports honestly.

**What you need to back up yourself — the whole list:**

1. **`cryptarch.key`** — copy it offline **once, at install time** (password
   manager, printed slip, anywhere that is not this machine). It seals every
   backup blob *and* encrypts the stored server credentials. Without it, both
   are unrecoverable. There is no second key and no recovery path.
2. **The backup directory** — rsync/syncthing it somewhere else on whatever
   cadence you want. It holds the tenant dumps and Cryptarch's own metadata
   dump.

Nothing else needs backing up: the compose file and `.env` are redeployable
config, and the admin account re-bootstraps from `CRYPTARCH_ADMIN_PASSWORD`.

**Recovering onto a fresh box:** install the stack as above → restore
`cryptarch.key` → `pg_restore` the metadata dump into the `cryptarch` database
(manual, and necessarily so: the portal needs its own metadata up before it can
serve anything) → start Cryptarch → restore tenant databases.

Restoring tenant databases through the portal is not built yet — the dumps are
standard `pg_dump` custom-format archives once decrypted, so `pg_restore`
works on them directly in the meantime.

## Bare metal / systemd

No docker required: the app is one binary that talks DSNs and writes bouncer
config files. See **[docs/deploy-systemd.md](docs/deploy-systemd.md)** for the
three-unit setup (distro PostgreSQL + PgBouncer + cryptarch.service),
including the Chef-friendly ownership boundaries.

## Development

```sh
./run-dev.sh          # throwaway Postgres + PgBouncer in docker, app on :8080
                      # (wipes dev data each run — that's the point; it also
                      # builds the frontend first, SKIP_FRONTEND=1 to skip)

# frontend: the UI is a SvelteKit SPA in frontend/, compiled into the binary
cd frontend && npm ci && npm run build   # before `cargo build`: the binary embeds frontend/build
npm run dev                              # live-reload UI on :5173, API proxied to :8080
npm run check && npm test                # types + vitest

# tests: unit tests run bare; integration tests need a throwaway Postgres
cargo test
CRYPTARCH_TEST_DSN=postgres://postgres:devpass@localhost:55432/postgres cargo test
```

Rust (edition 2021), axum, sqlx; SvelteKit 3 with Svelte 5, built to static
files with one fallback shell and embedded with rust-embed, so the deploy is
still one binary. The UI talks only to the JSON API under `/api/v1`; there are
no server-rendered pages. Without a frontend build the binary embeds a
placeholder (see `build.rs`) and says so at boot.

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
dashboard, on-demand encrypted backups. Next: scheduled backups + retention,
restore from the portal, MySQL/MariaDB engine, TLS at the edge, LDAP.

See `SPEC.md` for the full design and rationale.
