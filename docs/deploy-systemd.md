# Deploying Cryptarch as systemd services (bare metal / Chef)

The compose stack is packaging, not architecture: Cryptarch itself only speaks
DSNs, writes files into a bouncer conf dir, and runs PgBouncer console
commands. Nothing in it knows docker exists. This document maps the stack onto
three systemd units on one box — distro PostgreSQL, distro PgBouncer, and the
Cryptarch binary — the shape you'd provision with Chef/Ansible/Salt.

Written against v0.3 (2026-07-19). The compose stack (`docker-compose.yml`)
remains the reference deployment; where the two disagree, compose is current.

## The shape

```
LAN clients ──► pgbouncer.service :6432 (the ONLY network-facing listener)
                     │ auth_query / hba / knobs   (files cryptarch renders)
                     ▼
               postgresql.service :5432 bound to 127.0.0.1 ONLY
                     ▲
cryptarch.service :8080 ─ metadata DB, admin DSN, console — all via localhost
```

What the compose `backend` network does with topology, you do with bind
addresses: **Postgres listens on localhost only; the bouncer is the door.**

Concept mapping from the compose stack:

| compose concept                          | systemd equivalent                          |
|------------------------------------------|---------------------------------------------|
| `db` network (attachable)                | your LAN + firewall                         |
| `backend` network                        | `listen_addresses = 'localhost'`            |
| named source "db network" 172.18.0.0/16  | named source "LAN" = your subnet            |
| in-stack listener `bouncer:6432`         | listener "localhost" = `127.0.0.1:6432`     |
| `bouncer_conf` shared volume             | `/etc/pgbouncer` + a shared group           |
| image tag rollback                       | package pinning / binary versioning         |

## 1. Users and the permission model

One real friction point in this deployment: **Cryptarch writes what PgBouncer
reads.** Solve it with a shared group, not with running anything as root.

```sh
# pgbouncer package usually creates user/group `pgbouncer`
useradd --system --home /var/lib/cryptarch --shell /usr/sbin/nologin cryptarch
usermod -aG pgbouncer cryptarch
chgrp -R pgbouncer /etc/pgbouncer
chmod 2775 /etc/pgbouncer          # setgid: new files inherit the group
```

Cryptarch renders `pgbouncer_hba.conf`, `cryptarch_bouncer.ini`, and rewrites
`userlist.txt` atomically (temp file + rename in the same dir — hence the dir
needs group write, not just the files). Secret-bearing files are written 0640
when possible; the renderer falls back to 0644 with a loud log warning when
the group arrangement doesn't hold — if you see that warning, fix the group.

## 2. PostgreSQL

Distro package, default unit. Non-negotiables:

```
# postgresql.conf
listen_addresses = 'localhost'      # the bouncer is the only door
```

Everything Postgres-side that must pre-exist ships as one idempotent,
re-runnable file — `scripts/bootstrap.sql` (metadata role + database, the
CREATEDB CREATEROLE panel role, and the superuser bootstrap server-init
would otherwise ask for):

```sh
sudo -u postgres psql -d postgres \
  -v cryptarch_pw='metadata-role-password' \
  -v admin_pw='panel-role-password' \
  -f scripts/bootstrap.sql
```

Chef: run it guarded or just always — re-runs are no-ops and existing role
passwords are deliberately NOT reset by a re-converge. The app's own schema
inside the `cryptarch` database is migrated automatically at startup; this
file is the only manual SQL in the deployment.

`pg_hba.conf`: localhost scram for the roles above is all Cryptarch needs.
Tenant consumers never reach Postgres directly, so no LAN lines here.

## 3. PgBouncer

Distro package. `/etc/pgbouncer/pgbouncer.ini` is **yours** (Chef-templated);
Cryptarch only ever appends one `%include` line to it (idempotently, during
server-init) and owns the three files beside it. Template it from
`bouncer-seed/pgbouncer.ini` in this repo; the essentials:

```ini
[databases]
* = host=127.0.0.1 port=5432

[pgbouncer]
listen_addr = 0.0.0.0              ; or the LAN interface specifically
listen_port = 6432
auth_type = hba
auth_hba_file = /etc/pgbouncer/pgbouncer_hba.conf
auth_file = /etc/pgbouncer/userlist.txt
admin_users = pgbadmin
auth_user = cryptarch_auth
auth_dbname = postgres
auth_query = SELECT usename, passwd FROM cryptarch.get_auth($1)
ignore_startup_parameters = extra_float_digits,options

; MUST stay the LAST line of [pgbouncer]: the fragment is headerless (a
; re-opened section header resets every key above to its default on
; PgBouncer 1.24), and last-wins is what lets portal values override these.
%include /etc/pgbouncer/cryptarch_bouncer.ini
```

Ship placeholder files so pgbouncer starts before Cryptarch's first render
(Chef: `create_if_missing` — after first boot Cryptarch owns their content):

- `/etc/pgbouncer/cryptarch_bouncer.ini` — one comment line is fine
- `/etc/pgbouncer/pgbouncer_hba.conf` — console line only:
  `host pgbouncer pgbadmin 0.0.0.0/0 scram-sha-256`
- `/etc/pgbouncer/userlist.txt` — `"pgbadmin" "console-password"`

Files Cryptarch manages after that (do NOT template these — `create_if_missing`
only, or Chef and Cryptarch will fight):

| file                    | owner of content                              |
|-------------------------|-----------------------------------------------|
| `pgbouncer_hba.conf`    | rendered from ACLs on every edge sync         |
| `cryptarch_bouncer.ini` | rendered from pool settings on every sync     |
| `userlist.txt`          | Cryptarch rewrites its own auth-role line only; other lines (your `pgbadmin`) are preserved |
| `pgbouncer.ini`         | yours; Cryptarch appends the `%include` once  |

## 4. Cryptarch

Build and install the single binary:

```sh
cargo build --release
install -m 0755 target/release/cryptarch /usr/local/bin/cryptarch
install -d -o cryptarch -g cryptarch -m 0750 /etc/cryptarch
(umask 077; openssl rand -hex 32 > /etc/cryptarch/key)
chown cryptarch:cryptarch /etc/cryptarch/key
```

`/etc/systemd/system/cryptarch.service`:

```ini
[Unit]
Description=Cryptarch database provisioning portal
After=network-online.target postgresql.service pgbouncer.service
Wants=network-online.target

[Service]
User=cryptarch
Group=cryptarch
SupplementaryGroups=pgbouncer
EnvironmentFile=/etc/cryptarch/env
ExecStart=/usr/local/bin/cryptarch
Restart=on-failure
RestartSec=3

# Hardening — the app needs exactly: network, /etc/pgbouncer writes, its key.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/pgbouncer
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
```

`/etc/cryptarch/env` (mode 0640 root:cryptarch — it holds secrets):

```sh
CRYPTARCH_METADATA_DSN=postgres://cryptarch:pw@localhost/cryptarch
CRYPTARCH_BIND=0.0.0.0:8080
CRYPTARCH_ADMIN=admin
CRYPTARCH_ADMIN_PASSWORD=first-boot-only-password
CRYPTARCH_DEFAULT_QUOTA=3
CRYPTARCH_KEY_FILE=/etc/cryptarch/key

# Seed managed server (first boot; authoritative for its row on every boot —
# drop these lines once the CRUD manages servers, or leave and accept that).
CRYPTARCH_SEED_SERVER_DSN=postgres://cryptarch_admin:pw@localhost:5432/postgres
CRYPTARCH_SEED_SERVER_NAME=local
# Advertised address = what lands in user connection strings = the BOUNCER:
CRYPTARCH_SEED_SERVER_HOST=10.10.100.5        # this box's LAN IP or FQDN
CRYPTARCH_SEED_SERVER_PORT=6432
# Named source offered at provision time, pre-ticked:
CRYPTARCH_SEED_SERVER_DEFAULT_CIDR=10.10.100.0/24
# Same-box dial path, seeded as a listener labeled "db network"
# (label is cosmetic — here it means "this machine"):
CRYPTARCH_SEED_SERVER_STACK_LISTENER=127.0.0.1:6432
```

Full env reference: `CRYPTARCH_METADATA_DSN`*, `CRYPTARCH_ADMIN_PASSWORD`*,
`CRYPTARCH_KEY_FILE`* (required); `CRYPTARCH_BIND` (0.0.0.0:8080),
`CRYPTARCH_ADMIN` (admin), `CRYPTARCH_DEFAULT_QUOTA` (3);
`CRYPTARCH_HEALTH_INTERVAL_SECS` (60, 0 = off), `CRYPTARCH_NOTIFY_URL`
(unset = audit-only), `CRYPTARCH_NOTIFY_FORMAT` (ntfy | json);
`CRYPTARCH_BACKUP_DIR` (unset = backups off; needs `postgresql-client-18` on
PATH for `pg_dump`, and the unit's user must own the directory),
`CRYPTARCH_BACKUP_INTERVAL_SECS` (86400, 0 = manual only), `CRYPTARCH_BACKUP_KEEP`
(7 successes per database, 0 = keep all), `CRYPTARCH_BACKUP_STALE_AFTER_SECS`
(172800, 0 = off) — or drive it externally with `cryptarch backup --all` from a
systemd timer, which exits non-zero if any backup failed;
`CRYPTARCH_INSECURE_COOKIES` (dev only), `CRYPTARCH_ALLOW_SUPERUSER_ADMIN`
(dev only, never production); seed block optional as above.

## 5. First boot sequence

1. Chef converges: packages, users/groups, configs, placeholder files, unit.
2. `systemctl start cryptarch` — migrates the metadata schema, creates the
   bootstrap admin, upserts the seed server (encrypting its DSN with the key),
   seeds the named source and listener.
3. Log in → Servers → the seed server → **Run server init**. Init asserts the
   auth role + `cryptarch.get_auth` shim, writes the userlist line and the
   knobs fragment, appends the `%include`, and RELOADs the bouncer. (If you
   pre-ran the superuser bootstrap SQL in §2, this completes first try.)
4. Provision a test database; connect through :6432 from an allowed source.

## 6. Chef-specific notes

- **Ownership boundary:** Chef owns packages, users, `pgbouncer.ini`,
  `postgresql.conf`, the unit, and `/etc/cryptarch`. Cryptarch owns the three
  rendered files and rows in its metadata DB. Never let Chef template the
  rendered files — `create_if_missing` is the contract.
- **Idempotency:** everything Cryptarch does at boot is upsert-shaped
  (migrations, seed row, source, listener, `%include` append), so repeated
  restarts and re-converges are safe.
- **Secrets:** `CRYPTARCH_ADMIN_PASSWORD` matters on first boot only;
  the key file must never land in the same backup as the metadata DB dump
  (it decrypts the stored admin DSNs).
- **Multi-server later:** more managed Postgres boxes are added through the
  UI, not env — each remote box needs its own `cryptarch_admin` role +
  superuser bootstrap, which a Chef role can pre-stage exactly like §2.
- The seed env is authoritative for its row **every boot** — a rotated admin
  DSN gets overwritten by a stale Chef attribute. Either keep the attribute
  current or drop the seed block after first converge.
