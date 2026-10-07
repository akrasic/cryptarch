# dbportal — a small self-service Postgres provisioning panel

*Spec drafted 2026-07-16 with Antun. The gap none of pgAdmin/CloudBeaver/Adminer fills: a portal where an admin (or the user themselves) creates an isolated database + login in one click and walks away with a connection string. This is the "Supabase project button" without the Supabase stack.*

## Why build instead of buy

The off-the-shelf tools are DBA consoles — they manage the *server*. What's missing is the *provisioning workflow*: role + owned DB + isolation + credential handoff as one atomic, auditable action, optionally self-service. That last mile is genuinely a gap, not a reinvention. Scope stays small precisely because Postgres does the hard part; the panel is a thin, safe wrapper over `CREATE ROLE` / `CREATE DATABASE`.

## Non-goals (keep it small)

- Not a query editor / table browser — CloudBeaver already does that; link out to it.
- Not multi-tenant SaaS — single admin org, homelab scale.
- Not a Postgres cluster manager — one server, one panel.

## Decisions locked (2026-07-16)

- **Language: Rust.** One static binary. No runtime.
- **Model: self-service with per-user quotas.** Users log in and provision their *own* databases, up to a limit. Admin sets the cap, sees everything, can override. This is the real work — the auth + quota + ownership model.
- **Auth roadmap: local accounts in v1, LDAP added next.** (LDAP, not just OIDC — it's the enterprise directory that fits the work context. OIDC/Entra can follow but LDAP is the named target.)
- **Target is a REMOTE server, not colocated.** The panel manages one or more database servers over the network by admin connection — it is not assumed to live beside the DB. A "managed server" is a configured connection (host, port, admin creds, engine).
- **Multi-engine: PostgreSQL first, MySQL/MariaDB next.** This is the load-bearing architectural decision — the provisioning logic lives behind an **engine trait**, so Postgres and MySQL are two implementations of the same interface. Getting this boundary right in v0.1 (even with only Postgres implemented) is what stops MySQL from being a rewrite.

## Architecture consequence: the Engine trait

The DDL differs per engine, so provisioning is abstracted:

```
trait DbEngine {
    async fn create_user_db(&self, name, password) -> Result<ConnString>;
    async fn drop_user_db(&self, name) -> Result<()>;
    async fn set_login(&self, role, enabled: bool) -> Result<()>;   // suspend/resume
    async fn rotate_password(&self, role, password) -> Result<ConnString>;
    async fn stats(&self, name) -> Result<DbStats>;                 // size, last active
}
```

- **PostgresEngine**: `CREATE ROLE ... LOGIN` / `CREATE DATABASE ... OWNER` / `REVOKE CONNECT FROM PUBLIC`; stats from `pg_database_size` + `pg_stat_activity`.
- **MySqlEngine** (v0.3+): `CREATE USER` / `CREATE DATABASE` / `GRANT ALL ON db.* TO user` — MySQL's grant model is per-database so isolation is grant-scoped rather than role-owned. Same trait, different SQL.
- A **ManagedServer** record = {id, name, engine, host, port, admin connection}. The panel holds admin creds for each managed server (encrypted at rest) and instantiates the right engine per server. Users provision *onto* a chosen managed server, within quota.

## Core model

- **User**: authenticates (OIDC via Entra, or local accounts to start). Has a `db_quota` (default e.g. 3). Sees only their own databases. Provisions up to quota, manages (rotate/suspend/delete) their own, cannot see or touch anyone else's.
- **Admin**: superuser of the *panel* (not of Postgres). Sees all users and all databases. Sets/overrides per-user quotas, suspends users, views the global audit log. First admin bootstrapped from env.
- **Database record**: name, owner (panel user), owner role (pg), created_at, status (active/suspended), size (`pg_database_size`), last-connection (`pg_stat_activity`).
- **Provisioning action** = reserve, then build: in one metadata transaction, lock the user row (`FOR UPDATE`), verify the slots the user holds (every database row except those in a status that frees its slot) are below `user.db_quota`, insert the ownership row, commit. *Then*, outside that transaction, `CREATE ROLE x LOGIN PASSWORD ...` → `CREATE DATABASE x_db OWNER x` → `REVOKE CONNECT ... FROM PUBLIC` on the managed server, deleting the reservation if that fails → return connection string once (stored only as hash; shown one time, Entra-style).

## Quota + ownership model (the crux)

- Panel keeps its *own* small metadata DB (users, databases, quotas, audit) — separate from the databases it provisions. This is the source of truth for "who owns what" and "how many is Alice allowed."
- Every provision reserves its quota slot by writing the `databases` row under a `FOR UPDATE` lock on the user, and commits that before touching the managed server. Two rapid clicks can't race past the cap: the second blocks on the lock, then counts the first one's committed row. The engine call stays outside the transaction on purpose, so a slow remote `CREATE DATABASE` never holds a metadata pool connection.
- Suspend a user → all their pg roles get `NOLOGIN`, databases stay intact (reversible). Delete a user → typed-name confirm, cascades to their databases (the irreversible door).
- Quota is a soft integer per user; admin can bump it. A global default lives in config.

## MVP surface (v0.1)

1. **Login** (admin only).
2. **Dashboard**: table of databases — name, owner, size, status, last active. Search/filter.
3. **New database**: modal → name (validated: `^[a-z][a-z0-9_]{2,62}$`), optional description. On submit: provision, show the connection string once with a copy button and a "you won't see this again" warning.
4. **Manage row**: rotate password (regenerates, shows once), suspend (`ALTER ROLE ... NOLOGIN`), delete (with a typed-name confirm — the one irreversible action, gated).
5. **Audit log**: append-only table of every action (who, what, when) — because this is credential issuance and it should never be a mystery who created what.

## Stack (opinionated, minimal)

- **Backend**: one Go or Rust binary (you speak both; Rust keeps it a single static binary next to the DB). Talks to Postgres over the `db` network with an admin role scoped to CREATEROLE + CREATEDB — *not* superuser (principle of least privilege; the panel can't drop the server).
- **Frontend**: server-rendered HTML + a little htmx, or a tiny SPA — no build-tool circus for something this size. It's five screens.
  *(2026-10-07: it outgrew that. The UI is now a SvelteKit SPA over a JSON API, compiled into the same single binary — see dec-cryptarch-sveltekit-architecture and CLAUDE.md.)*
- **Auth**: start with a single admin credential in env; graft OIDC/Entra later (same flow as Komodo — `/auth/oidc/callback`).
- **Deploy**: one container on the `db` network, behind the existing proxy. Compose stanza ships with it.

## Security spine (non-negotiable, since this issues credentials)

- Panel's DB role is `CREATEDB CREATEROLE` only, never superuser.
- Generated passwords: 32-char, CSPRNG, shown once, stored only as hash.
- Every mutating action is audit-logged before it returns.
- Delete requires typed-name confirmation.
- Rate-limit provisioning; validate all identifiers against an allowlist regex to kill SQL-injection-via-dbname before it starts.
- No secrets in client-side anything (the exact own-goal that burned the Taiwan victims in the July 16 espionage report — noted deliberately).

## Stack detail (Rust)

- **axum** (web) + **sqlx** (Postgres, compile-time-checked queries) + **askama** or **maud** for server-rendered HTML + **htmx** sprinkled for the interactive bits (modal, copy-once, live quota counter). No JS build step.
  *(Superseded 2026-10-07: maud and htmx were replaced by a SvelteKit SPA and the `/api/v1` JSON API; the deploy is still one binary.)*
- Sessions: signed cookie (tower-sessions). Passwords/tokens: `argon2`. CSPRNG via `rand`.
- Panel connects as a dedicated pg role: `CREATEDB CREATEROLE`, never superuser.
- Single binary + one `Dockerfile` (scratch/distroless final stage) + compose stanza on the `db` network.

## Build phases

- **v0.1**: local accounts, login, per-user dashboard (own DBs only), create-with-quota-check, show-once connection string, audit log. The quota model is in from day one — it's the point.
- **v0.2**: rotate / suspend / delete (own DBs), size + last-active columns, admin view (all users, quota override).
- **v0.3**: OIDC/Entra login (same `/auth/oidc/callback` flow as Komodo), self-registration toggle.

## Decisions still open

1. **Login source for v0.1** — local accounts (fastest to build, no Entra dependency) then graft Entra in v0.3? Or Entra from the start? Lean: local first, it de-risks the core.
2. **Where the panel's own metadata DB lives** — its own database on the same Postgres instance (simplest) vs SQLite in the container (fully self-contained). Lean: a `dbportal` database on the same instance; one less moving part than SQLite-in-a-volume, and it dogfoods the thing.
3. Deploy as a Komodo stack on the komodo box beside Postgres — assumed yes.
