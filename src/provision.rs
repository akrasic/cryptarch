//! The provisioning core — the heart of Cryptarch.
//!
//! Provisioning spans two servers that can't share one SQL transaction: the
//! metadata DB (ownership, quota) and the target server (the actual database).
//! We get atomicity by ordering:
//!
//! 1. Metadata transaction with the user row **locked** (`FOR UPDATE`) — count
//!    the slots the user holds ([`slots_used`]: every status but those that
//!    free one, so an unknown status is counted), reject if at quota, insert
//!    the record, commit. The lock serialises concurrent provisions for one
//!    user, so two fast clicks can't both slip past the cap.
//! 2. Create the database on the target via [`DbEngine`] — outside that
//!    transaction, deliberately, so a slow remote `CREATE DATABASE` never holds
//!    a metadata connection.
//! 3. On engine failure, delete the metadata row (compensating action).
//!
//! The window where a metadata row exists but the target DB doesn't is small
//! and self-corrects on failure; the reverse (orphan DB, no record) never
//! happens because the record is written first.

use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth;
use crate::engine::ConnString;
use crate::names;
use crate::servers::ServerRegistry;

#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("database name must be 3-63 chars, lowercase letter first, then [a-z0-9_]")]
    BadName,
    #[error("'{0}' is not a valid IP or CIDR (no hostnames; network prefixes need zero host bits)")]
    BadCidr(String),
    /// The database is mid-delete or mid-restore: a delete has already
    /// disabled the role's login, so a new password could not log in.
    #[error("this database is {0} — its password can't be reset until it is active again")]
    NotActive(String),
    /// A non-admin asked for a range only an admin may allow (CRYPTARCH-142).
    #[error("{}", crate::servers::range_too_broad_message(.0))]
    RangeTooBroad(String),
    #[error("unknown or unavailable server")]
    NoServer,
    #[error("database quota reached ({used}/{quota})")]
    QuotaReached { used: i64, quota: i32 },
    #[error("a database named '{0}' already exists")]
    NameTaken(String),
    #[error("internal error")]
    Internal,
}

/// Outcome handed back to the UI: username, password, and full connection
/// string — shown exactly once. The password is never persisted in the clear;
/// only its Argon2 hash is stored, so this is the one moment it exists to show.
pub struct Provisioned {
    pub name: String,
    pub username: String,
    pub password: String,
    pub conn: ConnString,
    /// The credential below is live on the managed server, but Cryptarch failed
    /// to record its hash (CRYPTARCH-101).
    ///
    /// Only [`reset_password`] can set this. Provisioning cannot: it writes its
    /// metadata row BEFORE the engine call and compensates by deleting that row
    /// on failure, so there is no state where a provisioned credential exists
    /// unrecorded. A rotation has no such escape — the old password is already
    /// dead by the time the write is attempted — so the failure has to be
    /// carried forward and shown rather than swallowed or turned into an error.
    pub unrecorded: bool,
}

/// How many quota slots `owner_id` holds — THE count the cap is enforced
/// against.
///
/// One function so the dashboard can show the enforcer's number rather than
/// re-deriving it (CRYPTARCH-122). Counting the dashboard's own visible list
/// matched only while every visible status also occupied a slot; nothing made
/// that hold.
pub async fn slots_used<'e, E: sqlx::PgExecutor<'e>>(ex: E, owner_id: Uuid) -> sqlx::Result<i64> {
    sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM databases WHERE owner_id = $1 AND {}",
        crate::status::DbStatus::quota_exclusion_sql()
    )))
    .bind(owner_id)
    .fetch_one(ex)
    .await
}

/// Provision a database for `owner_id` on `server_id`. See module docs for the
/// atomicity model.
pub async fn provision_db(
    db: &sqlx::PgPool,
    registry: &ServerRegistry,
    owner_id: Uuid,
    actor: &str,
    server_id: Uuid,
    name: &str,
    // acl_sources: (cidr, note) pairs — the note carries a named source's
    // label so the ACL list later reads "db network", not CIDR archaeology.
    acl_sources: &[(String, Option<String>)],
) -> Result<Provisioned, ProvisionError> {
    if !names::valid_db_name(name) {
        return Err(ProvisionError::BadName);
    }
    for (c, _) in acl_sources {
        if !crate::servers::valid_cidr(c) {
            return Err(ProvisionError::BadCidr(c.clone()));
        }
    }
    let engine = registry.get(server_id).ok_or(ProvisionError::NoServer)?;

    // An unlocked look before paying for the hash (CRYPTARCH-128). A user
    // already at quota would otherwise spend an Argon2 hash — from the shared
    // capped pool — on every refused click. Advisory only: the authoritative
    // count is the one below, under the lock. A stale read here at worst lets
    // one hash through that the real check then refuses.
    if let Ok(Some(q)) = sqlx::query_scalar::<_, Option<i32>>("SELECT db_quota FROM users WHERE id = $1")
        .bind(owner_id)
        .fetch_one(db)
        .await
        && let Ok(used) = slots_used(db, owner_id).await
        && used >= q as i64
    {
        return Err(ProvisionError::QuotaReached { used, quota: q });
    }

    let password = names::generate_password();
    let password_hash = auth::hash_password_capped(password.clone()).await.map_err(|_| ProvisionError::Internal)?;

    // ---- 1. metadata transaction: lock, quota-check, reserve --------------
    let mut tx = db.begin().await.map_err(|_| ProvisionError::Internal)?;

    // NULL quota = unlimited; the FOR UPDATE lock still serialises the check.
    let quota: Option<i32> = sqlx::query_scalar("SELECT db_quota FROM users WHERE id = $1 FOR UPDATE")
        .bind(owner_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ProvisionError::Internal)?;

    // The predicate comes from `DbStatus`, not from a literal here
    // (CRYPTARCH-81). It used to read `status = 'active'`, which meant every
    // status added later was silently exempt from the cap — and a status that
    // does not occupy a slot is a way to hold a database outside it:
    // provision, move it into that status, provision again. It is phrased as
    // an exclusion so an unrecognised status is COUNTED rather than exempted.
    let used = slots_used(&mut *tx, owner_id).await.map_err(|_| ProvisionError::Internal)?;

    if let Some(q) = quota
        && used >= q as i64
    {
        // rollback is implicit on drop, but be explicit
        let _ = tx.rollback().await;
        return Err(ProvisionError::QuotaReached { used, quota: q });
    }

    let insert = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO databases (owner_id, server_id, name, password_hash, status) \
         VALUES ($1, $2, $3, $4, 'active') RETURNING id",
    )
    .bind(owner_id)
    .bind(server_id)
    .bind(name)
    .bind(&password_hash)
    .fetch_one(&mut *tx)
    .await;

    let record_id: Uuid = match insert {
        Ok(id) => id,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            let _ = tx.rollback().await;
            return Err(ProvisionError::NameTaken(name.to_string()));
        }
        Err(_) => {
            let _ = tx.rollback().await;
            return Err(ProvisionError::Internal);
        }
    };

    // "Allowed from" lands in the same transaction as the reservation —
    // a database and its ACL are born together or not at all.
    for (cidr, note) in acl_sources {
        if let Err(e) = sqlx::query(
            "INSERT INTO acl_entries (database_id, cidr, created_by, note) \
             VALUES ($1, $2::cidr, $3, $4) ON CONFLICT (database_id, cidr) DO NOTHING",
        )
        .bind(record_id)
        .bind(cidr)
        .bind(actor)
        .bind(note.as_deref())
        .execute(&mut *tx)
        .await
        {
            tracing::error!("acl insert for '{name}' ({cidr}): {e:#}");
            let _ = tx.rollback().await;
            // Only an invalid-text-representation (22P02) is the user's CIDR;
            // anything else (connection loss, ...) must not be blamed on it.
            let is_bad_value = e
                .as_database_error()
                .and_then(|d| d.code())
                .is_some_and(|c| c == "22P02");
            return Err(if is_bad_value {
                ProvisionError::BadCidr(cidr.clone())
            } else {
                ProvisionError::Internal
            });
        }
    }

    tx.commit().await.map_err(|_| ProvisionError::Internal)?;

    // ---- 2. create on the target server -----------------------------------
    match engine.create_user_db(name, &password).await {
        Ok(conn) => {
            audit(db, actor, "create_db", Some(name), Some("ok")).await;
            Ok(Provisioned {
                name: name.to_string(),
                username: name.to_string(),
                password,
                conn,
                // Always false here, and structurally so — see the field's doc.
                // The metadata row was written before this engine call and is
                // deleted again if it fails, so a provisioned credential is
                // never live-but-unrecorded.
                unrecorded: false,
            })
        }
        Err(e) => {
            // ---- 3. compensate: remove the reserved record -----------------
            let _ = sqlx::query("DELETE FROM databases WHERE id = $1")
                .bind(record_id)
                .execute(db)
                .await;
            audit(db, actor, "create_db_failed", Some(name), Some(&e.to_string())).await;
            // {e:#} prints the full context chain — the top line alone
            // ("creating login role") hides the actual Postgres error.
            tracing::error!("engine provisioning failed for '{name}': {e:#}");
            Err(ProvisionError::Internal)
        }
    }
}

/// A provisioned database as its owner views it — connection details, never the
/// password (which isn't stored in the clear to show).
#[derive(sqlx::FromRow)]
pub struct DbDetail {
    /// The database's own identity, as distinct from its name (CRYPTARCH-86).
    /// Names are freed on delete and re-provisionable by anyone, so anything
    /// that must belong to *this* database rather than to whoever holds the
    /// name has to key on this.
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub server_id: Uuid,
    pub server_name: String,
    pub host: String,
    pub port: i32,
    pub engine: String,
}

impl DbDetail {
    /// Connection string with the password masked — safe to display any time.
    pub fn masked_conn(&self) -> String {
        self.masked_conn_at(&self.host, self.port)
    }

    /// The masked string for one dial path — the db page shows one per
    /// listener (CRYPTARCH-40). IPv6 literals need brackets or libpq
    /// misparses them.
    pub fn masked_conn_at(&self, host: &str, port: i32) -> String {
        let host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        format!(
            "postgresql://{user}:••••••••@{host}:{port}/{db}",
            user = self.name,
            db = self.name,
        )
    }
}

/// A database `user_id` may LOOK at (CRYPTARCH-140): their own, or — for an
/// admin — anyone's, with the owner's username so the page can say whose it is.
///
/// For viewing only. The actions that hand out a credential (reset) or act as
/// the tenant (backup, restore) stay owner-scoped through [`owned_db_detail`];
/// an admin seeing a database must not mean an admin seeing its new password.
/// `None` for anyone else, exactly as for a name that does not exist.
pub async fn viewable_db_detail(
    db: &sqlx::PgPool,
    user_id: Uuid,
    is_admin: bool,
    name: &str,
) -> Result<Option<ViewableDb>, ProvisionError> {
    // No database can be named with a NUL (valid_db_name), and Postgres
    // refuses one in a text parameter — answered as "no such database" rather
    // than an error, like every other name that cannot exist.
    if name.contains('\0') {
        return Ok(None);
    }
    sqlx::query_as::<_, ViewableDb>(
        "SELECT d.id, d.name, d.status, d.created_at, s.id AS server_id, \
                s.name AS server_name, s.host, s.port, s.engine, u.username AS owner, \
                d.owner_id = $1 AS is_owner \
         FROM databases d JOIN managed_servers s ON s.id = d.server_id \
         JOIN users u ON u.id = d.owner_id \
         WHERE d.name = $2 AND (d.owner_id = $1 OR $3)",
    )
    .bind(user_id)
    .bind(name)
    .bind(is_admin)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!("looking up database {name:?}: {e}");
        ProvisionError::Internal
    })
}

/// What [`viewable_db_detail`] returns: the detail, whose it is, and whether
/// that is the caller — by id, not by comparing names.
#[derive(sqlx::FromRow)]
pub struct ViewableDb {
    #[sqlx(flatten)]
    pub detail: DbDetail,
    pub owner: String,
    pub is_owner: bool,
}

/// Fetch one of `owner_id`'s databases by name. Owner-scoped: returns `None` if
/// the database doesn't exist or belongs to someone else (no cross-user peeking).
pub async fn owned_db_detail(
    db: &sqlx::PgPool,
    owner_id: Uuid,
    name: &str,
) -> Result<Option<DbDetail>, ProvisionError> {
    // As in `viewable_db_detail`: no name has a NUL, and Postgres would refuse
    // it as an error rather than match nothing.
    if name.contains('\0') {
        return Ok(None);
    }
    sqlx::query_as::<_, DbDetail>(
        "SELECT d.id, d.name, d.status, d.created_at, s.id AS server_id, \
                s.name AS server_name, s.host, s.port, s.engine \
         FROM databases d JOIN managed_servers s ON s.id = d.server_id \
         WHERE d.owner_id = $1 AND d.name = $2",
    )
    .bind(owner_id)
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(|_| ProvisionError::Internal)
}

/// Reset (rotate) a database's password. Owner-scoped. Generates a new password,
/// applies it on the target server, updates the stored hash, and returns the new
/// credentials to show once. The old password stops working immediately.
pub async fn reset_password(
    db: &sqlx::PgPool,
    registry: &ServerRegistry,
    owner_id: Uuid,
    actor: &str,
    name: &str,
) -> Result<Provisioned, ProvisionError> {
    let detail = owned_db_detail(db, owner_id, name)
        .await?
        .ok_or(ProvisionError::NoServer)?;
    let engine = registry.get(detail.server_id).ok_or(ProvisionError::NoServer)?;

    let password = names::generate_password();
    let password_hash = auth::hash_password_capped(password.clone()).await.map_err(|_| ProvisionError::Internal)?;

    let conn = engine
        .rotate_password(name, &password)
        .await
        .map_err(|e| {
            tracing::error!("password rotate failed for '{name}': {e}");
            ProvisionError::Internal
        })?;

    // CRYPTARCH-101: THE ROTATE IS THE COMMIT POINT. Everything below is
    // record-keeping, and record-keeping that fails must not be reported as a
    // reset that did not happen.
    //
    // `ALTER ROLE ... PASSWORD` has already taken effect on the managed server:
    // the old password stops working the instant that returns. This used to
    // `?` on the UPDATE, which rendered "Password reset failed" and dropped
    // `password` — the ONLY copy that ever existed — on the floor. The tenant
    // then kept using a credential Postgres had already stopped accepting,
    // with nothing anywhere recording that a rotation had happened at all,
    // because the audit line below was only reached on success.
    //
    // There is no compensating action; you cannot un-rotate. So the credential
    // is returned either way and the bookkeeping failure is reported alongside
    // it. `rows_affected` is checked too, not just `Err`: a statement that
    // succeeds and matches nothing (the row deleted mid-request) leaves the
    // same stale hash as a failed one.
    let recorded =
        sqlx::query("UPDATE databases SET password_hash = $1 WHERE owner_id = $2 AND name = $3")
            .bind(&password_hash)
            .bind(owner_id)
            .bind(name)
            .execute(db)
            .await;

    let unrecorded = match recorded {
        Ok(r) if r.rows_affected() == 1 => false,
        Ok(_) => {
            tracing::error!(
                "password rotated for '{name}' but no row was updated — \
                 the database row is gone or not this owner's"
            );
            true
        }
        Err(e) => {
            tracing::error!("password rotated for '{name}' but the hash was not recorded: {e}");
            true
        }
    };

    // Both outcomes are audited, mirroring the three-way shape the backup
    // runner already uses. A rotation that happened is a fact about the managed
    // server, and the audit trail has to carry it whether or not Cryptarch
    // managed to write down the hash.
    audit(
        db,
        actor,
        if unrecorded { "reset_password_unrecorded" } else { "reset_password" },
        Some(name),
        Some(if unrecorded { "rotated on the server; hash not recorded" } else { "ok" }),
    )
    .await;

    Ok(Provisioned {
        name: name.to_string(),
        username: name.to_string(),
        password,
        conn,
        unrecorded,
    })
}

/// Minimal row for looking up a database by name (for lifecycle ops).
#[derive(sqlx::FromRow)]
pub struct DbLookup {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub server_id: Uuid,
    pub status: String,
}

/// Find a database record by name. Database names are globally unique
/// (migration 0010), so this resolves to at most one row — the `LIMIT 1` is
/// belt-and-suspenders against a constraint regression, not disambiguation.
/// Used by lifecycle ops that then authorise by owner or admin.
pub async fn find_db(db: &sqlx::PgPool, name: &str) -> Result<Option<DbLookup>, ProvisionError> {
    // As in `viewable_db_detail`: a NUL cannot be in any name, and Postgres
    // would refuse it as an error rather than match nothing.
    if name.contains('\0') {
        return Ok(None);
    }
    sqlx::query_as::<_, DbLookup>(
        "SELECT id, owner_id, server_id, status FROM databases WHERE name = $1 LIMIT 1",
    )
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(|_| ProvisionError::Internal)
}

/// Why a retry of a failed delete was refused.
#[derive(Debug)]
pub enum RetryRefusal {
    /// The row is no longer mid-delete — the maintenance sweep returned it to
    /// service between the page being rendered and the button being pressed.
    NoLongerDeleting,
    /// Nothing was ever destroyed: login is still enabled and the database is
    /// still present, so this is a delete that never started, not one that
    /// stopped halfway. The sweep will return it to service.
    NothingWasStarted,
    /// The server could not be asked, so the precondition could not be
    /// checked. Refusing is the only safe answer.
    CouldNotCheck(String),
    /// Another finish of this same database is in progress (S6b/c audit P1).
    AlreadyBeingFinished,
}

/// Finish a delete that failed partway (CRYPTARCH-80).
///
/// # The precondition is checked HERE, not when the page was rendered
///
/// The report decides what to *offer* by looking at the same two facts this
/// checks. That is a render-time decision, and it goes stale: between an
/// operator loading a page whose entire purpose is to be read slowly, and
/// their click, the maintenance sweep can return the row to service. Acting on
/// "it said `deleting` when I rendered" would then **destroy a live, healthy,
/// tenant-serving database that the system declared fine seconds earlier** —
/// which is precisely what refusing the never-started case exists to prevent,
/// arriving through the door a render-time filter does not cover.
///
/// So the destructive step is gated on facts re-read from the **server**
/// immediately before it, in the same spirit as counting quota under the
/// user's lock at the moment the slot is reserved, rather than trusting the
/// dashboard's count. A render-time check decides what to offer; only an
/// action-time check decides what happens.
///
/// Note the check deliberately asks the server rather than the row. This is
/// claim C7 from [`crate::repair`] for the third time — **metadata supplies
/// identity, the server supplies state** — and the third independent arrival
/// is the point at which it should stop being re-derived. The row records what
/// Cryptarch *intended*; the server records what is *true*; destruction is
/// gated on truth. The row is still consulted as a secondary signal
/// (`NoLongerDeleting`), because a row that changed underneath you is
/// information even when it is not the guard.
///
/// `CouldNotCheck` refuses rather than proceeding, which is the quota
/// exclusion's asymmetric-consequence rule pointed the other way: there an
/// unknown status must COUNT, here an unknown state must NOT ACT. Same rule —
/// pick the direction whose failure is recoverable.
pub async fn retry_delete(
    db: &sqlx::PgPool,
    registry: &ServerRegistry,
    lookup: &DbLookup,
    name: &str,
    actor: &str,
) -> Result<Result<(), RetryRefusal>, ProvisionError> {
    if lookup.status != "deleting" {
        return Ok(Err(RetryRefusal::NoLongerDeleting));
    }
    // One finisher per database, by IDENTITY (S6b/c audit P1). The lookup was
    // taken by name, possibly long ago; under this lock the row is re-read by
    // its id. Two stale finishers cannot both act, and once one has finished
    // and freed the name, a new database under that name has another id — so
    // the other finds nothing and refuses instead of dropping the newcomer.
    // A session-level lock on its own connection, released whatever happens;
    // held across the remote checks and the drop, which a rare admin action
    // can afford.
    let mut conn = db.acquire().await.map_err(|_| ProvisionError::Internal)?;
    let key = format!("cryptarch-finish:{}", lookup.id);
    let won: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))")
        .bind(&key)
        .fetch_one(&mut *conn)
        .await
        .map_err(|_| ProvisionError::Internal)?;
    if !won {
        return Ok(Err(RetryRefusal::AlreadyBeingFinished));
    }
    let outcome = retry_delete_locked(db, registry, lookup, name, actor).await;
    let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext($1))").bind(&key).execute(&mut *conn).await;
    outcome
}

async fn retry_delete_locked(
    db: &sqlx::PgPool,
    registry: &ServerRegistry,
    lookup: &DbLookup,
    name: &str,
    actor: &str,
) -> Result<Result<(), RetryRefusal>, ProvisionError> {
    let still: Option<String> = sqlx::query_scalar("SELECT status FROM databases WHERE id = $1 AND name = $2")
        .bind(lookup.id)
        .bind(name)
        .fetch_optional(db)
        .await
        .map_err(|_| ProvisionError::Internal)?;
    if still.as_deref() != Some("deleting") {
        return Ok(Err(RetryRefusal::NoLongerDeleting));
    }
    let engine = registry.get(lookup.server_id).ok_or(ProvisionError::NoServer)?;

    let can_log_in = match engine.login_states(crate::repair::PANEL_OWNED_ROLES).await {
        Ok(roles) => roles.iter().any(|r| r.role_name == name && r.can_login),
        Err(e) => return Ok(Err(RetryRefusal::CouldNotCheck(format!("{e:#}")))),
    };
    let db_exists = match engine.database_exists(name).await {
        Ok(v) => v,
        Err(e) => return Ok(Err(RetryRefusal::CouldNotCheck(format!("{e:#}")))),
    };

    // A delete turns the login off FIRST. Login still on means this delete
    // never got going for this role — with the database present, nothing was
    // destroyed; with it absent, that is a provision in flight under this
    // name (role created, database not yet), not anything of ours to finish
    // (S6b/c audit P1). Either way, refuse.
    if can_log_in {
        let _ = db_exists;
        return Ok(Err(RetryRefusal::NothingWasStarted));
    }

    // Same path as an ordinary delete — a second implementation of deletion is
    // a second thing to get wrong. `find_db` does not filter on status, so the
    // shared path accepts a `deleting` row without needing a bypass flag.
    delete_db(db, registry, lookup, name, actor).await?;
    Ok(Ok(()))
}

/// Drop the database and its role on the target server, then remove the record.
/// Irreversible — the caller gates this behind a typed-name confirmation.
/// Caller has already authorised (owner or admin).
pub async fn delete_db(
    db: &sqlx::PgPool,
    registry: &ServerRegistry,
    lookup: &DbLookup,
    name: &str,
    actor: &str,
) -> Result<(), ProvisionError> {
    let engine = registry.get(lookup.server_id).ok_or(ProvisionError::NoServer)?;

    // Record the INTENT before touching the server (CRYPTARCH-79). A delete
    // that fails partway leaves a role with login disabled, and without this
    // row the login report would attribute that to a human administrator —
    // a false statement about who acted, in the document someone reads during
    // an incident. Cause is not a server-side fact; it has to be written down
    // before the act, by whoever is acting.
    //
    // The ordering is not negotiable in the other direction either: writing it
    // AFTER the engine call would leave a crash-in-between looking exactly
    // like the human lockout it exists to distinguish.
    let _ = sqlx::query(
        "UPDATE databases SET status = 'deleting', status_changed_at = now() WHERE id = $1",
    )
        .bind(lookup.id)
        .execute(db)
        .await;

    engine.drop_user_db(name).await.map_err(|e| {
        tracing::error!("drop_user_db failed for '{name}': {e}");
        ProvisionError::Internal
    })?;
    sqlx::query("DELETE FROM databases WHERE id = $1")
        .bind(lookup.id)
        .execute(db)
        .await
        .map_err(|_| ProvisionError::Internal)?;
    audit(db, actor, "delete_db", Some(name), Some("ok")).await;
    Ok(())
}

/// Append an audit entry inside the caller's transaction, so the change and its
/// record commit together or not at all — for changes that CAN be rolled back
/// (a metadata row, not a remote DDL). Unlike [`audit`], a failure is the
/// caller's to handle.
pub async fn audit_in(
    conn: &mut sqlx::PgConnection,
    actor: &str,
    action: &str,
    target: Option<&str>,
    detail: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO audit_log (actor, action, target, detail) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(detail)
        .execute(conn)
        .await
        .map(|_| ())
}

/// Append an audit entry. Best-effort: a failed audit write is logged but never
/// blocks the operation's result. (The audit table is append-only.)
pub async fn audit(
    db: &sqlx::PgPool,
    actor: &str,
    action: &str,
    target: Option<&str>,
    detail: Option<&str>,
) {
    let res = sqlx::query(
        "INSERT INTO audit_log (actor, action, target, detail) VALUES ($1, $2, $3, $4)",
    )
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(detail)
    .execute(db)
    .await;
    if let Err(e) = res {
        tracing::error!("audit write failed ({action}): {e}");
    }
}
