//! The provisioning core — the heart of Cryptarch.
//!
//! Provisioning spans two servers that can't share one SQL transaction: the
//! metadata DB (ownership, quota) and the target server (the actual database).
//! We get atomicity by ordering:
//!
//! 1. Metadata transaction with the user row **locked** (`FOR UPDATE`) — count
//!    active databases, reject if at quota, insert the record. The lock
//!    serialises concurrent provisions for one user, so two fast clicks can't
//!    both slip past the cap.
//! 2. Create the database on the target via [`DbEngine`].
//! 3. On engine failure, delete the metadata row (compensating action).
//!
//! The window where a metadata row exists but the target DB doesn't is small
//! and self-corrects on failure; the reverse (orphan DB, no record) never
//! happens because the record is written first.

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
    #[error("unknown or unavailable server")]
    NoServer,
    #[error("database quota reached ({used}/{quota})")]
    QuotaReached { used: i64, quota: i32 },
    #[error("a database named '{0}' already exists on that server")]
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

    let password = names::generate_password();
    let password_hash = auth::hash_password(&password).map_err(|_| ProvisionError::Internal)?;

    // ---- 1. metadata transaction: lock, quota-check, reserve --------------
    let mut tx = db.begin().await.map_err(|_| ProvisionError::Internal)?;

    // NULL quota = unlimited; the FOR UPDATE lock still serialises the check.
    let quota: Option<i32> = sqlx::query_scalar("SELECT db_quota FROM users WHERE id = $1 FOR UPDATE")
        .bind(owner_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ProvisionError::Internal)?;

    let used: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM databases WHERE owner_id = $1 AND status = 'active'",
    )
    .bind(owner_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ProvisionError::Internal)?;

    if let Some(q) = quota {
        if used >= q as i64 {
            // rollback is implicit on drop, but be explicit
            let _ = tx.rollback().await;
            return Err(ProvisionError::QuotaReached { used, quota: q });
        }
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

/// Fetch one of `owner_id`'s databases by name. Owner-scoped: returns `None` if
/// the database doesn't exist or belongs to someone else (no cross-user peeking).
pub async fn owned_db_detail(
    db: &sqlx::PgPool,
    owner_id: Uuid,
    name: &str,
) -> Result<Option<DbDetail>, ProvisionError> {
    sqlx::query_as::<_, DbDetail>(
        "SELECT d.name, d.status, d.created_at, s.id AS server_id, \
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
    let password_hash = auth::hash_password(&password).map_err(|_| ProvisionError::Internal)?;

    let conn = engine
        .rotate_password(name, &password)
        .await
        .map_err(|e| {
            tracing::error!("password rotate failed for '{name}': {e}");
            ProvisionError::Internal
        })?;

    sqlx::query("UPDATE databases SET password_hash = $1 WHERE owner_id = $2 AND name = $3")
        .bind(&password_hash)
        .bind(owner_id)
        .bind(name)
        .execute(db)
        .await
        .map_err(|_| ProvisionError::Internal)?;

    audit(db, actor, "reset_password", Some(name), Some("ok")).await;

    Ok(Provisioned {
        name: name.to_string(),
        username: name.to_string(),
        password,
        conn,
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

/// Find a database record by name. Name is unique per server; with the v0.1
/// single seed server this is effectively a unique lookup. Returns the first
/// match. Used by lifecycle ops that then authorise by owner or admin.
pub async fn find_db(db: &sqlx::PgPool, name: &str) -> Result<Option<DbLookup>, ProvisionError> {
    sqlx::query_as::<_, DbLookup>(
        "SELECT id, owner_id, server_id, status FROM databases WHERE name = $1 LIMIT 1",
    )
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(|_| ProvisionError::Internal)
}

/// Suspend (`active=false`) or resume (`active=true`) a database's login on the
/// target server, and reflect it in metadata. Data is left intact — suspend is
/// reversible. Caller has already authorised (owner or admin).
pub async fn set_db_active(
    db: &sqlx::PgPool,
    registry: &ServerRegistry,
    lookup: &DbLookup,
    name: &str,
    active: bool,
    actor: &str,
) -> Result<(), ProvisionError> {
    let engine = registry.get(lookup.server_id).ok_or(ProvisionError::NoServer)?;
    engine.set_login(name, active).await.map_err(|e| {
        tracing::error!("set_login failed for '{name}': {e}");
        ProvisionError::Internal
    })?;
    let status = if active { "active" } else { "suspended" };
    sqlx::query("UPDATE databases SET status = $1 WHERE id = $2")
        .bind(status)
        .bind(lookup.id)
        .execute(db)
        .await
        .map_err(|_| ProvisionError::Internal)?;
    audit(
        db,
        actor,
        if active { "resume_db" } else { "suspend_db" },
        Some(name),
        Some("ok"),
    )
    .await;
    Ok(())
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
