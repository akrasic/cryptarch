//! The database-engine abstraction — the load-bearing boundary of Cryptarch.
//!
//! Every target server (Postgres now, MySQL/MariaDB next) is one implementation
//! of [`DbEngine`]. Everything above this trait — quota checks, ownership, the
//! web UI, the audit log — is engine-agnostic. Getting this boundary clean in
//! v0.1 is what makes adding MySQL an afternoon rather than a rewrite.

use async_trait::async_trait;

pub mod postgres;

/// A ready-to-share connection string, handed to the user exactly once.
///
/// Cryptarch never persists this in plaintext — only an Argon2 hash of the
/// generated password is stored on the database record.
#[derive(Debug, Clone)]
pub struct ConnString(pub String);

/// One table inside a provisioned database, catalog-level only.
#[derive(Debug, Clone)]
pub struct TableInfo {
    pub name: String,
    /// Planner estimate (`reltuples`-class); `-1` = never analyzed.
    pub approx_rows: i64,
    /// Total on-disk size including indexes and toast.
    pub total_bytes: i64,
}

/// One database's footprint on a managed server, for the admin dashboard.
#[derive(Debug, Clone)]
pub struct DbUsage {
    pub name: String,
    pub size_bytes: i64,
    pub connections: i64,
}

/// Whole-server snapshot for the admin dashboard: version, uptime,
/// connection pressure, and every database's disk/connection footprint.
#[derive(Debug, Clone, Default)]
pub struct ServerOverview {
    pub version: String,
    pub uptime_secs: i64,
    pub total_connections: i64,
    pub max_connections: i64,
    /// All non-template databases, largest first — including ones Cryptarch
    /// doesn't manage; the caller decides how to badge them.
    pub databases: Vec<DbUsage>,
}

/// Live stats for a provisioned database, read from the target server.
#[derive(Debug, Clone, Default)]
pub struct DbStats {
    /// On-disk size in bytes.
    pub size_bytes: i64,
    /// Whether any session is currently connected.
    pub active: bool,
    /// Table list, largest first. `None` when the engine could read the
    /// database's size but not its contents (e.g. no way in) — distinct
    /// from `Some(vec![])`, a genuinely empty database.
    pub tables: Option<Vec<TableInfo>>,
}

/// What Cryptarch needs to provision and manage databases on one target server.
///
/// Implementations hold the *admin* connection to a single managed server and
/// translate these operations into engine-specific DDL. The trait is
/// deliberately small: the panel's value is the ownership/quota layer above it,
/// not the SQL below it.
/// Decorator bounding every engine call: a hung managed server must cost a
/// request seconds, not forever. Wraps any [`DbEngine`]; production wraps at
/// connect time ([`crate::servers::connect_row`]), tests wrap their mocks.
pub struct TimeoutEngine {
    inner: std::sync::Arc<dyn DbEngine>,
    timeout: std::time::Duration,
}

impl TimeoutEngine {
    pub fn wrap(
        inner: std::sync::Arc<dyn DbEngine>,
        timeout: std::time::Duration,
    ) -> std::sync::Arc<dyn DbEngine> {
        std::sync::Arc::new(Self { inner, timeout })
    }

    async fn bound<T>(
        &self,
        what: &str,
        fut: impl std::future::Future<Output = anyhow::Result<T>> + Send,
    ) -> anyhow::Result<T> {
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(r) => r,
            Err(_) => anyhow::bail!(
                "managed server did not respond within {:?} ({what}) — it may be down or wedged",
                self.timeout
            ),
        }
    }
}

#[async_trait]
impl DbEngine for TimeoutEngine {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    async fn create_user_db(&self, name: &str, password: &str) -> anyhow::Result<ConnString> {
        self.bound("create", self.inner.create_user_db(name, password)).await
    }
    async fn drop_user_db(&self, name: &str) -> anyhow::Result<()> {
        self.bound("drop", self.inner.drop_user_db(name)).await
    }
    async fn set_login(&self, name: &str, enabled: bool) -> anyhow::Result<()> {
        self.bound("set_login", self.inner.set_login(name, enabled)).await
    }
    async fn rotate_password(&self, name: &str, password: &str) -> anyhow::Result<ConnString> {
        self.bound("rotate", self.inner.rotate_password(name, password)).await
    }
    async fn stats(&self, name: &str) -> anyhow::Result<DbStats> {
        self.bound("stats", self.inner.stats(name)).await
    }
    async fn server_overview(&self) -> anyhow::Result<ServerOverview> {
        self.bound("server_overview", self.inner.server_overview()).await
    }
    async fn ping(&self) -> anyhow::Result<()> {
        self.bound("ping", self.inner.ping()).await
    }
}

#[async_trait]
pub trait DbEngine: Send + Sync {
    /// Which engine this is (`"postgres"`, `"mysql"`), for display and routing.
    fn kind(&self) -> &'static str;

    /// Provision an isolated database + login for `name`, returning the
    /// connection string once. Implementations must ensure the new role can
    /// reach only its own database (Postgres: `REVOKE CONNECT ... FROM PUBLIC`;
    /// MySQL: grants scoped to `name.*`).
    async fn create_user_db(&self, name: &str, password: &str) -> anyhow::Result<ConnString>;

    /// Drop the database and its owning role. Irreversible — callers gate this
    /// behind a typed-name confirmation.
    async fn drop_user_db(&self, name: &str) -> anyhow::Result<()>;

    /// Suspend (`false`) or resume (`true`) login for the database's role,
    /// leaving data intact.
    async fn set_login(&self, name: &str, enabled: bool) -> anyhow::Result<()>;

    /// Regenerate the role's password, returning the new connection string once.
    async fn rotate_password(&self, name: &str, password: &str)
        -> anyhow::Result<ConnString>;

    /// Read live stats for a provisioned database.
    async fn stats(&self, name: &str) -> anyhow::Result<DbStats>;

    /// Whole-server snapshot for the admin dashboard.
    async fn server_overview(&self) -> anyhow::Result<ServerOverview>;

    /// Cheapest possible liveness probe over the admin connection — the
    /// health loop (CRYPTARCH-43) runs this every interval, so it must cost
    /// one round-trip, not a catalog scan.
    async fn ping(&self) -> anyhow::Result<()>;
}
