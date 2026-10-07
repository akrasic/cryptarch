//! The database-engine abstraction — the load-bearing boundary of Cryptarch.
//!
//! Every target server (Postgres now, MySQL/MariaDB next) is one implementation
//! of [`DbEngine`]. Everything above this trait — quota checks, ownership, the
//! web UI, the audit log — is engine-agnostic. Getting this boundary clean in
//! v0.1 is what makes adding MySQL an afternoon rather than a rewrite.

use anyhow::Context;
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

/// How much attention a maintenance finding wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Checked, nothing wrong. Reported anyway — "we looked and it is fine" is
    /// a different statement from silence, and only one of them is evidence.
    Ok,
    /// Not broken yet, and it will not fix itself.
    Watch,
    /// Acting late here means downtime or data loss.
    Urgent,
}

/// One thing an engine checked about itself.
///
/// # Why this is a bag of strings and not a struct of metrics
///
/// The engine trait is the boundary that keeps MySQL from being a rewrite, and
/// the interesting failure modes are not shared. Transaction-ID wraparound is a
/// Postgres concept with no MySQL equivalent; InnoDB has its own list. A trait
/// method called `wraparound()` would push Postgres vocabulary above the
/// boundary and make the MySQL implementation lie or return zero.
///
/// So each engine decides WHAT it checks and what counts as urgent, and reports
/// findings in a shape the UI can render without knowing which engine produced
/// them. The cost is that the panel cannot graph these; the benefit is that the
/// panel is not a Postgres panel.
#[derive(Debug, Clone)]
pub struct MaintenanceFinding {
    pub severity: Severity,
    /// What was checked, e.g. "Transaction ID headroom".
    pub title: String,
    /// The finding in one line, with the numbers that matter.
    pub summary: String,
    /// What it means and what to do, in an operator's terms rather than the
    /// database's. A panel that only reports numbers has moved the work rather
    /// than done it.
    pub advice: String,
    /// The measurements behind the finding, for export to Prometheus
    /// (CRYPTARCH-98).
    ///
    /// The prose above is what the panel shows; these are what a time series
    /// needs. Splitting them is the point: the panel answers "what is wrong
    /// now", and a graph answers "since when", and neither is much use spelled
    /// as the other.
    ///
    /// Names are `&'static str` so a metric name cannot be built at runtime —
    /// the same guarantee `JobLog::table` relies on, and here it also means an
    /// engine cannot accidentally emit a metric name containing a tenant's
    /// database name. The ENGINE names them, so the trait stays agnostic:
    /// MySQL will emit a different set through the same shape, and the
    /// exporter publishes whatever it is handed.
    pub metrics: Vec<(&'static str, f64)>,
}

/// What one server said about its own health.
#[derive(Debug, Clone)]
pub struct MaintenanceReport {
    pub findings: Vec<MaintenanceFinding>,
}

impl MaintenanceReport {
    /// The worst severity present, for badging the server without reading it.
    pub fn worst(&self) -> Severity {
        self.findings.iter().map(|f| f.severity).max().unwrap_or(Severity::Ok)
    }
}

/// A role the panel administers, and whether it can log in.
///
/// The unit of the CRYPTARCH-78 Tier B report. Deliberately just these two
/// facts: the server can say *what* the state is, and can never say *why* it
/// is that way. Attribution is decided from what Cryptarch recorded before it
/// acted — see [`crate::repair::classify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleLogin {
    pub role_name: String,
    pub can_login: bool,
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

/// What an engine can tell us about a database at dump time.
///
/// Deliberately the manifest's own types: the survey exists to fill a manifest,
/// and a second near-identical shape here would only invite the two to drift.
pub struct Survey {
    pub server_version: String,
    pub owner: String,
    pub properties: crate::manifest::DbProperties,
    pub extensions: Vec<crate::manifest::Extension>,
    pub hazards: crate::manifest::Hazards,
}

/// A running dump process, streaming one database's contents to the caller.
///
/// The engine owns *producing* the bytes (which tool, which flags — `pg_dump`
/// here, `mysqldump` later); the caller owns what happens to them (sealing,
/// checksumming, where they land). That split is what keeps the backup layer
/// engine-agnostic: `backup.rs` never learns a dump flag.
pub struct DumpStream {
    child: tokio::process::Child,
    stdout: Option<tokio::process::ChildStdout>,
    /// Drained concurrently by a task — a dump tool that fills the stderr pipe
    /// while nobody reads it deadlocks against a caller waiting on stdout.
    stderr: tokio::task::JoinHandle<String>,
    /// What was run, for the job log. Password-free by construction.
    pub command: String,
}

impl DumpStream {
    /// Wrap a spawned child whose stdout and stderr are both piped.
    pub fn new(child: tokio::process::Child) -> anyhow::Result<Self> {
        Self::labelled(child, String::new())
    }

    /// As [`DumpStream::new`], recording the command line for the job log.
    pub fn labelled(mut child: tokio::process::Child, command: String) -> anyhow::Result<Self> {
        let stdout = child.stdout.take().context("dump process has no stdout pipe")?;
        let mut err = child.stderr.take().context("dump process has no stderr pipe")?;
        let stderr = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = String::new();
            let _ = err.read_to_string(&mut buf).await;
            buf
        });
        Ok(Self { child, stdout: Some(stdout), stderr, command })
    }

    /// Take the byte stream. Callable once; the caller reads it to EOF before
    /// calling [`DumpStream::finish`].
    pub fn take_stdout(&mut self) -> anyhow::Result<tokio::process::ChildStdout> {
        self.stdout.take().context("dump stream already taken")
    }

    /// Wait for the dump tool and turn a non-zero exit into an error carrying
    /// its stderr. Load-bearing: a dump that fails partway still produces a
    /// plausible-looking prefix of bytes, so the caller must not treat "the
    /// stream ended" as "the backup is complete" — only this does.
    ///
    /// Returns the tool's stderr on SUCCESS too (CRYPTARCH-66). A dump can
    /// succeed while warning about something that matters; discarding those
    /// warnings because the exit code was zero is how a problem stays invisible
    /// until a restore.
    pub async fn finish(mut self) -> anyhow::Result<String> {
        let status = self.child.wait().await.context("waiting for dump process")?;
        let stderr = self.stderr.await.unwrap_or_default();
        if !status.success() {
            let detail = stderr.trim();
            anyhow::bail!(
                "dump failed ({status}){}{}",
                if detail.is_empty() { "" } else { ": " },
                detail
            );
        }
        Ok(stderr)
    }

    /// The command line that produced this stream, with no password in it —
    /// the password travels in the environment precisely so it is absent here,
    /// which makes this safe to record in a job log.
    pub fn describe(cmd: &tokio::process::Command) -> String {
        let c = cmd.as_std();
        std::iter::once(c.get_program())
            .chain(c.get_args())
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    }
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
    async fn enable_login(&self, name: &str) -> anyhow::Result<()> {
        self.bound("enable_login", self.inner.enable_login(name)).await
    }
    /// Bounded, and forwarded for the same reason `survey` is: a missing
    /// override here would be a catalog read that hangs instead of failing,
    /// inside a security report.
    async fn login_states(&self, exclude: &[&str]) -> anyhow::Result<Vec<RoleLogin>> {
        self.bound("login_states", self.inner.login_states(exclude)).await
    }
    async fn database_exists(&self, name: &str) -> anyhow::Result<bool> {
        self.bound("database_exists", self.inner.database_exists(name)).await
    }
    async fn claim_repair_attempt(&self, marker: &str, comment: &str) -> anyhow::Result<bool> {
        self.bound("claim_repair_attempt", self.inner.claim_repair_attempt(marker, comment))
            .await
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
    /// Forwarded, and bounded like every other catalog read. A maintenance
    /// report is exactly the thing you want from a server that is struggling,
    /// which is also when it is most likely to answer slowly — so it must time
    /// out rather than hold the admin page open.
    async fn maintenance(&self) -> anyhow::Result<MaintenanceReport> {
        self.bound("maintenance", self.inner.maintenance()).await
    }
    async fn ping(&self) -> anyhow::Result<()> {
        self.bound("ping", self.inner.ping()).await
    }
    /// Bounded like any other catalog read. Forwarding this is load-bearing:
    /// every production engine is wrapped in this decorator, so a missing
    /// override here means the trait's default fires and every backup records
    /// its contents as unknown.
    async fn survey(&self, name: &str) -> anyhow::Result<Survey> {
        self.bound("survey", self.inner.survey(name)).await
    }
    /// Only *starting* the dump is bounded. The transfer that follows is
    /// legitimately slow — a timeout around it would kill healthy backups of
    /// big databases, which is the opposite of the point.
    async fn dump_stream(&self, name: &str) -> anyhow::Result<DumpStream> {
        self.bound("dump_stream", self.inner.dump_stream(name)).await
    }
    /// Forwarded for the same reason as `dump_stream`, and the same warning
    /// applies: every production engine is wrapped in this decorator, so a
    /// missing override here means the trait's default fires and restores
    /// report "this engine does not support restores" on an engine that does.
    /// Only STARTING is bounded; the transfer that follows is legitimately slow.
    async fn restore_stream(&self, name: &str) -> anyhow::Result<RestoreSink> {
        self.bound("restore_stream", self.inner.restore_stream(name)).await
    }
}

/// The other direction: a restore tool waiting to be fed a dump on stdin
/// (CRYPTARCH-69).
///
/// The mirror of [`DumpStream`], and the same trap applies in reverse. A
/// restore tool that dies partway leaves the caller's writes failing with a
/// broken pipe, which is indistinguishable from a normal end of input — so
/// "we finished writing the bytes" is NOT "the restore worked". Only
/// [`RestoreSink::finish`] can say that.
pub struct RestoreSink {
    child: tokio::process::Child,
    stdin: Option<tokio::process::ChildStdin>,
    /// Drained concurrently, for the same reason the dump drains stderr: a
    /// tool that fills the pipe while nobody reads it deadlocks.
    stderr: tokio::task::JoinHandle<String>,
    /// What was run, for the job log. Password-free by construction.
    pub command: String,
    /// An engine-supplied supervisor for the running restore, if it has one.
    watchdog: Option<RestoreWatchdog>,
}

/// A task supervising a running restore, plus what it concluded if it had to
/// intervene (CRYPTARCH-128). Aborted when dropped, so it never outlives the
/// restore it watches.
pub struct RestoreWatchdog {
    handle: tokio::task::JoinHandle<()>,
    verdict: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

impl RestoreWatchdog {
    pub fn new(
        handle: tokio::task::JoinHandle<()>,
        verdict: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    ) -> Self {
        Self { handle, verdict }
    }
}

impl Drop for RestoreWatchdog {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl RestoreSink {
    pub fn new(mut child: tokio::process::Child, command: String) -> anyhow::Result<Self> {
        let stdin = child.stdin.take().context("restore process has no stdin pipe")?;
        let mut err = child.stderr.take().context("restore process has no stderr pipe")?;
        let stderr = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = String::new();
            let _ = err.read_to_string(&mut buf).await;
            buf
        });
        Ok(Self { child, stdin: Some(stdin), stderr, command, watchdog: None })
    }

    /// Attach a supervisor. Its verdict, if it intervened, leads the error
    /// [`RestoreSink::finish`] returns — the tool's own stderr only says it was
    /// cancelled, not why.
    pub fn with_watchdog(mut self, watchdog: RestoreWatchdog) -> Self {
        self.watchdog = Some(watchdog);
        self
    }

    /// Take the pipe to write the dump into. Callable once; the caller drops it
    /// to signal EOF before calling [`RestoreSink::finish`].
    pub fn take_stdin(&mut self) -> anyhow::Result<tokio::process::ChildStdin> {
        self.stdin.take().context("restore sink already taken")
    }

    /// Wait for the restore tool and turn a non-zero exit into an error
    /// carrying its stderr. Returns stderr on success too: a restore can
    /// succeed while warning about something worth reading.
    pub async fn finish(mut self) -> anyhow::Result<String> {
        // Drop our end first, or the tool waits forever for input that is
        // already all delivered.
        self.stdin.take();
        let status = self.child.wait().await.context("waiting for the restore tool")?;
        let complaints = self.stderr.await.unwrap_or_default();
        // Taken, then dropped at the end of this statement — which aborts it.
        let verdict = self
            .watchdog
            .take()
            .and_then(|w| w.verdict.lock().ok().and_then(|v| v.clone()));
        anyhow::ensure!(
            status.success(),
            "{}restore failed ({status}){}{}",
            verdict.map(|v| format!("{v} — ")).unwrap_or_default(),
            if complaints.trim().is_empty() { "" } else { ": " },
            complaints.trim()
        );
        Ok(complaints)
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

    /// Login state of every role the panel administers on this server, for the
    /// CRYPTARCH-78 Tier B report. `exclude` is the set of roles Cryptarch
    /// created for its own purposes ([`crate::repair::PANEL_OWNED_ROLES`]),
    /// which the panel also administers and which have no `databases` row —
    /// without excluding them, each would report itself forever.
    ///
    /// A SET, not one name: there are two already.
    ///
    /// Read-only. Reports state; never changes it.
    async fn login_states(&self, exclude: &[&str]) -> anyhow::Result<Vec<RoleLogin>>;

    /// Whether a database of this name exists on the server.
    ///
    /// The repair needs this because re-enabling login for a role whose
    /// database is gone is not a repair — it hands out a credential for
    /// nothing. Asking the server is the point: the metadata row is exactly
    /// what cannot be trusted here.
    async fn database_exists(&self, name: &str) -> anyhow::Result<bool>;

    /// Atomically claim this server's single repair attempt.
    ///
    /// Returns `true` if the claim was won (the marker did not exist and now
    /// does), `false` if it had already been spent. `CREATE ROLE` fails on a
    /// duplicate name, which makes this atomic without a read-then-write race.
    ///
    /// The marker records that the attempt was **spent**, not that the repair
    /// **succeeded** — see [`crate::repair`] for why that distinction is the
    /// whole design.
    async fn claim_repair_attempt(&self, marker: &str, comment: &str) -> anyhow::Result<bool>;

    /// Re-enable login for the database's role.
    ///
    /// One-directional on purpose (CRYPTARCH-78). This replaced a
    /// `set_login(name, enabled: bool)` when database suspend/resume was
    /// removed, and the missing `false` is the point: nothing in Cryptarch may
    /// write `NOLOGIN` any more, so the API cannot express it. The Tier B
    /// report on the admin server page reads a disabled role as *somebody
    /// disabled this outside Cryptarch* — an attribution that is only sound
    /// while that remains true. A boolean here would let a future caller
    /// falsify it by accident; a missing variant cannot.
    ///
    /// The one legitimate caller is the CRYPTARCH-78 upgrade repair, which
    /// re-enables roles left `NOLOGIN` by the removed suspend feature.
    async fn enable_login(&self, name: &str) -> anyhow::Result<()>;

    /// Regenerate the role's password, returning the new connection string once.
    async fn rotate_password(&self, name: &str, password: &str)
        -> anyhow::Result<ConnString>;

    /// Read live stats for a provisioned database.
    async fn stats(&self, name: &str) -> anyhow::Result<DbStats>;

    /// Whole-server snapshot for the admin dashboard.
    async fn server_overview(&self) -> anyhow::Result<ServerOverview>;

    /// What the engine says about its own operational health (CRYPTARCH-97).
    ///
    /// The failure modes worth reporting are the ones that arrive without
    /// symptoms and then take the server down at once — for Postgres, mostly
    /// things that stop vacuum reclaiming. What those are is the ENGINE's
    /// business; see [`MaintenanceFinding`] for why this returns prose rather
    /// than metrics.
    ///
    /// Defaults to reporting nothing so a new engine is honestly silent rather
    /// than falsely healthy: an empty report renders as "this engine does not
    /// report maintenance", not as a clean bill of health.
    async fn maintenance(&self) -> anyhow::Result<MaintenanceReport> {
        Ok(MaintenanceReport { findings: Vec::new() })
    }

    /// Cheapest possible liveness probe over the admin connection — the
    /// health loop (CRYPTARCH-43) runs this every interval, so it must cost
    /// one round-trip, not a catalog scan.
    async fn ping(&self) -> anyhow::Result<()>;

    /// Survey what a database contains, for the backup manifest
    /// (CRYPTARCH-67).
    ///
    /// Runs at DUMP time, while the source is guaranteed to exist. Errors are
    /// the caller's to record as "unknown" — an engine that cannot survey must
    /// not let the result be mistaken for "nothing found".
    async fn survey(&self, _name: &str) -> anyhow::Result<Survey> {
        anyhow::bail!("this engine cannot describe database contents yet")
    }

    /// Start a logical dump of `name`, streaming to the caller (CRYPTARCH-56).
    ///
    /// Defaults to unsupported so an engine without a dump path (MySQL, test
    /// doubles) says so plainly instead of silently producing nothing.
    async fn dump_stream(&self, _name: &str) -> anyhow::Result<DumpStream> {
        anyhow::bail!("this engine does not support backups yet")
    }

    /// Start a restore INTO `name`, returning a sink to write the dump to
    /// (CRYPTARCH-69).
    ///
    /// Implementations must make this all-or-nothing. The whole safety story of
    /// restore is that a failure leaves the database exactly as it was, so a
    /// half-applied restore is not an acceptable outcome to report.
    ///
    /// Defaults to unsupported, like `dump_stream`: an engine with no restore
    /// path says so rather than appearing to succeed at nothing.
    async fn restore_stream(&self, _name: &str) -> anyhow::Result<RestoreSink> {
        anyhow::bail!("this engine does not support restores yet")
    }
}
