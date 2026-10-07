//! Restoring a database from one of its own backups (CRYPTARCH-69).
//!
//! Three steps, deliberately: pick a backup, check it opens, load it back.
//!
//! # Why this is smaller than it looks
//!
//! An earlier design restored alongside the live database under a generated
//! name, or renamed the original aside so a failure could be rolled back by
//! swapping it in again. Both exist to answer one question — *what if the
//! restore fails halfway?* — and `pg_restore --single-transaction` already
//! answers it. Either the whole dump applies or the database is exactly what it
//! was. There is no aside copy, no second name to fit inside the 63-character
//! limit, no window where the data lives only in the backup, and no `IS_TEMPLATE`
//! or active-connection problem, because the database is never dropped.
//!
//! # What the `databases` row does during a restore
//!
//! Nothing. It stays `active`.
//!
//! Marking it `restoring` would mean a status that has to be cleared again,
//! and CRYPTARCH-80 is the story of what happens when a transient status gets
//! stranded — a live database sitting in `deleting`, invisible to the backup
//! schedule, needing a sweep to rescue it. The restore's own row carries the
//! progress instead. A crash mid-restore therefore leaves a stale `running`
//! restore row and a database that still works, rather than a working database
//! nobody can see.

use anyhow::Context;
use uuid::Uuid;

use crate::backup;

#[derive(Debug, thiserror::Error)]
pub enum EnqueueError {
    #[error("backups are not configured")]
    Disabled,
    #[error("no such backup for this database")]
    NotFound,
    #[error("a restore of this database is already running")]
    AlreadyRunning,
    /// The database is not active — mid-delete, say. Checked under the job
    /// lock a delete also takes (S4f audit P1).
    #[error("this database is not active — it may be being deleted")]
    NotActive,
    /// Shutdown has begun; the job was never claimed (CRYPTARCH-128).
    #[error("Cryptarch is shutting down — try again once it is back")]
    ShuttingDown,
    /// A BACKUP holds this database (CRYPTARCH-114). Its own variant for the
    /// same reason backup has RestoreRunning: "wait for your restore" and "a
    /// dump of this database is in flight and a restore would fight it for
    /// table locks" are different facts.
    #[error("a backup of this database is running — wait for it to finish, then restore")]
    BackupRunning,
    /// The blob was sealed with a different at-rest key than the one loaded
    /// (CRYPTARCH-107). Its own variant so the UI can say which, rather than
    /// folding into the generic decrypt failure.
    #[error("this backup was sealed with a different encryption key \
             (blob: {sealed_under}, currently loaded: {loaded}) — restoring it needs \
             the key it was made with")]
    WrongKey { sealed_under: String, loaded: String },
    #[error("internal error")]
    Internal,
}

/// How a finished restore turned out.
///
/// Two variants and no `is_ok()`, for the reason CRYPTARCH-85 established: a
/// bool cannot carry the difference between "the data is back" and "nothing
/// happened", and those are the only two states a single-transaction restore
/// can end in.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// The dump applied in full. The database now holds the backup's contents.
    Restored,
    /// It did not apply. The database is unchanged — that is the guarantee, not
    /// a hope, and it comes from the restore running as one transaction.
    Failed { error: String },
}

/// The ordered stages of a restore, as the page shows them.
///
/// `restores.stage` was provisioned by migration 0015 for exactly this and then
/// went unused when the design collapsed to replace-in-place. The column stores
/// [`Stage::key`]; the row's `status` says how to read it — while `running` the
/// stored stage is IN FLIGHT, and on `failed` it is the stage that failed.
///
/// The order is the order they execute in, and the page derives every step's
/// state from position alone. That is why it is one list rather than a flag per
/// step: two sources for "where are we" is how a progress display starts
/// disagreeing with itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Locating,
    Checking,
    Connecting,
    Loading,
    Finishing,
}

impl Stage {
    /// Every stage in execution order.
    pub const ALL: [Stage; 5] =
        [Stage::Locating, Stage::Checking, Stage::Connecting, Stage::Loading, Stage::Finishing];

    /// Stored in `restores.stage`. Also the label `JobLog` writes per line, so
    /// the log and the step list cannot drift apart.
    pub fn key(self) -> &'static str {
        match self {
            Stage::Locating => "locating",
            Stage::Checking => "checking",
            Stage::Connecting => "connecting",
            Stage::Loading => "loading",
            Stage::Finishing => "finishing",
        }
    }

    pub fn from_key(key: &str) -> Option<Stage> {
        Stage::ALL.into_iter().find(|s| s.key() == key)
    }

    /// What this step is called in the UI.
    pub fn title(self) -> &'static str {
        match self {
            Stage::Locating => "Find the backup",
            Stage::Checking => "Check it opens",
            Stage::Connecting => "Connect as the owner",
            Stage::Loading => "Load it in one transaction",
            Stage::Finishing => "Confirm it committed",
        }
    }

    /// Why the step exists, in the reader's terms rather than the code's. Each
    /// one names the consequence of the step, because that is what tells an
    /// operator whether they should be worried yet.
    pub fn blurb(self) -> &'static str {
        match self {
            Stage::Locating => {
                "Locates the sealed file on the backup disk. A backup whose path was never \
                 recorded is still found, by the id in its filename."
            }
            Stage::Checking => {
                "Decrypts and reads the whole backup back before the database is touched at \
                 all. A corrupt backup is caught here, while nothing has happened yet."
            }
            Stage::Connecting => {
                "Opens the restore as the database's own owner, so what comes back is owned \
                 by the same role that owned it before."
            }
            Stage::Loading => {
                "Applies the dump inside a single transaction. Until it commits, the database \
                 still holds exactly what it held before this restore started."
            }
            Stage::Finishing => {
                "Waits for the tool to exit and checks how. The data stream ending is not \
                 success — a crashed restore closes the pipe the same way a finished one does."
            }
        }
    }
}

struct Job {
    id: Uuid,
    backup_id: Uuid,
    /// The database claimed, by identity: rechecked before connecting, since
    /// the runner reaches the server by NAME (S4f audit P1).
    database_id: Uuid,
    db_name: String,
    server_id: Uuid,
    /// Where the blob was recorded, if it ever was. `None` is not fatal — see
    /// `backup::locate_blob`, which finds it by the id in the filename.
    path: Option<String>,
    actor: String,
}

/// Start a restore of `db_name` from `backup_id` and return its id immediately.
///
/// The INSERT is the lock: `idx_restores_one_running_per_database` is a partial
/// unique index on running rows, so two clicks race inside Postgres rather than
/// in a check-then-insert window here — the same primitive the backup runner
/// uses.
///
/// That index keys on `database_id`, not on the name (CRYPTARCH-100). Keying it
/// on `target_name` meant one wedged `running` row held the lock against
/// whoever NEXT took that name, for as long as the row survived — which is
/// forever, since nothing deletes restore rows.
pub async fn enqueue(
    state: &crate::web::AppState,
    actor: &str,
    database_id: Uuid,
    db_name: &str,
    backup_id: Uuid,
) -> Result<Uuid, EnqueueError> {
    if state.backup_dir.is_none() {
        return Err(EnqueueError::Disabled);
    }
    // Registered before anything is claimed, and refused once shutdown has
    // begun (CRYPTARCH-128); see `JobTracker::begin`.
    let guard = state.jobs.begin().ok_or(EnqueueError::ShuttingDown)?;

    // Scoped to the database's IDENTITY, not its name (CRYPTARCH-86). A backup
    // whose database was deleted belongs to the operator, and a tenant who
    // later took that name must not be able to restore a stranger's data into
    // their database by passing its id.
    let row = sqlx::query_as::<_, (Option<String>, Option<Uuid>, String, Option<String>)>(
        "SELECT path, server_id, status, key_fingerprint FROM backups \
         WHERE id = $1 AND database_id = $2",
    )
    .bind(backup_id)
    .bind(database_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("looking up backup {backup_id} to restore: {e}");
        EnqueueError::Internal
    })?
    .ok_or(EnqueueError::NotFound)?;

    let (path, server_id, status, sealed_under) = row;
    // Only a backup that finished. A `running` row has no complete blob, and a
    // `failed` one is kept as evidence rather than as something to restore.
    if status != "ok" {
        return Err(EnqueueError::NotFound);
    }

    // Refuse before touching the database, and say WHY (CRYPTARCH-107).
    //
    // Without this the restore proceeds, decrypts nothing, and reports the
    // generic AEAD failure — "tampered, reordered, truncated, spliced from
    // another backup, or wrong key" — which is five possibilities the operator
    // cannot distinguish at the moment they most need to.
    //
    // NULL means the blob predates this column, which is NOT the same as a
    // mismatch and must not be reported as one; those restore as before and
    // fail (or succeed) on the bytes themselves.
    if let Some(sealed_under) = sealed_under.as_deref()
        && sealed_under != state.crypto.key_fingerprint()
    {
        tracing::error!(
            "refusing to restore backup {backup_id}: sealed under key {sealed_under}, \
             loaded key is {}",
            state.crypto.key_fingerprint()
        );
        return Err(EnqueueError::WrongKey {
            sealed_under: sealed_under.to_string(),
            loaded: state.crypto.key_fingerprint().to_string(),
        });
    }
    let server_id = server_id.ok_or(EnqueueError::NotFound)?;

    // Symmetric with `backup::claim` (CRYPTARCH-114) — same advisory lock, same
    // question asked from the other side. It has to be symmetric or the mutual
    // exclusion only holds in one direction, which is worse than none: it would
    // read as protected while the ordering that actually happens is unguarded.
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("opening the restore claim transaction for '{db_name}': {e}");
        EnqueueError::Internal
    })?;
    backup::lock_db_jobs(&mut tx, db_name).await.map_err(|e| {
        tracing::error!("taking the job lock for '{db_name}': {e}");
        EnqueueError::Internal
    })?;
    match backup::other_job_running(&mut tx, db_name, backup::JobKind::Restore).await {
        Ok(true) => return Err(EnqueueError::BackupRunning),
        Ok(false) => {}
        Err(e) => {
            tracing::error!("checking for a running backup of '{db_name}': {e}");
            return Err(EnqueueError::Internal);
        }
    }
    // Under the lock `web::delete_request` takes before marking a database
    // `deleting`: either the delete sees this restore running and refuses, or
    // this sees the database no longer active and refuses. Never both through.
    let active: Option<bool> = sqlx::query_scalar(
        "SELECT status = 'active' FROM databases WHERE id = $1 AND name = $2",
    )
    .bind(database_id)
    .bind(db_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("checking '{db_name}' is active before restoring: {e}");
        EnqueueError::Internal
    })?;
    if active != Some(true) {
        return Err(EnqueueError::NotActive);
    }

    let id: Uuid = match sqlx::query_scalar(
        // Starts at the first step: the column's default ('checking') would
        // show "Find the backup" done before it has run.
        "INSERT INTO restores (backup_id, source_name, target_name, database_id, mode, requested_by, stage) \
         VALUES ($1, $2, $2, $3, 'replace', $4, 'locating') RETURNING id",
    )
    .bind(backup_id)
    .bind(db_name)
    .bind(database_id)
    .bind(actor)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(EnqueueError::AlreadyRunning);
        }
        Err(e) => {
            tracing::error!("claiming restore of '{db_name}': {e}");
            return Err(EnqueueError::Internal);
        }
    };
    tx.commit().await.map_err(|e| {
        tracing::error!("committing the restore claim for '{db_name}': {e}");
        EnqueueError::Internal
    })?;

    crate::provision::audit(
        &state.db,
        actor,
        "restore_start",
        Some(db_name),
        Some(&format!("from backup {backup_id}")),
    )
    .await;

    let job = Job {
        id,
        backup_id,
        database_id,
        db_name: db_name.to_string(),
        server_id,
        path,
        actor: actor.to_string(),
    };
    let state = state.clone();
    tokio::spawn(async move {
        let _guard = guard;
        run(state, job).await
    });
    Ok(id)
}

async fn run(state: crate::web::AppState, job: Job) -> Outcome {
    // Same log machinery the backup runner uses, pointed at `restores` — the
    // table name is `&'static str` by construction, which is what makes it safe
    // to interpolate (see `JobLog`).
    let log = backup::JobLog::new(state.db.clone(), "restores", job.id);
    match attempt(&state, &job, &log).await {
        Ok(warnings) => {
            let warnings = redact_stderr(&warnings);
            let detail = if warnings.trim().is_empty() {
                None
            } else {
                Some(warnings.trim().to_string())
            };
            settle(&state, &job, "ok", None).await;
            crate::provision::audit(
                &state.db,
                &job.actor,
                "restore_ok",
                Some(&job.db_name),
                detail.as_deref(),
            )
            .await;
            Outcome::Restored
        }
        Err(e) => {
            // Stored in the job row and the audit log, both readable by
            // admins: no row data from pg_restore's stderr (S4f audit P2).
            let detail = redact_stderr(&format!("{e:#}"));
            tracing::error!("restore of '{}' failed: {detail}", job.db_name);
            settle(&state, &job, "failed", Some(&detail)).await;
            crate::provision::audit(
                &state.db,
                &job.actor,
                "restore_failed",
                Some(&job.db_name),
                Some(&detail),
            )
            .await;
            Outcome::Failed { error: detail }
        }
    }
}

/// Is `name` still the active database `database_id` — the one a restore was
/// claimed for? Names are freed on delete and reused; identity is not.
pub async fn target_still_matches(db: &sqlx::PgPool, database_id: Uuid, name: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM databases WHERE id = $1 AND name = $2 AND status = 'active')",
    )
    .bind(database_id)
    .bind(name)
    .fetch_one(db)
    .await
    .unwrap_or_else(|e| {
        tracing::error!("rechecking restore target '{name}': {e}");
        false
    })
}

/// pg_restore's stderr without the lines that quote ROW DATA: a failing COPY
/// names the line it choked on, and constraint errors print the offending
/// row and key. What remains says what went wrong without repeating the
/// tenant's data into a job row and an audit log an admin reads.
pub fn redact_stderr(text: &str) -> String {
    text.lines()
        .map(|line| {
            let t = line.trim_start();
            let quotes_data = (t.starts_with("CONTEXT:") && t.contains("COPY "))
                || t.contains("Failing row contains")
                || (t.starts_with("DETAIL:") && t.contains("Key ("))
                || (t.contains("COPY ") && t.contains(", line ") && t.contains('"'));
            if quotes_data { "[row data omitted]" } else { line }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Move the row into `stage`, so the page can show which step is in flight.
///
/// Best effort: a restore that is actually running must not be abandoned
/// because its progress display could not be updated. A failure here costs the
/// page one stale step, and the log line still records what happened.
async fn enter(state: &crate::web::AppState, job: &Job, stage: Stage) {
    if let Err(e) = sqlx::query("UPDATE restores SET stage = $2 WHERE id = $1")
        .bind(job.id)
        .bind(stage.key())
        .execute(&state.db)
        .await
    {
        tracing::warn!("restore {}: could not record stage {}: {e}", job.id, stage.key());
    }
}

/// The whole restore. Returns the tool's warnings on success.
///
/// Each stage announces itself before doing its work and records what it found
/// afterwards, so the page shows a step in flight rather than a spinner, and a
/// failure names the step it failed at. The stage names are `Stage::key`, which
/// is also what the log lines are tagged with — one vocabulary, so the step list
/// and the log cannot describe different restores.
async fn attempt(
    state: &crate::web::AppState,
    job: &Job,
    log: &backup::JobLog,
) -> anyhow::Result<String> {
    let root = state.backup_dir.as_ref().context("backups are not configured")?;

    enter(state, job, Stage::Locating).await;
    let blob = backup::locate_blob(root, &job.db_name, job.backup_id, job.path.as_deref())
        .await?
        .context("the backup's file is not on the backup disk")?;
    let sealed_size = tokio::fs::metadata(&blob).await.map(|m| m.len()).unwrap_or(0);
    log.step(
        Stage::Locating.key(),
        format!(
            "{} ({}){}",
            blob.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
            crate::web::human_bytes(sealed_size as i64),
            // Worth saying out loud: this is the CRYPTARCH-85 recovery path,
            // and an operator seeing it should know the row was incomplete.
            if job.path.is_none() { " — found by id; its path was never recorded" } else { "" }
        ),
    )
    .await;

    // Check it opens BEFORE touching the database. This is the same read-back
    // that verification does when the backup is taken, and it is cheap next to
    // the restore itself. Without it the first thing a corrupt blob does is
    // begin a transaction against live data — which would roll back safely, but
    // "we tried and it failed" is a worse answer than "we checked first".
    enter(state, job, Stage::Checking).await;
    backup::verify_blob(&state.crypto, job.backup_id, &blob)
        .await
        .context("the backup could not be read back before restoring")?;
    log.step(Stage::Checking.key(), "decrypted and read back in full; the backup is intact").await;

    enter(state, job, Stage::Connecting).await;
    // The server is reached by NAME. If this database was deleted and the
    // name taken since the claim, the name is someone else's now (S4f audit
    // P1) — delete refuses while this job runs, and this is the last look.
    if !target_still_matches(&state.db, job.database_id, &job.db_name).await {
        anyhow::bail!(
            "'{}' is no longer the database this restore was started for — it was deleted or \
             replaced; nothing was restored",
            job.db_name
        );
    }
    let engine = state
        .servers
        .get(job.server_id)
        .context("managed server is not registered (inactive or unreachable)")?;

    let mut sink = engine
        .restore_stream(&job.db_name)
        .await
        .context("starting the restore")?;
    let stdin = sink.take_stdin()?;
    log.step(
        Stage::Connecting.key(),
        format!("restoring into '{}' as its owner, in a single transaction", job.db_name),
    )
    .await;

    // Decrypting into the tool is what actually performs the restore. A failure
    // here is reported by `finish` below, not by this call: a restore process
    // that dies makes our writes fail with a broken pipe, which is
    // indistinguishable from having finished normally.
    enter(state, job, Stage::Loading).await;
    let written = backup::open_stream(&state.crypto, job.backup_id, &blob, stdin).await;
    log.step(
        Stage::Loading.key(),
        format!("streamed {} of decrypted dump into the tool", crate::web::human_bytes(sealed_size as i64)),
    )
    .await;

    // NOT a success signal on its own — see the stage's blurb. The exit status
    // is the only thing that distinguishes a committed restore from a crashed
    // one, and it is checked here before `written` is even consulted.
    enter(state, job, Stage::Finishing).await;
    let warnings = sink.finish().await?;
    written.context("the sealed backup could not be decrypted from disk")?;
    log.step(
        Stage::Finishing.key(),
        if warnings.trim().is_empty() {
            "the tool exited cleanly; the transaction committed".to_string()
        } else {
            // Flattened: a log line is one step, and the tool's notes arrive
            // multi-line. Left as-is they would be parsed back as steps with
            // unrecognised tags and silently dropped from the step list.
            format!(
                "the transaction committed, with notes from the tool: {}",
                warnings.split_whitespace().collect::<Vec<_>>().join(" ")
            )
        },
    )
    .await;
    Ok(warnings)
}

async fn settle(state: &crate::web::AppState, job: &Job, status: &str, error: Option<&str>) {
    match sqlx::query(
        "UPDATE restores SET status = $2, finished_at = now(), error = $3 \
         WHERE id = $1 AND status = 'running'",
    )
    .bind(job.id)
    .bind(status)
    .bind(error)
    .execute(&state.db)
    .await
    {
        // Zero rows means the row was no longer `running`: the abandoned sweep
        // reclaimed it while this job was still going (CRYPTARCH-123). The job
        // page now says `failed` about a restore that may have succeeded, and
        // that disagreement must be visible somewhere.
        Ok(r) if r.rows_affected() == 0 => tracing::warn!(
            "restore {} finished as '{status}' after its row had already been swept — \
             the job page shows the sweep's verdict, not this outcome",
            job.id
        ),
        Ok(_) => {}
        // Same shape as CRYPTARCH-85: the restore itself already happened or
        // already did not, and this row is only the record of it. Logged rather
        // than swallowed silently, and the row stays `running` for a human to
        // notice rather than being quietly marked either way.
        Err(e) => tracing::error!("restore {} finished but its row did not update: {e}", job.id),
    }
}

/// One restore job, scoped to the database it targeted.
///
/// Takes `database_id` as well as the id on purpose: the caller has already
/// resolved that the signed-in user owns that database, and pairing the two
/// here means a restore id alone is not a capability. Guessing an id gets you
/// nothing unless it belongs to a database you already own.
///
/// Scoped to the database's IDENTITY, not its name (CRYPTARCH-100). Keying this
/// on `target_name` made the guarantee above false: names are freed on delete
/// and reused, so taking a freed name handed you the previous owner's restore
/// jobs — including a job page carrying their blob filenames and `pg_restore`
/// stderr. `enqueue` below already scoped its backup lookup this way and said
/// why; this is the same fix on the read side.
pub async fn get(db: &sqlx::PgPool, database_id: Uuid, id: Uuid) -> Option<RestoreRow> {
    sqlx::query_as::<_, RestoreRow>(
        "SELECT id, created_at, finished_at, status, error, requested_by, stage, log \
         FROM restores WHERE id = $1 AND database_id = $2",
    )
    .bind(id)
    .bind(database_id)
    .fetch_optional(db)
    .await
    .unwrap_or_else(|e| {
        tracing::error!("reading restore {id}: {e}");
        None
    })
}

/// The restores of one database, newest first, for its page.
///
/// Keyed on identity rather than name for the reason spelled out on [`get`]
/// (CRYPTARCH-100). A deleted database's restores are not transferred to the
/// next holder of its name — they stop matching any tenant and become the
/// operator's, exactly as `backups.database_id` behaves.
pub async fn history(db: &sqlx::PgPool, database_id: Uuid) -> Vec<RestoreRow> {
    sqlx::query_as::<_, RestoreRow>(
        "SELECT id, created_at, finished_at, status, error, requested_by, stage, log \
         FROM restores WHERE database_id = $1 ORDER BY created_at DESC LIMIT 20",
    )
    .bind(database_id)
    .fetch_all(db)
    .await
    .unwrap_or_else(|e| {
        tracing::error!("reading restore history for database {database_id}: {e}");
        Vec::new()
    })
}

#[derive(sqlx::FromRow)]
pub struct RestoreRow {
    pub id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: String,
    pub error: Option<String>,
    pub requested_by: String,
    /// The stage stored by [`enter`]. Read through [`RestoreRow::step_state`],
    /// never on its own — it means "in flight" or "failed here" depending on
    /// `status`, and reading it without that context is how a finished restore
    /// ends up rendered as though it were stuck.
    pub stage: String,
    pub log: String,
}

/// How one step of a restore should be drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Done,
    Running,
    Failed,
    /// Never reached, because an earlier step failed. Distinct from `Pending`:
    /// "not started yet" and "will never start" look the same on a stalled page
    /// and mean opposite things.
    Skipped,
    Pending,
}

impl RestoreRow {
    pub fn is_running(&self) -> bool {
        self.status == "running"
    }

    /// The state of `stage` for this restore.
    ///
    /// Derived entirely from position relative to the stored stage, so the list
    /// cannot contradict itself. A finished-ok restore reports every step done
    /// regardless of where `stage` stopped — the row committed, so every step
    /// it needed did happen, and trusting the column over the outcome would
    /// show a successful restore with an unfinished-looking tail.
    pub fn step_state(&self, stage: Stage) -> StepState {
        if self.status == "ok" {
            return StepState::Done;
        }
        let Some(at) = Stage::from_key(&self.stage) else {
            // An unrecognised stage means a newer writer or a corrupt row.
            // Claiming "done" would be inventing progress; claiming "failed"
            // would invent a failure.
            return StepState::Pending;
        };
        let (here, now) = (
            Stage::ALL.iter().position(|s| *s == stage),
            Stage::ALL.iter().position(|s| *s == at),
        );
        match (here, now) {
            (Some(here), Some(now)) if here < now => StepState::Done,
            (Some(here), Some(now)) if here == now => {
                if self.status == "failed" {
                    StepState::Failed
                } else {
                    StepState::Running
                }
            }
            _ if self.status == "failed" => StepState::Skipped,
            _ => StepState::Pending,
        }
    }

    /// The log line this step recorded, as `(time, detail)`.
    ///
    /// `JobLog::step` writes `HH:MM:SSZ  <stage>  <detail>`, and the stage tag
    /// is `Stage::key`, so the log is keyed by the same vocabulary the step list
    /// uses rather than by line order.
    pub fn detail(&self, stage: Stage) -> Option<(String, String)> {
        // Last match wins: a step that reported twice should show what it ended
        // up saying, not what it said first.
        self.log.lines().rev().find_map(|line| {
            let (time, rest) = line.trim_start().split_once(char::is_whitespace)?;
            let rest = rest.trim_start();
            let tag_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            let (tag, detail) = rest.split_at(tag_end);
            (tag == stage.key()).then(|| (time.to_string(), detail.trim().to_string()))
        })
    }
}

/// Fail any restore left `running` by a previous process.
///
/// Runs at boot, like the backup sweep it mirrors. A restore's status is only
/// advanced by the task running it, so a restart mid-restore strands the row —
/// and because the per-target lock IS that row, the database could never be
/// restored again.
///
/// The database itself needs no repair: the restore either committed before the
/// crash or it did not, and Postgres decided that, not us. Which is also why the
/// message cannot say which — the commit can land a moment before the crash
/// that kept its row from being updated.
pub async fn sweep_stale(db: &sqlx::PgPool) -> anyhow::Result<u64> {
    let swept = sqlx::query(
        "UPDATE restores SET status = 'failed', finished_at = now(), \
         error = 'interrupted by a restart before its outcome was recorded — the restore is all-or-nothing, so the database is either fully restored or untouched; check its contents' \
         WHERE status = 'running'",
    )
    .execute(db)
    .await
    .context("sweeping stale restore jobs")?
    .rows_affected();
    if swept > 0 {
        tracing::warn!("marked {swept} interrupted restore job(s) failed");
    }
    Ok(swept)
}

/// How long a restore may be `running` before it is presumed dead.
///
/// The same 6h the backup runner uses, and for the same reason: long enough
/// that a genuinely large job is never killed by the clock, short enough that a
/// wedged row does not outlive anyone's patience.
const ABANDONED_AFTER: chrono::TimeDelta = chrono::TimeDelta::hours(6);

/// Fail any restore that has been `running` past [`ABANDONED_AFTER`], on every
/// scheduler pass (CRYPTARCH-113).
///
/// `sweep_stale` above only runs at boot, and that was the whole recovery path.
/// It is not enough, because the row can be stranded WITHOUT a restart:
///
/// * `enqueue` spawns the job and drops the handle, so a panic inside it is
///   swallowed with no `JoinHandle` to observe;
/// * `settle` only logs when its finishing UPDATE fails — deliberately, so the
///   row stays `running` "for a human to notice" — and nothing was doing the
///   noticing.
///
/// And the row IS the per-target lock, so either path means that database can
/// never be restored again until someone restarts the process. On a homelab box
/// that is months. This is the exact reasoning `backup::sweep_abandoned`
/// already carries; restore inherited the spawn-and-drop and not the fix.
pub async fn sweep_abandoned(db: &sqlx::PgPool) -> anyhow::Result<u64> {
    let swept = sqlx::query(
        "UPDATE restores SET status = 'failed', finished_at = now(), \
         error = 'abandoned — no outcome recorded within the maximum runtime; the restore may have completed, or may still be running' \
         WHERE status = 'running' AND created_at < now() - $1::interval",
    )
    .bind(ABANDONED_AFTER)
    .execute(db)
    .await
    .context("sweeping abandoned restore jobs")?
    .rows_affected();
    if swept > 0 {
        tracing::warn!("marked {swept} abandoned restore job(s) failed (no progress in 6h)");
    }
    Ok(swept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stderr_redaction_drops_the_lines_that_quote_row_data() {
        let raw = "pg_restore: error: COPY failed for table \"ledger\": ERROR:  new row violates check constraint \"c\"\n\
                   DETAIL:  Failing row contains (1, SSN 123-45-6789).\n\
                   CONTEXT:  COPY ledger, line 1: \"1\tSSN 123-45-6789 card 4111111111111111\"\n\
                   DETAIL:  Key (email)=(alice@example.com) already exists.\n\
                   pg_restore: warning: errors ignored on restore: 1";
        let out = redact_stderr(raw);
        for secret in ["123-45-6789", "4111111111111111", "alice@example.com"] {
            assert!(!out.contains(secret), "{secret} survived: {out}");
        }
        assert!(out.contains("violates check constraint"), "what went wrong stays: {out}");
        assert!(out.contains("errors ignored on restore"), "{out}");
        assert_eq!(out.matches("[row data omitted]").count(), 3, "{out}");
    }

    fn row(status: &str, stage: &str, log: &str) -> RestoreRow {
        RestoreRow {
            id: Uuid::nil(),
            created_at: chrono::Utc::now(),
            finished_at: None,
            status: status.into(),
            error: None,
            requested_by: "tester".into(),
            stage: stage.into(),
            log: log.into(),
        }
    }

    /// Position drives every step's state, so a running restore reads as a
    /// place along the list rather than five independent flags.
    #[test]
    fn a_running_restore_splits_the_list_at_the_current_stage() {
        let r = row("running", "connecting", "");
        assert_eq!(r.step_state(Stage::Locating), StepState::Done);
        assert_eq!(r.step_state(Stage::Checking), StepState::Done);
        assert_eq!(r.step_state(Stage::Connecting), StepState::Running);
        assert_eq!(r.step_state(Stage::Loading), StepState::Pending);
        assert_eq!(r.step_state(Stage::Finishing), StepState::Pending);
    }

    /// A failure names the step that failed, and everything after it is
    /// SKIPPED rather than pending — "never started" and "will never start"
    /// look identical on a stalled page and mean opposite things.
    #[test]
    fn a_failed_restore_marks_its_stage_and_skips_the_rest() {
        let r = row("failed", "checking", "");
        assert_eq!(r.step_state(Stage::Locating), StepState::Done);
        assert_eq!(r.step_state(Stage::Checking), StepState::Failed);
        assert_eq!(r.step_state(Stage::Loading), StepState::Skipped);
        assert_eq!(r.step_state(Stage::Finishing), StepState::Skipped);
    }

    /// The outcome outranks the column.
    ///
    /// `settle` writes `status` and never rewinds `stage`, so a successful
    /// restore is stored as ok-at-whatever-stage-it-reached. Reading the column
    /// literally would draw a committed restore with an unfinished tail — the
    /// display contradicting the fact.
    #[test]
    fn a_successful_restore_shows_every_step_done_whatever_the_stage_says() {
        for stage in ["locating", "loading", "finishing", ""] {
            let r = row("ok", stage, "");
            for s in Stage::ALL {
                assert_eq!(
                    r.step_state(s),
                    StepState::Done,
                    "stage={stage:?} step={s:?} — a committed restore ran every step"
                );
            }
        }
    }

    /// An unreadable stage must not be turned into progress. Claiming "done"
    /// would invent work; claiming "failed" would invent a failure.
    #[test]
    fn an_unrecognised_stage_invents_neither_progress_nor_failure() {
        let r = row("running", "teleporting", "");
        for s in Stage::ALL {
            assert_eq!(r.step_state(s), StepState::Pending);
        }
    }

    /// The step list reads its detail out of the log by TAG, not by line order,
    /// which is what lets the two stay in step when a stage logs more than once.
    #[test]
    fn details_are_matched_by_tag_and_the_last_line_wins() {
        // Exactly the shape `JobLog::step` writes: time, two spaces, the tag
        // padded to 8, then the detail.
        let log = "11:37:54Z  locating first attempt\n\
                   11:37:54Z  checking decrypted and read back in full\n\
                   11:37:55Z  locating found by id\n\
                   11:37:56Z  connecting restoring into 'brunos' as its owner\n";
        let r = row("running", "loading", log);

        let (t, d) = r.detail(Stage::Locating).expect("locating logged a line");
        assert_eq!(t, "11:37:55Z");
        assert_eq!(d, "found by id", "an earlier line for the same stage won");

        let (_, d) = r.detail(Stage::Checking).unwrap();
        assert_eq!(d, "decrypted and read back in full");

        // `connecting` is 10 characters, so it overflows the {:<8} padding and
        // is followed by a single space rather than the padded gap. Both shapes
        // have to parse or the longer stage names silently lose their detail.
        let (_, d) = r.detail(Stage::Connecting).unwrap();
        assert_eq!(d, "restoring into 'brunos' as its owner");

        // A stage that never logged has no detail — and must not borrow
        // another stage's line, which is what matching by order would do.
        assert!(r.detail(Stage::Finishing).is_none());
    }

    /// Every stage is renderable and distinct. A duplicate key would make two
    /// steps read the same log line and stay lit together.
    #[test]
    fn stage_keys_round_trip_and_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for s in Stage::ALL {
            assert!(seen.insert(s.key()), "duplicate stage key {:?}", s.key());
            assert_eq!(Stage::from_key(s.key()), Some(s));
            assert!(!s.title().is_empty() && !s.blurb().is_empty());
        }
        assert_eq!(Stage::from_key("nope"), None);
    }
}
