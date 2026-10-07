//! Per-database logical backups (CRYPTARCH-56, doc-cryptarch-backup-spec).
//!
//! An engine produces dump bytes; this module seals them. The blob written to
//! disk is a framed AES-256-GCM stream — chunked because a dump does not fit in
//! memory, authenticated per frame because a chunked format that isn't would let
//! someone reorder or truncate a backup without detection.
//!
//! Blob layout: `"CRBK" || version:u8 || backup_id:16 || aux_len:u32be || aux`,
//! then repeated frames of `len:u32be || nonce:12 || ciphertext+tag`. Each frame
//! authenticates a digest of that whole header plus its own index and
//! last-frame flag, so a stream that lost its tail — or borrowed a frame from
//! another backup under the same key — fails to open instead of restoring a
//! partial database that looks whole. See [`frame_aad`] for the break that
//! shaped this.

use crate::crypto::Crypto;
use anyhow::{bail, Context};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAGIC: &[u8; 4] = b"CRBK";
/// v2 is the only format ever written outside development. v1 authenticated a
/// frame's position but not its file, which was forgeable — see [`frame_aad`].
/// Its reader and one-time migration were deleted once no v1 blob remained.
const VERSION: u8 = 2;
/// Magic plus version byte — read first, before the rest of the header, so an
/// unknown version is rejected without interpreting anything after it.
const MAGIC_AND_VERSION: usize = 5;
/// Fixed part of a v2 header: magic, version, backup id, and the aux length
/// field itself. The variable `aux` bytes follow.
const V2_HEADER_FIXED: usize = 4 + 1 + 16 + 4;
/// Plaintext bytes per frame. Each frame costs a 12-byte nonce and a 16-byte
/// tag, so 1 MiB keeps the overhead at ~0.003% while bounding memory.
const FRAME_SIZE: usize = 1024 * 1024;
/// A legitimate frame is one plaintext frame plus nonce and tag. Anything
/// larger is a corrupt or hostile length prefix, and the prefix is not
/// authenticated — it is read before any key is involved — so it must be
/// bounded before it becomes an allocation.
const MAX_FRAME_ON_DISK: usize = FRAME_SIZE + 64;

/// The v2 file header: `magic || version || backup_id || aux_len || aux`.
///
/// `aux` is empty today and exists so the manifest (CRYPTARCH-67) can land
/// inside the authenticated header rather than forcing another format version.
/// Putting the manifest in "frame 0" instead would redefine what frame 0 means
/// for every v2 blob already written, which is a v3 — this way there is one
/// bump, and the manifest inherits the header's authentication for free.
struct Header {
    backup_id: uuid::Uuid,
    aux: Vec<u8>,
}

impl Header {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(V2_HEADER_FIXED + self.aux.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(self.backup_id.as_bytes());
        out.extend_from_slice(&(self.aux.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.aux);
        out
    }
}

/// Associated data for one frame: a digest of the entire file header, then the
/// frame's position.
///
/// Hashed rather than inlined so the AAD stays a fixed 41 bytes however large
/// `aux` grows — a manifest should not make every frame's associated data
/// proportional to it.
///
/// The header is in here because of a real break (found by review, 2026-07-20,
/// with a working exploit). v1 authenticated only `index || last`, which pins a
/// frame to a POSITION but not to a FILE — and every blob on a deployment is
/// sealed under the same master key. So an attacker with write access to the
/// backup directory but no key could truncate a backup to its first frame and
/// splice in a terminator frame harvested from ANY other backup at the same
/// index. Retention keeps seven donors per database in the same directory. The
/// forged blob opened cleanly and restored a plausible prefix of a database —
/// exactly the outcome the frame AAD existed to prevent.
///
/// Including the header binds each frame to one specific backup id, and
/// authenticates the magic and version bytes for free. That second part
/// matters ahead of time: without it, a future v3's frames would still open as
/// v2, which is a silent downgrade. Rewriting the id in the header does not
/// help an attacker — every frame was sealed against the true header, so all of
/// them then fail.
fn frame_aad(header: &[u8], index: u64, last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 9);
    aad.extend_from_slice(&Sha256::digest(header));
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(last));
    aad
}

/// What a completed backup produced, for the metadata row.
#[derive(Debug, Clone)]
pub struct SealedBlob {
    /// Size of the sealed file on disk.
    pub size_bytes: i64,
    /// Hex SHA-256 of the sealed file — verifies the blob is intact without
    /// needing the key.
    pub checksum: String,
}

/// Seal `src` into `dest`, returning the sealed size and checksum.
///
/// The checksum covers the *sealed* bytes deliberately: an operator (or a
/// restore) can verify a blob survived its trip to another disk without
/// decrypting anything, and the AEAD tags already cover the plaintext.
pub async fn seal_stream<R: AsyncRead + Unpin>(
    crypto: &Crypto,
    backup_id: uuid::Uuid,
    src: R,
    dest: &Path,
) -> anyhow::Result<SealedBlob> {
    seal_stream_with(crypto, backup_id, Vec::new(), src, dest).await
}

/// As [`seal_stream`], carrying `aux` in the header — the manifest
/// (CRYPTARCH-67) travels here so it is authenticated by every frame and can
/// never be separated from the data it describes.
pub async fn seal_stream_with<R: AsyncRead + Unpin>(
    crypto: &Crypto,
    backup_id: uuid::Uuid,
    aux: Vec<u8>,
    mut src: R,
    dest: &Path,
) -> anyhow::Result<SealedBlob> {
    let mut out = tokio::fs::File::create(dest)
        .await
        .with_context(|| format!("creating backup file {}", dest.display()))?;
    restrict_permissions(&out).await?;

    let mut hasher = Sha256::new();
    let mut written = 0usize;
    let header = Header { backup_id, aux }.encode();
    write_all(&mut out, &mut hasher, &mut written, &header).await?;

    // One frame of lookahead: a frame's "is this the last one" flag is
    // authenticated, and we only know the answer once the read after it comes
    // back empty.
    let mut index = 0u64;
    let mut pending: Option<Vec<u8>> = None;
    loop {
        let mut buf = vec![0u8; FRAME_SIZE];
        let n = read_full(&mut src, &mut buf).await?;
        buf.truncate(n);
        let eof = n == 0;
        if let Some(prev) = pending.take() {
            let frame = crypto.seal_frame(&frame_aad(&header, index, eof), &prev)?;
            write_frame(&mut out, &mut hasher, &mut written, &frame).await?;
            index += 1;
        }
        if eof {
            // An empty source still gets one (empty) final frame, so every
            // valid blob ends with an authenticated terminator.
            if index == 0 {
                let frame = crypto.seal_frame(&frame_aad(&header, 0, true), &[])?;
                write_frame(&mut out, &mut hasher, &mut written, &frame).await?;
            }
            break;
        }
        pending = Some(buf);
    }

    out.flush().await.context("flushing backup file")?;
    // The point of a backup is surviving a crash; leaving it in the page cache
    // undoes that.
    out.sync_all().await.context("fsyncing backup file")?;

    Ok(SealedBlob {
        size_bytes: written as i64,
        checksum: hex(&hasher.finalize()),
    })
}

/// Reverse of [`seal_stream`]: decrypt `src` into `dest`.
///
/// `expect` is the backup id the CALLER believes this file holds, taken from
/// the metadata row. Checking it closes whole-file substitution: binding frames
/// to their header stops an attacker assembling a forged file, but it cannot
/// stop them dropping database B's perfectly valid blob at database A's path.
/// The file is genuinely well-formed; only the mismatch between what it says it
/// is and what we asked for reveals the swap. The metadata database is a
/// different trust domain from the backup mount, which is what makes it a
/// usable anchor.
pub async fn open_stream<W: AsyncWrite + Unpin>(
    crypto: &Crypto,
    expect: uuid::Uuid,
    src: &Path,
    dest: W,
) -> anyhow::Result<()> {
    open_stream_aux(crypto, expect, src, dest).await.map(|_| ())
}

/// As [`open_stream`], also returning the header's `aux` section — the
/// authenticated manifest. Restore reads hazards from HERE, never from the
/// display copy in the metadata database: a row is editable by anyone with
/// database write access, and a forged "no hazards" is read as reassurance at
/// exactly the wrong moment.
pub async fn open_stream_aux<W: AsyncWrite + Unpin>(
    crypto: &Crypto,
    expect: uuid::Uuid,
    src: &Path,
    mut dest: W,
) -> anyhow::Result<Vec<u8>> {
    let mut f = tokio::fs::File::open(src)
        .await
        .with_context(|| format!("opening backup file {}", src.display()))?;

    let mut fixed = [0u8; MAGIC_AND_VERSION];
    f.read_exact(&mut fixed).await.context("reading backup header")?;
    if &fixed[..4] != MAGIC {
        bail!("not a Cryptarch backup file");
    }
    let version = fixed[4];
    if version != VERSION {
        bail!(
            "unsupported backup format version {version} — this build reads v{VERSION} only"
        );
    }

    let mut id_bytes = [0u8; 16];
    f.read_exact(&mut id_bytes).await.context("reading backup id")?;
    let backup_id = uuid::Uuid::from_bytes(id_bytes);
    let mut aux_len = [0u8; 4];
    f.read_exact(&mut aux_len).await.context("reading header aux length")?;
    let aux_len = u32::from_be_bytes(aux_len) as usize;
    anyhow::ensure!(aux_len <= MAX_FRAME_ON_DISK, "header aux section is implausibly large");
    let mut aux = vec![0u8; aux_len];
    if aux_len > 0 {
        f.read_exact(&mut aux).await.context("reading header aux section")?;
    }

    anyhow::ensure!(
        expect == backup_id,
        "this file is backup {backup_id}, not the expected {expect} — it has been \
         replaced or moved"
    );

    let header = Header { backup_id, aux: aux.clone() }.encode();
    read_frames(crypto, &mut f, &mut dest, &header).await?;
    Ok(aux)
}

/// Decrypt the frame stream.
async fn read_frames<W: AsyncWrite + Unpin>(
    crypto: &Crypto,
    f: &mut tokio::fs::File,
    dest: &mut W,
    header: &[u8],
) -> anyhow::Result<()> {
    let aad = |index: u64, last: bool| frame_aad(header, index, last);
    // One frame of lookahead, as when sealing: whether a frame is the last one
    // is authenticated, and we only learn the answer from the read after it.
    let mut index = 0u64;
    let mut pending: Option<Vec<u8>> = None;
    loop {
        let next = read_frame(f).await?;
        match (pending.take(), next) {
            (Some(prev), Some(next)) => {
                let plain = crypto.open_frame(&aad(index, false), &prev)?;
                dest.write_all(&plain).await.context("writing restored bytes")?;
                index += 1;
                pending = Some(next);
            }
            (Some(prev), None) => {
                let plain = crypto.open_frame(&aad(index, true), &prev)?;
                dest.write_all(&plain).await.context("writing restored bytes")?;
                break;
            }
            (None, Some(next)) => pending = Some(next),
            (None, None) => bail!("backup file has no frames — it is truncated or empty"),
        }
    }
    dest.flush().await.context("flushing restored stream")?;
    Ok(())
}

/// Ceiling on a stored job log. Generous for a normal job; the point is that a
/// pathological one (a dump emitting a warning per table across ten thousand
/// tables) cannot bloat the metadata database.
const LOG_LIMIT: usize = 64 * 1024;

/// Appends timestamped step lines to a job's log as it runs.
///
/// Incremental on purpose: a log written only at the end is useless while the
/// thing you are worried about is still happening. Each step is one UPDATE,
/// which is nothing next to the dump it describes.
///
/// Writes are best-effort — losing a log line must never fail the backup it is
/// describing. Restore will share this by pointing `table` at its own table.
#[derive(Clone)]
pub struct JobLog {
    db: sqlx::PgPool,
    table: &'static str,
    id: uuid::Uuid,
}

impl JobLog {
    /// `table` is `&'static str` rather than a parameter because it is
    /// interpolated into SQL — a table name cannot be a bind parameter, so the
    /// type is the guarantee that it is a compile-time constant.
    pub fn new(db: sqlx::PgPool, table: &'static str, id: uuid::Uuid) -> Self {
        Self { db, table, id }
    }

    /// Record one step: `HH:MM:SSZ  step  detail`.
    pub async fn step(&self, step: &str, detail: impl AsRef<str>) {
        let line = format!(
            "{}  {:<8} {}\n",
            chrono::Utc::now().format("%H:%M:%SZ"),
            step,
            detail.as_ref().trim_end()
        );
        self.append(&line).await;
    }

    /// Record a tool's own output verbatim, indented so it reads as a quoted
    /// block rather than as our step lines.
    pub async fn output(&self, from: &str, text: &str) {
        let text = text.trim_end();
        if text.is_empty() {
            return;
        }
        let quoted: String = text.lines().map(|l| format!("    | {l}\n")).collect();
        self.append(&format!(
            "{}  {:<8} {from} said:\n{quoted}",
            chrono::Utc::now().format("%H:%M:%SZ"),
            "output"
        ))
        .await;
    }

    async fn append(&self, text: &str) {
        // Truncation happens in SQL against the current value so concurrent
        // appends cannot resurrect trimmed bytes. Keeping the HEAD and dropping
        // from the middle is deliberate: the start of a log says what was
        // attempted, and losing that leaves an unreadable tail.
        let sql = format!(
            "UPDATE {} SET log = CASE \
                 WHEN length(log) + length($2) <= $3 THEN log || $2 \
                 ELSE left(log, $3 / 2) || E'\\n    ... log truncated ...\\n' \
                      || right(log || $2, $3 / 2) \
             END WHERE id = $1",
            self.table
        );
        // `self.table` is `&'static str` by construction (see the field), so
        // the only interpoland here cannot be a runtime value.
        if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(self.id)
            .bind(text)
            .bind(LOG_LIMIT as i32)
            .execute(&self.db)
            .await
        {
            tracing::warn!("could not append to job log {}: {e}", self.id);
        }
    }
}

/// One row of a database's backup history, as the db page renders it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BackupRow {
    pub id: uuid::Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub size_bytes: Option<i64>,
    pub status: String,
    pub error: Option<String>,
    pub log: String,
    /// When the blob was read back and proven readable. NULL means that never
    /// happened — whether because verification was off or because the backup
    /// predates it, which are the same claim.
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Which database this backup is of. Carried so the fleet-wide view can
    /// name it; the per-database view already knows.
    #[sqlx(default)]
    pub db_name: String,
    /// Display copy of the manifest. NEVER used for a safety decision — see
    /// migration 0013. The authoritative copy is inside the sealed blob.
    pub manifest: Option<serde_json::Value>,
}

impl BackupRow {
    /// What the portal knows about this backup's contents.
    ///
    /// Reads the DISPLAY copy, which is why this is only ever rendered and
    /// never used to decide whether a restore is safe. A row with no manifest
    /// resolves to `Absent`, which reports as unknown rather than as clean.
    pub fn contents(&self) -> crate::manifest::ManifestState {
        match &self.manifest {
            Some(v) => crate::manifest::ManifestState::decode(
                &serde_json::to_vec(v).unwrap_or_default(),
            ),
            None => crate::manifest::ManifestState::Absent,
        }
    }

    /// How long the job took, or how long it has been running so far.
    pub fn duration(&self) -> String {
        let end = self.finished_at.unwrap_or_else(chrono::Utc::now);
        let secs = (end - self.created_at).num_milliseconds() as f64 / 1000.0;
        if secs < 60.0 {
            format!("{secs:.1}s")
        } else {
            format!("{}m {}s", (secs / 60.0) as i64, (secs % 60.0) as i64)
        }
    }
}

/// Backup history for one database, newest first — keyed on the database's
/// IDENTITY, never its name (CRYPTARCH-86).
///
/// This used to key on `db_name`, justified by history outliving the row it
/// describes. That reasoning held for *the same database after deletion* and
/// silently failed for *a different database with the same name*: names are
/// freed on delete (`provision.rs` removes the row, and the unique constraint
/// only binds live ones), so the next person to take a name inherited the
/// previous owner's backup list — sizes, timestamps, and their `pg_dump` error
/// output. Authorisation was on the live row while retrieval was on the name,
/// and those are not the same thing.
///
/// Deleting a database therefore no longer hides its backups by accident of the
/// query — it transfers them. `backups.database_id` is `ON DELETE SET NULL`, so
/// an orphaned row stops matching any tenant here and becomes the operator's,
/// visible and purgeable only through the admin view. That is the whole owner
/// change, and it falls out of the foreign key rather than needing a flag.
///
/// Best-effort: a failed read renders as "no backups yet" rather than taking
/// down the page.
pub async fn history(db: &sqlx::PgPool, database_id: uuid::Uuid) -> Vec<BackupRow> {
    sqlx::query_as::<_, BackupRow>(
        "SELECT id, created_at, finished_at, size_bytes, status, error, log, manifest, \
                verified_at \
         FROM backups WHERE database_id = $1 ORDER BY created_at DESC LIMIT 50",
    )
    .bind(database_id)
    .fetch_all(db)
    .await
    .unwrap_or_else(|e| {
        tracing::error!("reading backup history for database {database_id}: {e}");
        Vec::new()
    })
}

/// Recent backup jobs across every database, for the admin view.
///
/// Deliberately queried by `backups` alone rather than joined to `databases`:
/// history outlives the database it describes, and Cryptarch's own metadata
/// database has no `databases` row at all — joining is exactly what made its
/// backups invisible everywhere in the portal.
/// An error is returned, not an empty list: "no backups have run" and "could
/// not read the backups" must not look the same.
pub async fn recent(db: &sqlx::PgPool, limit: i64) -> Result<Vec<BackupRow>, sqlx::Error> {
    sqlx::query_as::<_, BackupRow>(
        "SELECT id, created_at, finished_at, size_bytes, status, error, log, manifest, \
                verified_at, db_name \
         FROM backups ORDER BY created_at DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(db)
    .await
}

/// Why a backup could not be started. Distinct from a backup that started and
/// then failed — that outcome lives on the row, not in a return value.
#[derive(Debug, thiserror::Error)]
pub enum EnqueueError {
    #[error("backups are not configured on this deployment")]
    Disabled,
    #[error("a backup of this database is already running")]
    AlreadyRunning,
    /// A RESTORE holds this database (CRYPTARCH-114). Distinct from
    /// `AlreadyRunning` because the two say different things to the person
    /// reading them: "wait for your backup" versus "something is rewriting this
    /// database right now, and a dump taken during it would capture a
    /// half-restored state".
    #[error("a restore of this database is running — a backup taken now would capture it mid-rebuild")]
    RestoreRunning,
    #[error("database not found")]
    NotFound,
    /// Shutdown has begun; the job was never claimed (CRYPTARCH-128).
    #[error("Cryptarch is shutting down — try again once it is back")]
    ShuttingDown,
    #[error("internal error")]
    Internal,
}

/// Start a backup of `db_name` and return its id immediately.
///
/// Enqueue-then-run, rather than dumping inline: even a few-GB database takes
/// longer than an HTTP request should hold, so the caller gets a `running` row
/// to render and the work happens on a background task. The scheduler wants
/// the opposite (run it here, one at a time) and calls [`run_now`] — same job
/// body either way.
pub async fn enqueue(
    state: &crate::web::AppState,
    actor: &str,
    db_name: &str,
) -> Result<uuid::Uuid, EnqueueError> {
    // Registered BEFORE the claim, and refused if shutdown has begun
    // (CRYPTARCH-128) — see `JobTracker::begin` for why the order matters.
    let guard = state.jobs.begin().ok_or(EnqueueError::ShuttingDown)?;
    let job = claim(state, actor, db_name).await?;
    let id = job.id;
    let state = state.clone();
    tokio::spawn(async move {
        // `guard` moves in and lives exactly as long as the job (CRYPTARCH-113).
        let _guard = guard;
        run_job(state, job).await
    });
    Ok(id)
}

/// Back up `db_name` and wait for it. Used by the scheduler and the CLI, where
/// running jobs one at a time is the point — a homelab box should not dump
/// every database at once.
pub async fn run_now(
    state: &crate::web::AppState,
    actor: &str,
    db_name: &str,
) -> Result<Outcome, EnqueueError> {
    // Tracked like an enqueued job (CRYPTARCH-123). The scheduler awaits this
    // inline rather than spawning it, which made it invisible to the shutdown
    // drain — and the nightly sweep is the backup most likely to be running
    // when a redeploy lands. Registered BEFORE the claim (CRYPTARCH-128): after
    // it, drain could read zero and return between the claim and the guard.
    let _guard = state.jobs.begin().ok_or(EnqueueError::ShuttingDown)?;
    let job = claim(state, actor, db_name).await?;
    Ok(run_job(state.clone(), job).await)
}

/// How a finished job turned out, for callers that waited on it.
///
/// Three outcomes, not two, and deliberately no `is_ok()` helper (CRYPTARCH-85).
/// "The blob sealed cleanly" and "the row saying so was written" are separate
/// facts, and collapsing them is how a backup nobody recorded gets reported as
/// a success — to the CLI's exit code, to cron, and worst of all to the audit
/// log. A bool cannot carry the difference, so callers must match and answer it.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// Sealed, and the row recording it was written.
    Ok { size_bytes: i64 },
    /// Sealed and on disk, but the row could not be updated to say so. NOT a
    /// success: nothing in the metadata database knows this backup exists, and
    /// the row is still `running`, which is the per-database lock. Recovery is
    /// `sweep_abandoned`, at the first pass past `ABANDONED_AFTER` — see its
    /// doc comment for why that bound is longer the more actively backups run.
    Unrecorded { size_bytes: i64, detail: String },
    /// The dump or its verification failed. The blob may or may not have been
    /// kept; the row says which.
    Failed { error: String },
}

/// Take the process-wide claim lock for one database's jobs (CRYPTARCH-114).
///
/// Backups and restores each have their own partial unique index, so each table
/// prevents a duplicate of ITSELF — but neither knew about the other, and the
/// two are not independent: `pg_dump` holds `ACCESS SHARE` on every table for
/// its whole run while `pg_restore --clean` wants `ACCESS EXCLUSIVE` to drop
/// them. Overlap either blocks the tenant's live application on its own tables
/// for the duration of the dump, or kills the dump with "relation does not
/// exist" after a full-size partial blob has been written.
///
/// A cross-table check alone would be check-then-insert with a real window: a
/// backup and a restore can both read "nothing running" before either commits.
/// An advisory lock on the database NAME closes it — the two claimers serialise
/// here, so the loser reads the winner's committed row. It is transaction-
/// scoped, so it is released at commit and cannot leak; the durable lock stays
/// what it has always been, the `running` row itself.
///
/// Keyed on the name rather than an id because that is what the two jobs
/// actually contend over — the physical database — and because the metadata
/// database has no id at all.
pub async fn lock_db_jobs(tx: &mut sqlx::PgConnection, db_name: &str) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(format!("cryptarch-job:{db_name}"))
        .execute(&mut *tx)
        .await
        .map(|_| ())
}

/// Is a job of the OTHER kind already running against this database?
///
/// Public so `restore::enqueue` asks the same question from its side; the
/// answer has to be symmetric or the exclusion only holds in one direction.
pub async fn other_job_running(
    tx: &mut sqlx::PgConnection,
    db_name: &str,
    kind: JobKind,
) -> Result<bool, sqlx::Error> {
    let sql = match kind {
        // A restore is claiming: look for a running backup.
        JobKind::Restore => "SELECT EXISTS (SELECT 1 FROM backups WHERE db_name = $1 AND status = 'running')",
        // A backup is claiming: look for a running restore.
        JobKind::Backup => "SELECT EXISTS (SELECT 1 FROM restores WHERE target_name = $1 AND status = 'running')",
    };
    sqlx::query_scalar(sql).bind(db_name).fetch_one(&mut *tx).await
}

/// Which kind of job is asking. Not a bool: `other_job_running(.., true)` at a
/// call site is unreadable, and getting it backwards silently disables the
/// exclusion in one direction.
#[derive(Debug, Clone, Copy)]
pub enum JobKind {
    Backup,
    Restore,
}

/// Reserve the right to back up `db_name`, or say why not.
///
/// The insert IS the lock: `idx_backups_one_running_per_db` is a partial unique
/// index on `status='running'`, so a second attempt loses the race inside the
/// database rather than in a check-then-insert window here. The advisory lock
/// above extends that mutual exclusion across the `restores` table too.
async fn claim(
    state: &crate::web::AppState,
    actor: &str,
    db_name: &str,
) -> Result<Job, EnqueueError> {
    let Some(root) = state.backup_dir.clone() else {
        return Err(EnqueueError::Disabled);
    };

    // The metadata database is not a provisioned one — it has no owner, no
    // server row, and no `databases` entry to look up.
    let (database_id, server_id) = if db_name == METADATA_DB {
        (None, None)
    } else {
        let row = sqlx::query_as::<_, (uuid::Uuid, uuid::Uuid)>(
            // Never resolve a backup target to a reservation or an aside copy.
            sqlx::AssertSqlSafe(format!(
            // Acting question (CRYPTARCH-111): dumping a database mid-rebuild
            // captures a half-restored state and files it as a good backup.
            "SELECT id, server_id FROM databases WHERE name = $1 AND {}",
            crate::status::DbStatus::should_be_backed_up_sql()
        ))
        )
        .bind(db_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("backup lookup failed for '{db_name}': {e}");
            EnqueueError::Internal
        })?
        .ok_or(EnqueueError::NotFound)?;
        (Some(row.0), Some(row.1))
    };

    // Claim inside a transaction so the cross-table check and the insert cannot
    // be interleaved by a restore claiming the same database (CRYPTARCH-114).
    let mut tx = state.db.begin().await.map_err(|e| {
        tracing::error!("opening the backup claim transaction for '{db_name}': {e}");
        EnqueueError::Internal
    })?;
    lock_db_jobs(&mut tx, db_name).await.map_err(|e| {
        tracing::error!("taking the job lock for '{db_name}': {e}");
        EnqueueError::Internal
    })?;
    match other_job_running(&mut tx, db_name, JobKind::Backup).await {
        Ok(true) => return Err(EnqueueError::RestoreRunning),
        Ok(false) => {}
        Err(e) => {
            tracing::error!("checking for a running restore of '{db_name}': {e}");
            return Err(EnqueueError::Internal);
        }
    }

    let id: uuid::Uuid = match sqlx::query_scalar(
        "INSERT INTO backups (database_id, db_name, server_id, status) \
         VALUES ($1, $2, $3, 'running') RETURNING id",
    )
    .bind(database_id)
    .bind(db_name)
    .bind(server_id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(id) => id,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(EnqueueError::AlreadyRunning);
        }
        Err(e) => {
            tracing::error!("backup insert failed for '{db_name}': {e}");
            return Err(EnqueueError::Internal);
        }
    };
    tx.commit().await.map_err(|e| {
        tracing::error!("committing the backup claim for '{db_name}': {e}");
        EnqueueError::Internal
    })?;

    crate::provision::audit(&state.db, actor, "backup_start", Some(db_name), None).await;

    Ok(Job {
        id,
        db_name: db_name.to_string(),
        database_id,
        server_id,
        root,
        actor: actor.to_string(),
    })
}

struct Job {
    id: uuid::Uuid,
    db_name: String,
    /// `None` for the metadata database, which is not a provisioned row.
    database_id: Option<uuid::Uuid>,
    /// `None` for the metadata database, which lives on no managed server.
    server_id: Option<uuid::Uuid>,
    root: PathBuf,
    actor: String,
}

/// Run one enqueued backup to completion and record the outcome.
///
/// Every exit path writes a terminal status. A job that returned without doing
/// so would leave the row `running` forever, and the partial unique index would
/// then block that database's backups permanently.
async fn run_job(state: crate::web::AppState, job: Job) -> Outcome {
    let started = chrono::Utc::now();
    let rel = blob_path(&job.db_name, job.id, started);
    let abs = job.root.join(&rel);
    let log = JobLog::new(state.db.clone(), "backups", job.id);

    log.step(
        "start",
        format!(
            "{} — requested by {}, client {}",
            job.db_name,
            job.actor,
            client_version().await,
        ),
    )
    .await;

    let elapsed = || {
        let secs = (chrono::Utc::now() - started).num_milliseconds() as f64 / 1000.0;
        format!("{secs:.1}s")
    };

    let sealed = match dump_and_seal(&state, &job, &abs, &log).await {
        Ok(sealed) => sealed,
        Err(e) => {
            let detail = format!("{e:#}");
            log.step("FAILED", format!("{detail} (after {})", elapsed())).await;
            tracing::warn!("backup of '{}' failed: {detail}", job.db_name);
            // A failed dump still wrote a prefix of a file. Leaving it behind
            // would put something that looks like a backup next to real ones.
            if let Err(rm) = tokio::fs::remove_file(&abs).await
                && rm.kind() != std::io::ErrorKind::NotFound
            {
                tracing::warn!("could not remove partial backup {}: {rm}", abs.display());
            }
            return record_failure(&state, &job, &detail, None).await;
        }
    };

    // Verify BEFORE claiming success: "a backup exists" and "a backup that can
    // be read exists" are different statements, and only the second is worth
    // anything at 3am.
    //
    // NOT OPTIONAL, and that is a deletion rather than a default (Antun,
    // 2026-07-21). This used to be switchable with CRYPTARCH_BACKUP_VERIFY, for
    // a pathologically large database where a second full read costs real time.
    // The switch bought that and charged for it everywhere else: with it off,
    // `status = 'ok'` meant only "sealed", so every consumer of that column had
    // to ask which of two claims it was making. Retention was the expensive
    // one — its whole tiered design existed to answer "does ok mean verified
    // here?" before deciding what to delete.
    //
    // An option nobody should choose is a trap with a manual. Removing it makes
    // `ok` mean verified, once, everywhere.
    //
    // What it does NOT do is re-verify history: rows written before this still
    // carry a NULL `verified_at`, and migration 0014's reasoning stands for
    // them. The badge that distinguishes them stays for exactly that reason.
    let verified_at = match verify_and_log(&state, &job, &abs, &log).await {
        Ok(()) => Some(chrono::Utc::now()),
        Err(e) => {
            let detail = format!("verification failed: {e:#}");
            log.step("FAILED", format!("{detail} (after {})", elapsed())).await;
            tracing::error!("backup of '{}' could not be verified: {detail}", job.db_name);
            // The blob is deliberately KEPT. A file that sealed cleanly but
            // failed verification is not the same thing as a truncated write:
            // the cause may be transient (disk pressure, pg_restore failing to
            // spawn) and the backup may be perfectly good. Deleting it would
            // destroy evidence and possibly a usable backup; marking the row
            // failed leaves it for a human to look at.
            return record_failure(
                &state,
                &job,
                &detail,
                Some((rel.to_string_lossy().as_ref(), &sealed)),
            )
            .await;
        }
    };

    {
        {
            log.step(
                "done",
                format!("ok in {} — {}", elapsed(), rel.display()),
            )
            .await;
            if let Err(detail) = record_success(
                &state.db,
                job.id,
                sealed.size_bytes,
                &sealed.checksum,
                rel.to_string_lossy().as_ref(),
                verified_at,
                state.crypto.key_fingerprint(),
            )
            .await
            {
                // The blob is on disk and good; only the bookkeeping failed —
                // but that is NOT a success, and it must not be recorded as
                // one. No `backup_ok` here (CRYPTARCH-85): the audit trail is
                // read during an incident, and a success it invented is worse
                // than a gap.
                //
                // The row is left `running` because `sweep_abandoned` is the
                // single owner of the running->failed transition; writing
                // `failed` here would be a second implementation of it, free
                // to disagree. That is the whole reason, and it holds even
                // when the metadata database is perfectly healthy.
                //
                // The two writes below are BEST EFFORT and will usually be
                // absent in the case that matters: the likeliest cause of a
                // failed record is the metadata database being unreachable, in
                // which case this `audit` and this `log.step` fail too (audit
                // swallows its own error by design). That asymmetry is
                // deliberate and safe, because the guarantee that matters is
                // NEGATIVE — no invented `backup_ok` — and it is achieved by
                // NOT writing, so it survives the database being gone. The
                // positive record is a convenience on top.
                //
                // Consequence, and the reason this is spelled out: do NOT
                // build an alert on the presence of `backup_unrecorded` rows.
                // They appear in the rare case (row gone, database up) and are
                // missing in the common one. The load-bearing signal is the
                // `tracing::error!` below, which needs no database at all.
                log.step("UNRECORDED", format!("{detail} (after {})", elapsed())).await;
                tracing::error!(
                    "backup of '{}' sealed but its row did not record: {detail}",
                    job.db_name
                );
                crate::provision::audit(
                    &state.db,
                    &job.actor,
                    "backup_unrecorded",
                    Some(&job.db_name),
                    Some(&detail),
                )
                .await;
                return Outcome::Unrecorded { size_bytes: sealed.size_bytes, detail };
            }
            crate::provision::audit(
                &state.db,
                &job.actor,
                "backup_ok",
                Some(&job.db_name),
                Some(&format!("{} bytes", sealed.size_bytes)),
            )
            .await;
            Outcome::Ok { size_bytes: sealed.size_bytes }
        }
    }
}

/// Verify a finished blob and record what was found.
async fn verify_and_log(
    state: &crate::web::AppState,
    job: &Job,
    abs: &Path,
    log: &JobLog,
) -> anyhow::Result<()> {
    let entries = verify_blob(&state.crypto, job.id, abs).await?;
    // An archive that lists cleanly but contains nothing is not a verified
    // backup of a database with tables in it.
    log.step(
        "verify",
        format!("decrypted in full; pg_restore reads {entries} archive entr{}",
                if entries == 1 { "y" } else { "ies" }),
    )
    .await;
    Ok(())
}

/// Record a finished backup against its `running` row, or say why it could not
/// be recorded (CRYPTARCH-85).
///
/// Returns `Err` on BOTH ways this can go wrong, because they are the same fact
/// to every caller — no row now says this backup exists:
///
///  - the statement failed, or
///  - the statement succeeded and matched NOTHING.
///
/// The second is the one that hid: an `UPDATE ... WHERE` matching nothing is a
/// perfectly successful statement with `rows_affected` of 0. Testing only for
/// `Err` reports a backup as recorded when nothing was written, and leaves no
/// error line behind to notice later. **The affected count is the claim; the
/// absence of an error is not.**
///
/// `AND status = 'running'` is the other half of that, and it is not belt and
/// braces — without it this write overclaims in a way reachable in production.
/// A dump outliving `ABANDONED_AFTER` is marked `failed` by `sweep_abandoned`
/// while its task is still running, which a multi-GB dump on a homelab box will
/// do. Finishing afterwards would match that failed row by id alone, flip it
/// back to `'ok'`, and — because this statement clears `error` — erase the
/// record that the job was ever declared dead. A success is only meaningful
/// against a job still believed to be in flight, so the statement says so
/// rather than trusting the caller to have checked.
///
/// That clause is also what makes the zero-row branch reachable without an
/// operator at a psql prompt: losing the race with the sweep is an ordinary
/// interleaving, not a hypothetical.
///
/// `error` is cleared, not left behind: a row that reached 'ok' after a
/// previous sweep had marked it stale would otherwise carry a failure string
/// forever, and anything later asking "was this backup clean?" would read it
/// and be wrong. Clearing it is only safe BECAUSE of the status clause above —
/// the two are one decision, not two. `verified_at` records what was DONE: a
/// configuration flag says what we intended; this says whether the read-back
/// actually happened, which is what an operator is really asking when they look
/// at a green badge.
pub async fn record_success(
    db: &sqlx::PgPool,
    id: uuid::Uuid,
    size_bytes: i64,
    checksum: &str,
    rel_path: &str,
    verified_at: Option<chrono::DateTime<chrono::Utc>>,
    // Which key sealed this blob (CRYPTARCH-107). Recorded so a later restore
    // can say "sealed under a different key" instead of handing the operator
    // the generic AEAD failure, which cannot tell a wrong key from a bad disk.
    key_fingerprint: &str,
) -> Result<(), String> {
    let done = sqlx::query(
        "UPDATE backups SET status = 'ok', finished_at = now(), \
         size_bytes = $2, checksum = $3, path = $4, error = NULL, \
         verified_at = $5, key_fingerprint = $6 WHERE id = $1 AND status = 'running'",
    )
    .bind(id)
    .bind(size_bytes)
    .bind(checksum)
    .bind(rel_path)
    .bind(verified_at)
    .bind(key_fingerprint)
    .execute(db)
    .await
    .map_err(|e| format!("recording the backup row failed: {e}"))?;

    match done.rows_affected() {
        1 => Ok(()),
        n => Err(format!("no backup row {id} to record into (matched {n})")),
    }
}

/// Mark a job failed and audit it. Does NOT touch the blob — whether the file
/// should survive depends on how it failed, so that decision stays with the
/// caller.
///
/// `kept` carries the blob's identity when the file is being left on disk. Not
/// recording it would make "kept for a human to look at" hollow: retention
/// reclaims files through `path`, so a NULL there means the blob can never be
/// cleaned up, and nothing would tell the human WHICH of a directory of
/// timestamped files they were being asked to look at. Keeping evidence and
/// merely not deleting something are different acts.
async fn record_failure(
    state: &crate::web::AppState,
    job: &Job,
    detail: &str,
    kept: Option<(&str, &SealedBlob)>,
) -> Outcome {
    let res = match kept {
        Some((rel, blob)) => {
            sqlx::query(
                "UPDATE backups SET status = 'failed', finished_at = now(), error = $2, \
                 path = $3, size_bytes = $4, checksum = $5 WHERE id = $1",
            )
            .bind(job.id)
            .bind(detail)
            .bind(rel)
            .bind(blob.size_bytes)
            .bind(&blob.checksum)
            .execute(&state.db)
            .await
        }
        None => {
            sqlx::query(
                "UPDATE backups SET status = 'failed', finished_at = now(), error = $2 \
                 WHERE id = $1",
            )
            .bind(job.id)
            .bind(detail)
            .execute(&state.db)
            .await
        }
    };
    if let Err(e) = res {
        tracing::error!("could not mark backup of '{}' failed: {e}", job.db_name);
    }
    crate::provision::audit(
        &state.db,
        &job.actor,
        "backup_failed",
        Some(&job.db_name),
        Some(detail),
    )
    .await;
    Outcome::Failed { error: detail.to_string() }
}

async fn dump_and_seal(
    state: &crate::web::AppState,
    job: &Job,
    abs: &Path,
    log: &JobLog,
) -> anyhow::Result<SealedBlob> {
    if let Some(parent) = abs.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating backup directory {}", parent.display()))?;
    }

    let (mut dump, aux) = match job.server_id {
        Some(server_id) => {
            let engine = state
                .servers
                .get(server_id)
                .context("managed server is not registered (inactive or unreachable)")?;
            // Survey BEFORE dumping, while the source is guaranteed to exist —
            // the case a restore needs this for most is a database that will
            // not exist by then.
            let aux = survey_to_aux(state, job, engine.as_ref(), log).await;
            (engine.dump_stream(&job.db_name).await?, aux)
        }
        None => {
            log.step("target", "Cryptarch's own metadata database").await;
            // Not surveyed: it is not a provisioned database, and its restore
            // is a documented manual procedure rather than a portal action.
            (metadata_dump(state).await?, Vec::new())
        }
    };
    log.step("dump", &dump.command).await;

    let stdout = dump.take_stdout()?;
    let sealed = seal_stream_with(&state.crypto, job.id, aux.clone(), stdout, abs).await?;
    // Only now is the backup real: the stream ending means the pipe closed,
    // which a crashed pg_dump also does.
    let warnings = dump.finish().await?;
    // Recorded even though the dump SUCCEEDED — that is the whole point.
    log.output("pg_dump", &warnings).await;
    log.step(
        "sealed",
        format!(
            "{} bytes, sha256 {}",
            sealed.size_bytes,
            &sealed.checksum[..16.min(sealed.checksum.len())]
        ),
    )
    .await;
    Ok(sealed)
}

/// Prove a finished blob can actually be read back (CRYPTARCH-68).
///
/// Two claims are being made, and the code has to earn both:
///
/// 1. **Every frame decrypts.** The blob is re-opened FROM DISK, not from the
///    buffer we just sealed — surviving the write is the entire question, and
///    verifying memory proves nothing about what reached the platter. Reading
///    to the end is what makes the AEAD tags attest to the whole file.
/// 2. **`pg_restore` can parse it.** Note this alone would be a much weaker
///    claim than it looks: in custom format the table of contents sits at the
///    FRONT, so a listing succeeds having touched almost none of the data. If
///    we stopped as soon as the listing was satisfied, "verified" would mean
///    "the header is intact" while reading as "the backup is good".
///
/// So the decrypted stream is piped into `pg_restore --list`, and if that
/// process stops reading early the remaining plaintext is discarded rather than
/// aborting the decrypt — the full read happens either way.
///
/// Returns the number of real archive entries. An EMPTY archive lists
/// successfully and prints a dozen comment lines, so neither exit status nor
/// "produced output" distinguishes it — only counting entries does.
pub async fn verify_blob(
    crypto: &Crypto,
    backup_id: uuid::Uuid,
    path: &Path,
) -> anyhow::Result<i64> {
    let mut child = tokio::process::Command::new("pg_restore")
        .arg("--list")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawning pg_restore --list to verify the backup")?;

    let stdin = child.stdin.take().context("pg_restore has no stdin")?;
    let mut stdout = child.stdout.take().context("pg_restore has no stdout")?;
    let mut stderr = child.stderr.take().context("pg_restore has no stderr")?;
    // Drained concurrently: a listing large enough to fill the pipe would
    // otherwise deadlock against us writing the archive in.
    let out = tokio::spawn(async move {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s).await;
        s
    });
    let err = tokio::spawn(async move {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s).await;
        s
    });

    let decrypted = open_stream(crypto, backup_id, path, TolerantWriter::new(stdin)).await;
    // Close our end so pg_restore sees EOF, whatever happened above.
    let status = child.wait().await.context("waiting for pg_restore --list")?;
    let listing = out.await.unwrap_or_default();
    let complaints = err.await.unwrap_or_default();

    decrypted.context("the sealed backup could not be decrypted from disk")?;
    anyhow::ensure!(
        status.success(),
        "pg_restore could not read the backup ({status}){}{}",
        if complaints.trim().is_empty() { "" } else { ": " },
        complaints.trim()
    );

    // Comment lines are always present, even for an archive with nothing in it.
    let entries = listing
        .lines()
        .filter(|l| !l.trim_start().starts_with(';') && !l.trim().is_empty())
        .count() as i64;
    Ok(entries)
}

/// Test entry point for [`verify_blob`], named so its use in production would
/// stand out in review.
#[doc(hidden)]
pub async fn verify_for_tests(
    crypto: &Crypto,
    backup_id: uuid::Uuid,
    path: &Path,
) -> anyhow::Result<i64> {
    verify_blob(crypto, backup_id, path).await
}

/// Forwards to a writer until it goes away, then discards.
///
/// `pg_restore --list` may stop reading once it has the table of contents. The
/// decrypt must still run to completion — that is what proves the whole blob
/// authenticates — so a broken pipe here is an expected end to the forwarding,
/// not an error to propagate.
struct TolerantWriter {
    inner: Option<tokio::process::ChildStdin>,
}

impl TolerantWriter {
    fn new(inner: tokio::process::ChildStdin) -> Self {
        Self { inner: Some(inner) }
    }
}

impl tokio::io::AsyncWrite for TolerantWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let Some(inner) = self.inner.as_mut() else {
            return std::task::Poll::Ready(Ok(buf.len()));
        };
        match std::pin::Pin::new(inner).poll_write(cx, buf) {
            std::task::Poll::Ready(Err(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::WriteZero
                ) =>
            {
                self.inner = None;
                std::task::Poll::Ready(Ok(buf.len()))
            }
            other => other,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.inner.as_mut() {
            Some(inner) => match std::pin::Pin::new(inner).poll_flush(cx) {
                std::task::Poll::Ready(Err(_)) => {
                    self.inner = None;
                    std::task::Poll::Ready(Ok(()))
                }
                other => other,
            },
            None => std::task::Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.inner.as_mut() {
            Some(inner) => {
                let r = std::pin::Pin::new(inner).poll_shutdown(cx);
                if r.is_ready() {
                    self.inner = None;
                }
                r
            }
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

/// Survey the database and serialise a manifest for the blob header.
///
/// Returns EMPTY on failure, deliberately and after saying so loudly in the
/// log. A failed survey must not fail the backup — the data is the point, and
/// refusing to protect it because we could not describe it would be the wrong
/// trade. It is safe to continue precisely because an absent manifest reads as
/// "hazards unknown" rather than "no hazards"; if that ever inverts, this
/// decision becomes indefensible.
async fn survey_to_aux(
    state: &crate::web::AppState,
    job: &Job,
    engine: &dyn crate::engine::DbEngine,
    log: &JobLog,
) -> Vec<u8> {
    let survey = match engine.survey(&job.db_name).await {
        Ok(s) => s,
        Err(e) => {
            log.step(
                "survey",
                format!("FAILED — this backup's contents will read as unknown: {e:#}"),
            )
            .await;
            tracing::warn!("survey of '{}' failed: {e:#}", job.db_name);
            return Vec::new();
        }
    };

    let manifest = crate::manifest::Manifest {
        schema: crate::manifest::SCHEMA,
        db_name: job.db_name.clone(),
        owner: survey.owner,
        database_id: job.database_id,
        server_id: job.server_id,
        taken_at: chrono::Utc::now(),
        server_version: survey.server_version,
        client_version: client_version().await,
        properties: survey.properties,
        extensions: survey.extensions,
        hazards: survey.hazards,
    };

    let summary = {
        let h = &manifest.hazards;
        format!(
            "{} table(s), {} extension(s); RLS {}, FORCE-RLS {}, policies {}, \
             non-owner grants {}, SECURITY DEFINER {}, foreign servers {}, event triggers {}",
            h.rls_tables.len(),
            manifest.extensions.len(),
            h.rls_tables.len(),
            h.force_rls_tables.len(),
            h.policies.len(),
            h.non_owner_grants.len(),
            h.security_definer_functions.len(),
            h.foreign_servers.len(),
            h.event_triggers.len(),
        )
    };
    log.step("survey", summary).await;

    match serde_json::to_vec(&manifest) {
        Ok(bytes) => {
            // Display copy for the portal. The authoritative one is the copy
            // going into the sealed header; this is only so the page can show
            // contents without the key, and it is never read for a safety
            // decision.
            let display = serde_json::to_value(&manifest).ok();
            if let Err(e) = sqlx::query("UPDATE backups SET manifest = $2 WHERE id = $1")
                .bind(job.id)
                .bind(display)
                .execute(&state.db)
                .await
            {
                tracing::warn!("could not record the display manifest for {}: {e}", job.db_name);
            }
            bytes
        }
        Err(e) => {
            log.step("survey", format!("could not be serialised: {e}")).await;
            Vec::new()
        }
    }
}

/// The local `pg_dump` version, for the job log — restore compatibility is a
/// version question, so the answer belongs in the record.
async fn client_version() -> String {
    match tokio::process::Command::new("pg_dump").arg("--version").output().await {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(e) => format!("pg_dump unavailable ({e})"),
    }
}

/// Dump Cryptarch's own metadata database (CRYPTARCH-62).
///
/// Deliberately not routed through a `DbEngine`: the metadata database is not
/// provisioned, has no owner role to `SET ROLE` to, and lives on whatever
/// server the panel's own DSN points at. It gets the same sealing, checksum and
/// history as any tenant backup, because a box that dies takes the ledger of
/// who-owns-what with it otherwise.
async fn metadata_dump(state: &crate::web::AppState) -> anyhow::Result<crate::engine::DumpStream> {
    let dsn = state
        .metadata_dsn
        .as_deref()
        .context("metadata DSN not available for backup")?;
    let db = crate::engine::postgres::database_in_dsn(dsn)
        .context("metadata DSN names no database")?;
    let child = crate::engine::postgres::dump_command(dsn, &db, None)?
        .spawn()
        .context("spawning pg_dump for the metadata database")?;
    crate::engine::DumpStream::new(child)
}

/// The reserved history name for Cryptarch's own metadata database.
///
/// Collision-proof by construction: `names::valid_db_name` requires a leading
/// lowercase letter, so no tenant database can ever be called this.
pub const METADATA_DB: &str = "_cryptarch_meta";

/// How the scheduler is configured. Zero interval disables the loop entirely,
/// matching the health loop's convention.
#[derive(Debug, Clone, Copy)]
pub struct Schedule {
    pub interval_secs: u64,
    /// Successful backups to keep per database; 0 keeps everything.
    pub keep: i64,
    /// Alert when a database's newest successful backup is older than this;
    /// 0 disables the staleness check.
    pub stale_after_secs: u64,
    /// Whether this pass does BACKUP work at all.
    ///
    /// The loop also carries maintenance that is not a backup concern — see
    /// [`run_loop`] — so it runs in configurations where backups are off or
    /// driven externally, and this says which half applies.
    pub backups_enabled: bool,
}

/// How often the loop ticks when it is running for maintenance alone.
///
/// Only bounds how long a stranded row waits, so it does not need to be
/// aggressive; it needs to be a number rather than "next restart".
pub const MAINTENANCE_INTERVAL_SECS: u64 = 300;

/// Background maintenance loop (CRYPTARCH-61, CRYPTARCH-80).
///
/// # It is not only a backup loop, and it must not be gated like one
///
/// This started as the backup scheduler, and the stranded-delete sweep lives
/// on its pass because a periodic loop already existed here. That is a good
/// reason to *write* it here and a bad reason for its liveness to depend on
/// backups being enabled — it is a `databases` lifecycle concern, not a backup
/// concern.
///
/// Two supported configurations switch backups off: `CRYPTARCH_BACKUP_DIR`
/// unset, and `interval_secs = 0` with backups driven by external cron via
/// `cryptarch backup --all`. Gated on backups, the sweep would never run in
/// either, so a delete that failed at its first step would leave a live
/// database holding a quota slot and out of the backup schedule **permanently**
/// rather than for one interval — invisible to the login report too, because
/// its role is still enabled. The externally-driven case is the sharp one:
/// backups genuinely are running, and `deleting` is excluded from the CLI's
/// target list as well.
///
/// So the loop starts whenever the process is serving, and each half of the
/// pass is gated separately.
pub async fn run_loop(
    state: crate::web::AppState,
    schedule: Schedule,
    notifier: crate::health::Notifier,
) {
    let interval = std::time::Duration::from_secs(schedule.interval_secs);
    // Edge-triggered alerting: remembering which databases are currently
    // unhealthy is what turns "no backup for 3 days" into one notification
    // rather than one per sweep.
    let mut alerted: std::collections::HashSet<String> = std::collections::HashSet::new();
    loop {
        tokio::time::sleep(interval).await;
        sweep(&state, schedule, &notifier, &mut alerted).await;
    }
}

/// One pass, exposed so tests can drive it directly rather than waiting on a
/// timer — including with `backups_enabled: false`, which is the configuration
/// the maintenance half must survive.
pub async fn run_one_pass(
    state: &crate::web::AppState,
    schedule: Schedule,
    notifier: &crate::health::Notifier,
    alerted: &mut std::collections::HashSet<String>,
) {
    sweep(state, schedule, notifier, alerted).await
}

/// One scheduled pass: back everything up, prune, then alert on what looks bad.
async fn sweep(
    state: &crate::web::AppState,
    schedule: Schedule,
    notifier: &crate::health::Notifier,
    alerted: &mut std::collections::HashSet<String>,
) {
    // Before anything else: release locks held by jobs that died without
    // saying so, or this pass skips those databases forever.
    if let Err(e) = sweep_abandoned(&state.db).await {
        tracing::error!("abandoned-job sweep failed: {e:#}");
    }
    // Restores too (CRYPTARCH-113). Their `running` row is the per-target lock
    // in exactly the same way, they are spawned-and-dropped in exactly the same
    // way, and until now their only recovery was a boot-time sweep — so a
    // wedged restore blocked that database until someone restarted the process.
    if let Err(e) = crate::restore::sweep_abandoned(&state.db).await {
        tracing::error!("abandoned-restore sweep failed: {e:#}");
    }

    // BEFORE choosing backup targets, not after (CRYPTARCH-80). A delete that
    // failed at its very first step leaves a fully working database in the
    // `deleting` status and therefore out of `scheduled_targets`. Reverting it
    // here means it rejoins the schedule on THIS pass rather than the next
    // one, so a single missed backup is the worst case rather than two.
    //
    // Periodic, deliberately, not boot-only like the neighbouring sweeps: the
    // harm accrues while the row is stranded, so a boot sweep would bound the
    // exposure by process uptime, which is not a number.
    match crate::repair::sweep_stranded_deletes(&state.db, &state.servers).await {
        Ok(0) => {}
        Ok(n) => tracing::info!("stranded-delete sweep: returned {n} database(s) to active"),
        Err(e) => tracing::error!("stranded-delete sweep failed: {e:#}"),
    }

    // Human obligations, aged and alerted. Edge-triggered like backup
    // staleness, and OUTSIDE the backups gate for the same reason the sweep
    // is: an unfinished delete is a `databases` lifecycle concern, and the
    // configurations that switch backups off are exactly the ones where it
    // would otherwise never be mentioned again.
    for item in crate::repair::outstanding_work(&state.db, schedule.stale_after_secs).await {
        if alerted.insert(item.what.clone()) {
            crate::provision::audit(
                &state.db,
                "system",
                "outstanding_work",
                Some(&item.what),
                Some(&item.detail),
            )
            .await;
            notifier
                .send(&crate::health::Transition {
                    server: item.what.clone(),
                    check: "outstanding_work",
                    failed: true,
                    detail: item.detail.clone(),
                })
                .await;
        }
    }

    if !schedule.backups_enabled {
        return;
    }

    for name in scheduled_targets(&state.db).await {
        // Checked per database, not once per pass: a pass over a dozen
        // databases outlasts any shutdown, and the drain only waits for the
        // job in hand (CRYPTARCH-123). Prune is skipped too — cheap to defer,
        // and not worth interrupting halfway. The skipped work waits for the
        // next pass, which is one full interval after the next boot.
        if state.jobs.is_closing() {
            tracing::info!("shutting down — leaving the rest of this backup pass for the next one");
            return;
        }
        // Sequential on purpose: this runs on the same box as the databases,
        // and dumping all of them at once is how a backup sweep turns into an
        // outage.
        // Matched, not `Ok(_)`: a wildcard here would silently absorb
        // `Unrecorded`, which is exactly the collapse CRYPTARCH-85 removed
        // from `Outcome` in the first place. The scheduler is the caller with
        // nobody watching an exit code, so its log line is the only place an
        // unrecorded backup surfaces before the staleness alert fires.
        match run_now(state, "system", &name).await {
            Ok(Outcome::Ok { .. }) => {}
            Ok(Outcome::Unrecorded { detail, .. }) => {
                tracing::error!("scheduled backup of '{name}' sealed but was not recorded: {detail}");
            }
            Ok(Outcome::Failed { .. }) => {}
            // `run_now` refused because shutdown began between the check above
            // and its own registration. Nothing was claimed.
            Err(EnqueueError::ShuttingDown) => return,
            Err(EnqueueError::AlreadyRunning) => {
                tracing::info!("skipping scheduled backup of '{name}' — one is already running");
            }
            Err(e) => tracing::warn!("scheduled backup of '{name}' could not start: {e}"),
        }
    }

    if let Err(e) = prune(state, schedule.keep).await {
        tracing::error!("backup retention pass failed: {e:#}");
    }

    for t in assess(&state.db, schedule.stale_after_secs, alerted).await {
        crate::provision::audit(
            &state.db,
            "system",
            if t.failed { "backup_alert" } else { "backup_recovered" },
            Some(&t.server),
            Some(&t.detail),
        )
        .await;
        notifier.send(&t).await;
    }
}

/// Everything a scheduled sweep backs up: every provisioned database, plus
/// Cryptarch's own metadata database.
pub async fn scheduled_target_names(db: &sqlx::PgPool) -> Vec<String> {
    scheduled_targets(db).await
}

async fn scheduled_targets(db: &sqlx::PgPool) -> Vec<String> {
    let mut names: Vec<String> = sqlx::query_scalar(
        // Live databases only. A `restoring` row is a name reservation whose
        // database is mid-load — dumping it would back up a half-restored
        // state — and an `aside` copy is retained for undo, not for protecting
        // again at the cost of storage and a retention slot.
        sqlx::AssertSqlSafe(format!(
            "SELECT name FROM databases WHERE {} ORDER BY name",
            crate::status::DbStatus::should_be_backed_up_sql()
        )),
    )
        .fetch_all(db)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("listing databases for scheduled backup: {e}");
            Vec::new()
        });
    names.push(METADATA_DB.to_string());
    names
}

/// Compare each database's newest backup against the staleness budget and
/// return only the CHANGES since the last pass.
///
/// Edge-triggered like the health loop: a database that has been stale for a
/// week should have produced one alert, not one per sweep.
async fn assess(
    db: &sqlx::PgPool,
    stale_after_secs: u64,
    alerted: &mut std::collections::HashSet<String>,
) -> Vec<crate::health::Transition> {
    if stale_after_secs == 0 {
        return Vec::new();
    }
    // Grouped on IDENTITY, not name, and orphans excluded (CRYPTARCH-86).
    //
    // Grouping on `db_name` let a live database inherit a DEAD one's
    // freshness: take a recycled name, have every backup fail, and the
    // previous owner's two-day-old row held the verdict inside budget. No
    // alert, for as long as her rows stayed young enough. That is worse than
    // the retention hole it sat next to — retention destroys data, which is
    // visible and audited, while this SILENCES the alert that would say
    // anything is wrong at all, including the backstop the unrecorded-backup
    // path in CRYPTARCH-85 leans on.
    //
    // Orphans get no verdict here, and that is a decision rather than a
    // side effect of the WHERE. A deleted database can never take another
    // backup, so "stale" is not a condition it can leave — it would alert
    // once and then forever, which is noise, not signal. Alerting needs a
    // condition someone can act on. The operator's copies are made visible by
    // the orphan list instead, and if their DISK is the worry that is a size
    // question, not a freshness one.
    //
    // `min(db_name)` is load-bearing, not clutter: the group key is now the
    // identity, so `db_name` is no longer functionally dependent on it and a
    // bare reference is rejected by Postgres. A partition is one database, so
    // the aggregate picks the only value there is. Do not "simplify" it back.
    let rows = sqlx::query_as::<_, (String, Option<chrono::DateTime<chrono::Utc>>, Option<String>)>(
        "SELECT min(db_name), \
                max(created_at) FILTER (WHERE status = 'ok'), \
                (array_agg(status ORDER BY created_at DESC))[1] \
         FROM backups \
         WHERE database_id IS NOT NULL OR db_name = $1 \
         GROUP BY COALESCE(database_id::text, db_name)",
    )
    .bind(METADATA_DB)
    .fetch_all(db)
    .await
    .unwrap_or_else(|e| {
        tracing::error!("reading backup freshness: {e}");
        Vec::new()
    });

    let budget = chrono::Duration::seconds(stale_after_secs as i64);
    let now = chrono::Utc::now();
    let verdicts = rows
        .into_iter()
        .map(|(name, newest_ok, _latest_status)| (name, classify(now, budget, newest_ok)));
    transitions(verdicts, alerted)
}

/// Turn per-database verdicts into only the CHANGES, updating what is currently
/// alerted.
///
/// Separated from the query so the edge-triggering can be tested directly: a
/// database stale for a week must produce one notification, not one per sweep,
/// and that is bookkeeping, not SQL.
fn transitions(
    verdicts: impl Iterator<Item = (String, Option<String>)>,
    alerted: &mut std::collections::HashSet<String>,
) -> Vec<crate::health::Transition> {
    let mut out = Vec::new();
    for (name, problem) in verdicts {
        match problem {
            Some(detail) if alerted.insert(name.clone()) => {
                out.push(crate::health::Transition {
                    server: name,
                    check: "backup",
                    failed: true,
                    detail,
                });
            }
            None if alerted.remove(&name) => {
                out.push(crate::health::Transition {
                    server: name,
                    check: "backup",
                    failed: false,
                    detail: String::new(),
                });
            }
            _ => {}
        }
    }
    out
}

/// Is this database's backup coverage a problem right now? `Some(reason)` if so.
///
/// Judged only on the newest SUCCESSFUL backup, deliberately: a failure on top
/// of a good recent backup is worth logging but is not an emergency, while a
/// database whose last good backup has aged out is one whether or not anything
/// failed recently.
fn classify(
    now: chrono::DateTime<chrono::Utc>,
    budget: chrono::Duration,
    newest_ok: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<String> {
    match newest_ok {
        None => Some("no successful backup has ever completed".to_string()),
        Some(at) if now - at > budget => {
            Some(format!("newest good backup is {} old", human_duration(now - at)))
        }
        Some(_) => None,
    }
}

fn human_duration(d: chrono::Duration) -> String {
    let days = d.num_days();
    if days > 0 {
        return format!("{days} day{}", if days == 1 { "" } else { "s" });
    }
    let hours = d.num_hours();
    if hours > 0 {
        return format!("{hours} hour{}", if hours == 1 { "" } else { "s" });
    }
    let mins = d.num_minutes().max(1);
    format!("{mins} minute{}", if mins == 1 { "" } else { "s" })
}

/// Retention: keep the newest `keep` successful backups per database, delete
/// everything older along with its blob (CRYPTARCH-61).
///
/// Anchored on the Nth newest *successful* backup rather than on row count:
/// a run of failures must never age out the good backups behind them. `keep`
/// of 0 keeps everything.
/// Never delete a database's last restorable backup — for age, for count, for
/// policy, for anything (CRYPTARCH-82).
///
/// A SEPARATE GUARD over the delete set, deliberately not another branch in the
/// query above. Inside that SQL it would just be a fourth tier, free to be
/// wrong in the same way the rest of the rule can be wrong; out here, a bug in
/// the storage policy cannot route around it. The worst a broken policy can now
/// do is keep too much, or delete down to one restorable backup. Never to zero.
///
/// **Restorable** means `status = 'ok'` AND the blob is actually on disk. That
/// used to need a preference order — verified, else sealed-ok, else present —
/// because `ok` meant two different things depending on a config flag. Making
/// verification mandatory (CRYPTARCH-68) collapsed that to one test.
///
/// **Protects by rank with a floor, not by row identity**, and that is the
/// TOCTOU fix rather than a style choice. Pinning "keep row X" leaves a window:
/// X's blob can vanish between the check and the deletes, and the pass then
/// removes the others and reports success with nothing left. So a partition
/// holding exactly one restorable backup is skipped ENTIRELY this pass — no
/// transaction can close that gap, because the filesystem is not in it.
///
/// Partitioned on `db_name`, which is sound here only because the query above
/// already excluded orphans and live names are unique. It would be wrong on the
/// raw table.
async fn protect_last_restorable(
    state: &crate::web::AppState,
    root: &Path,
    doomed: Vec<(uuid::Uuid, String, Option<String>)>,
) -> Vec<(uuid::Uuid, String, Option<String>)> {
    let mut names: Vec<&str> = doomed.iter().map(|(_, n, _)| n.as_str()).collect();
    names.sort_unstable();
    names.dedup();

    let mut protected: std::collections::HashSet<uuid::Uuid> = std::collections::HashSet::new();
    let mut frozen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for name in names {
        let rows = sqlx::query_as::<_, (uuid::Uuid, Option<String>)>(
            "SELECT id, path FROM backups \
             WHERE db_name = $1 AND status = 'ok' \
               AND (database_id IS NOT NULL OR db_name = $2) \
             ORDER BY created_at DESC",
        )
        .bind(name)
        .bind(METADATA_DB)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        let mut restorable = Vec::new();
        for (id, path) in rows {
            // Stat it. The row saying a backup exists and the backup existing
            // are different claims, and this is the pass that acts on the
            // difference.
            match locate_blob(root, name, id, path.as_deref()).await {
                Ok(Some(_)) => restorable.push(id),
                Ok(None) => {}
                // Could not even ask — a stored path that fails validation.
                // Counted as restorable on purpose: the failure mode of
                // guessing "absent" here is deleting the last good backup,
                // and the failure mode of guessing "present" is keeping one
                // file too many.
                Err(e) => {
                    tracing::warn!("retention: cannot check the blob for {id} ({name}): {e}");
                    restorable.push(id);
                }
            }
        }

        match restorable.len() {
            // Nothing restorable at all, so Rule 1 has nothing to protect and
            // freezing would only let failure rows — each carrying a full error
            // string — accumulate forever, which is the bug CRYPTARCH-61 fixed.
            // Prune normally, and say why it looks like this.
            0 => tracing::warn!(
                "retention: '{name}' has NO restorable backup. Pruning its failed rows by \
                 count; there is nothing here to restore from."
            ),
            // Exactly one. This partition is a single deletion away from having
            // nothing restorable, and that one blob could vanish between this
            // check and the deletes below — no transaction covers the
            // filesystem. So nothing here is pruned today.
            1 => {
                frozen.insert(name.to_string());
                tracing::warn!(
                    "retention: not pruning '{name}' — one restorable backup left. \
                     Backups are failing, or their files are missing."
                );
            }
            _ => {
                protected.insert(restorable[0]);
            }
        }
    }

    doomed
        .into_iter()
        .filter(|(id, name, _)| !protected.contains(id) && !frozen.contains(name))
        .collect()
}

pub async fn prune(state: &crate::web::AppState, keep: i64) -> anyhow::Result<u64> {
    if keep <= 0 {
        return Ok(0);
    }
    let Some(root) = state.backup_dir.as_ref() else {
        return Ok(0);
    };

    // Two populations, and the second one used to be missed entirely: an inner
    // JOIN on the success cutoff drops every database that has NEVER succeeded,
    // so its failure rows — each carrying a full error string — accumulated
    // forever. That is precisely the database you least want quietly filling a
    // table. A LEFT JOIN plus the rn fallback prunes those by count.
    //
    // Never delete a job that is still writing its file.
    //
    // PARTITIONED ON IDENTITY, NOT NAME (CRYPTARCH-86). Partitioning on
    // `db_name` put a deleted database's backups in the same partition as
    // whoever took its name next: once the new tenant reached `keep`
    // successes, the previous owner's rows fell below the cutoff and this pass
    // deleted them and unlinked their blobs. The operator's copies destroyed
    // as a side effect of an unrelated tenant's ordinary schedule — nothing
    // chosen, nobody told. It ran backwards too, with a stranger's backups
    // occupying the live tenant's cutoff ranking.
    //
    // `scoped` therefore EXCLUDES orphans entirely. Backups whose database has
    // been deleted are the operator's, and the only thing that removes them is
    // an explicit purge. That is what makes "the operator's copy is permanent"
    // true rather than aspirational.
    //
    // The exception is `_cryptarch_meta`, which has NULL `database_id` because
    // it has no `databases` row at all (see `claim`) — it is not an orphan, and
    // excluding it would let the metadata backups grow without bound. NULL
    // means two different things here, so the predicate names both.
    let doomed = sqlx::query_as::<_, (uuid::Uuid, String, Option<String>)>(
        "WITH scoped AS ( \
             SELECT id, db_name, path, created_at, status, \
                    COALESCE(database_id::text, db_name) AS part \
             FROM backups \
             WHERE database_id IS NOT NULL OR db_name = $2 \
         ), cutoff AS ( \
             SELECT part, min(created_at) AS oldest_kept FROM ( \
                 SELECT part, created_at, \
                        row_number() OVER (PARTITION BY part ORDER BY created_at DESC) AS rn \
                 FROM scoped WHERE status = 'ok' \
             ) ranked WHERE rn <= $1 GROUP BY part \
         ), ranked_all AS ( \
             SELECT id, db_name, path, created_at, part, \
                    row_number() OVER (PARTITION BY part ORDER BY created_at DESC) AS rn \
             FROM scoped WHERE status <> 'running' \
         ) \
         SELECT a.id, a.db_name, a.path FROM ranked_all a \
         LEFT JOIN cutoff c USING (part) \
         WHERE ((c.oldest_kept IS NOT NULL AND a.created_at < c.oldest_kept) \
             OR (c.oldest_kept IS NULL AND a.rn > $1)) \
           AND NOT EXISTS (SELECT 1 FROM restores r \
                           WHERE r.backup_id = a.id AND r.status = 'running')",
    )
    .bind(keep)
    .bind(METADATA_DB)
    .fetch_all(&state.db)
    .await
    .context("selecting backups to prune")?;

    let doomed = protect_last_restorable(state, root, doomed).await;

    let mut pruned = 0;
    for (id, db_name, path) in doomed {
        // File first: a row deleted before its blob leaks the file with nothing
        // left pointing at it. The reverse just retries next pass.
        //
        // Resolved through `locate_blob`, NOT through `path` alone (CRYPTARCH-87).
        // A NULL path does not mean "there is no file". An unrecorded backup
        // (CRYPTARCH-85) deliberately KEEPS its blob, and `path` is written by
        // exactly one statement — the one that just failed — so the surviving row
        // has a file on disk and no way to name it. Pruning that row on the
        // strength of `path` being NULL deleted the last record of a file nobody
        // could subsequently find: unlistable, invisible in the portal, and
        // reclaimable only by someone with shell access to the mount. Every
        // unrecorded backup leaked exactly one full-size dump, permanently.
        //
        // Matching on the id embedded in the filename is safe for a destructive
        // pass because the id is the row's primary key: it can only ever match
        // this backup's own blob, never another tenant's in a reused directory.
        // That is the same reasoning `purge_operator_backup` records — reading
        // the directory to FIND a file is fine, only the deletion is per-file.
        let found = match locate_blob(root, &db_name, id, path.as_deref()).await {
            Ok(f) => f,
            Err(e) => {
                // The stored path is untrusted input on this side too — this is
                // the pass that DELETES files, unattended, on a schedule.
                tracing::error!("retention: refusing to act on stored path for {db_name}: {e}");
                continue;
            }
        };
        if let Some(abs) = found {
            match tokio::fs::remove_file(&abs).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::warn!("retention: could not delete {} ({e}) — keeping its row", abs.display());
                    continue;
                }
            }
        }
        if let Err(e) = sqlx::query("DELETE FROM backups WHERE id = $1")
            .bind(id)
            .execute(&state.db)
            .await
        {
            tracing::warn!("retention: deleted blob for {db_name} but not its row: {e}");
            continue;
        }
        pruned += 1;
    }
    if pruned > 0 {
        tracing::info!("retention: pruned {pruned} backup(s) beyond the newest {keep}");
    }
    Ok(pruned)
}

/// Resolve a stored relative path under `root`, refusing anything that escapes.
///
/// `path` is a text column, and `Path::join` REPLACES the base when handed an
/// absolute path — so without this, anyone who can write the metadata database
/// turns the unattended retention pass into an arbitrary-file-delete running as
/// the app user. Today `path` is only ever written by `blob_path`, making that
/// safe by construction; this makes it safe by check, which is the version that
/// survives a second writer being added.
/// One backup left behind by a deleted database, for the operator's list.
#[derive(sqlx::FromRow)]
pub struct OperatorBackup {
    pub id: uuid::Uuid,
    pub db_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: String,
    /// What the row CLAIMS the blob weighs. Shown next to whether the file is
    /// actually there, because the two disagreeing is how an operator finds out
    /// CRYPTARCH-87 happened to them.
    pub size_bytes: Option<i64>,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub path: Option<String>,
}

/// What a purge actually did. Two outcomes, kept apart on purpose: "deleted the
/// row and its blob" and "deleted the row, and there was no blob to delete" are
/// different facts, and the second is the operator's only signal that a backup
/// lost its file (CRYPTARCH-87). Collapsing them into "purged" would report a
/// clean reclaim for a file still sitting on the disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purged {
    WithBlob,
    RowOnlyNoBlobFound,
}

/// Every backup whose database has been deleted, newest first.
///
/// Reads the `operator_backups` VIEW rather than restating its predicate -- see
/// migration 0019 for why that is a view and not a helper.
pub async fn operator_backups(db: &sqlx::PgPool) -> Result<Vec<OperatorBackup>, sqlx::Error> {
    sqlx::query_as::<_, OperatorBackup>(
        "SELECT id, db_name, created_at, status, size_bytes, verified_at, path \
         FROM operator_backups ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await
}

/// The operator's backups, each paired with whether its blob is actually on
/// disk, plus the two totals.
///
/// BOTH numbers, deliberately. The recorded total comes from `size_bytes` and
/// over-reports when a file has gone missing; a total measured by stat alone
/// would under-report and quietly hide the same fact. Showing the recorded size
/// beside "file missing" is how an operator finds out a backup lost its blob
/// (CRYPTARCH-87) rather than inferring it from a number that looks plausible.
///
/// This list is load-bearing beyond tidiness: it is the reason orphans are
/// given no staleness verdict. A deleted database can never take another
/// backup, so "stale" is not a condition it can leave and alerting on it would
/// fire once and then forever — the question these backups actually raise is
/// how much disk they hold, and this is where that gets answered.
///
/// Whether a file is present is `None` when it could not be looked for — an
/// unreadable directory, or no backup directory configured. That is counted
/// apart from "missing": reporting "file missing, purging reclaims no space"
/// about a file nobody could look for is a guess dressed as a finding.
pub struct OperatorBackups {
    pub rows: Vec<(OperatorBackup, Option<bool>)>,
    pub recorded_bytes: i64,
    pub missing: usize,
    pub unchecked: usize,
}

pub async fn operator_backups_view(state: &crate::web::AppState) -> Result<OperatorBackups, sqlx::Error> {
    let rows = operator_backups(&state.db).await?;
    let mut out = Vec::with_capacity(rows.len());
    let mut recorded_bytes = 0i64;
    let (mut missing, mut unchecked) = (0usize, 0usize);
    for row in rows {
        recorded_bytes += row.size_bytes.unwrap_or(0);
        let present = match state.backup_dir.as_ref() {
            Some(root) => match locate_blob(root, &row.db_name, row.id, row.path.as_deref()).await {
                Ok(found) => Some(found.is_some()),
                Err(e) => {
                    tracing::warn!("looking for the blob of backup {}: {e:#}", row.id);
                    None
                }
            },
            None => None,
        };
        match present {
            Some(false) => missing += 1,
            None => unchecked += 1,
            Some(true) => {}
        }
        out.push((row, present));
    }
    Ok(OperatorBackups { rows: out, recorded_bytes, missing, unchecked })
}

/// Why a purge of an operator-owned backup did not happen.
#[derive(Debug, thiserror::Error)]
pub enum PurgeError {
    #[error("backups are not configured on this deployment")]
    Disabled,
    #[error("no backup left behind by a deleted database has that id")]
    NotFound,
    #[error("a restore is reading this backup right now")]
    RestoreRunning,
    #[error(transparent)]
    Failed(#[from] anyhow::Error),
}

/// Delete one operator-owned backup and its blob.
///
/// SCOPED THROUGH THE VIEW, not by id alone. A purge that took an id and
/// deleted it would destroy a LIVE tenant's backup given a stale or guessed id
/// -- and this is the one action in the system whose whole job is deletion, so
/// the narrowing belongs in the statement rather than in the caller's care.
///
/// PER FILE, NEVER PER DIRECTORY. Blobs live under a directory named after the
/// database (`blob_path`), and until backups are keyed by id on disk that
/// directory can also hold the blobs of a LIVE database that reused the name.
/// `remove_dir_all` on it is the cheapest thing to write, looks obviously
/// right, and deletes the current tenant's backups. Reading the directory to
/// FIND a file is fine and necessary (see `locate_blob`); only the destructive
/// step is per-file.
///
/// ROW AND FILE SHARE ONE FATE (CRYPTARCH-147). The row is deleted and the
/// purge audited inside a transaction; the file is removed while that
/// transaction is still open, and only then does it commit. A file that cannot
/// be removed rolls the row back, so the backup is still listed and the purge
/// can be tried again. This used to run file first, row second, and a row
/// delete that failed (it always did for a backup that had been restored from,
/// until migration 0024) left a row for a file that no longer existed. The one
/// window left is a commit that fails after the unlink: that row then reads
/// "file missing" on the operator's page and purges as row-only.
pub async fn purge_operator_backup(
    state: &crate::web::AppState,
    actor: &str,
    id: uuid::Uuid,
) -> Result<Purged, PurgeError> {
    let root = state.backup_dir.as_ref().ok_or(PurgeError::Disabled)?;

    let mut tx = state.db.begin().await.context("opening the purge transaction")?;
    // Locked, so two purges of one backup serialise here and the second finds
    // nothing rather than auditing a second purge.
    let (db_name, path) = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT db_name, path FROM backups \
         WHERE id IN (SELECT id FROM operator_backups WHERE id = $1) FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .context("looking up the backup to purge")?
    .ok_or(PurgeError::NotFound)?;

    // Nothing can START a restore from an operator-owned backup (`restore::
    // enqueue` scopes by database id), but one already running keeps reading it.
    let reading: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM restores WHERE backup_id = $1 AND status = 'running')",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .context("checking for a restore reading the backup")?;
    if reading {
        return Err(PurgeError::RestoreRunning);
    }

    let found = locate_blob(root, &db_name, id, path.as_deref()).await?;
    let deleted = sqlx::query("DELETE FROM backups WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .context("deleting the purged backup row")?
        .rows_affected();
    // Cannot happen under the lock above; checked anyway, since a purge that
    // deleted nothing must not audit a purge.
    if deleted != 1 {
        return Err(PurgeError::NotFound);
    }
    let outcome = if found.is_some() { Purged::WithBlob } else { Purged::RowOnlyNoBlobFound };
    crate::provision::audit_in(
        &mut tx,
        actor,
        "backup_purged",
        Some(&db_name),
        Some(match outcome {
            Purged::WithBlob => "row and blob",
            Purged::RowOnlyNoBlobFound => "row only — no blob found on disk",
        }),
    )
    .await
    .context("auditing the purge")?;

    if let Some(abs) = &found {
        match tokio::fs::remove_file(abs).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Dropping `tx` rolls the row back: the file is still there.
            Err(e) => return Err(anyhow::anyhow!("removing {}: {e}", abs.display()).into()),
        }
    }
    if let Err(e) = tx.commit().await {
        tracing::error!(
            "purging backup {id} of {db_name}: the file is removed but the row could not be \
             deleted ({e}); it will show as file missing and can be purged again"
        );
        return Err(anyhow::Error::from(e).context("committing the purge").into());
    }
    Ok(outcome)
}

/// A file on the backup mount that no `backups` row can reach (CRYPTARCH-93).
pub struct UnreferencedFile {
    /// Path relative to the backup root — what the operator sees, and the only
    /// handle the purge action accepts.
    pub rel: String,
    pub size_bytes: u64,
    /// The backup id parsed out of the filename. `None` means the name did not
    /// have the shape `blob_path` writes, so nothing can be concluded about it.
    /// Those are listed and never offered for deletion.
    pub id: Option<uuid::Uuid>,
}

/// Walk the backup mount and report files that no row points at.
///
/// # Why this direction, and why it needs to exist at all
///
/// Every other pass in this module starts from `backups` and asks about the
/// file. None of them can see a file whose row is already gone — there is
/// nothing left to iterate from. This is the only pass that starts at the
/// FILESYSTEM and asks about the row, which is the only direction that can.
///
/// The source of such files is no longer prune (CRYPTARCH-87 closed that), but
/// a crash between unlinking a blob and deleting its row, an operator restoring
/// an older metadata database over a newer mount, or files placed by hand
/// during a recovery will all produce them.
///
/// # It reports; it does not delete
///
/// Deliberately no automatic sweep. The failure mode of getting this wrong is
/// deleting a backup a human put there during a recovery, which is exactly the
/// moment they can least afford it. Removal is a per-file operator action, and
/// only for files whose id parses and provably has no row.
///
/// A file whose name does not parse is reported rather than ignored: an
/// unrecognised file in the backup root is information, and silently skipping
/// it would make this listing quietly incomplete — the same "looks like
/// coverage" failure the rest of this arc kept finding.
pub async fn unreferenced_files(state: &crate::web::AppState) -> anyhow::Result<Vec<UnreferencedFile>> {
    let Some(root) = state.backup_dir.as_ref() else {
        return Ok(Vec::new());
    };

    // Blobs live one level down, under a directory named for the database.
    // Anything directly in the root is already unexpected, so it is collected
    // too rather than skipped.
    let mut found: Vec<(String, u64, Option<uuid::Uuid>)> = Vec::new();
    // A directory that cannot be read FAILS the scan. Skipping it returned a
    // shorter list that looked complete — "nothing unreferenced" from a scan
    // that could not see. Only a root that does not exist yet (no backup has
    // run) is empty.
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && dir == *root => break,
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        while let Some(entry) =
            entries.next_entry().await.with_context(|| format!("reading {}", dir.display()))?
        {
            let path = entry.path();
            // Async, unlike `Path::is_dir`, which stats on the runtime thread
            // (CRYPTARCH-124). And not following symlinks: a link cycle in the
            // backup root must not turn this walk into an infinite one.
            if entry.file_type().await.is_ok_and(|t| t.is_dir()) {
                dirs.push(path);
                continue;
            }
            let Ok(rel) = path.strip_prefix(root) else { continue };
            let rel = rel.to_string_lossy().replace('\\', "/");
            let size = entry.metadata().await.map(|m| m.len()).unwrap_or(0);
            found.push((rel, size, parse_blob_id(&path)));
        }
    }
    if found.is_empty() {
        return Ok(Vec::new());
    }

    // One query for every id seen, rather than one per file: this runs against
    // a mount that may hold thousands of blobs.
    let ids: Vec<uuid::Uuid> = found.iter().filter_map(|(_, _, id)| *id).collect();
    let known: std::collections::HashSet<uuid::Uuid> =
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM backups WHERE id = ANY($1)")
            .bind(&ids)
            .fetch_all(&state.db)
            .await
            .context("looking up which blobs still have rows")?
            .into_iter()
            .collect();

    let mut out: Vec<UnreferencedFile> = found
        .into_iter()
        // A file whose id HAS a row is referenced, whatever that row's `path`
        // column says — `locate_blob` reaches it by id. Comparing paths here
        // would report every pathless-but-recorded blob as garbage.
        .filter(|(_, _, id)| !id.is_some_and(|i| known.contains(&i)))
        .map(|(rel, size_bytes, id)| UnreferencedFile { rel, size_bytes, id })
        .collect();
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

/// The backup id embedded in a blob filename by [`blob_path`], if present.
///
/// `blob_path` writes `<stamp>-<uuid>.dump.zst.enc`, and the stamp format
/// (`%Y%m%dT%H%M%SZ`) contains no `-`, so the first `-` separates the two. A
/// UUID contains hyphens, which is why this splits on the FIRST one rather than
/// the last.
fn parse_blob_id(path: &Path) -> Option<uuid::Uuid> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".dump.zst.enc")?;
    let (_stamp, id) = stem.split_once('-')?;
    id.parse().ok()
}

/// Why an unreferenced file was not deleted.
#[derive(Debug, thiserror::Error)]
pub enum FilePurgeError {
    #[error("backups are not configured on this deployment")]
    Disabled,
    #[error("{0}")]
    BadPath(String),
    #[error(
        "refusing to delete a file whose name does not identify a backup — it was listed \
         so a human could look at it, not so it could be removed unexamined"
    )]
    Unrecognised,
    #[error("that file now has a backup row and is no longer unreferenced")]
    NowReferenced,
    #[error("there is no such file on the backup disk")]
    NotFound,
    #[error(transparent)]
    Failed(#[from] anyhow::Error),
}

/// Delete one unreferenced file, after re-establishing that it is one.
///
/// The check is repeated here rather than trusted from the listing: the
/// operator is acting on a page that was rendered earlier, and in between a row
/// could have appeared for that id. Acting on the stale view would delete a
/// live backup's blob.
pub async fn purge_unreferenced_file(
    state: &crate::web::AppState,
    actor: &str,
    rel: &str,
) -> Result<u64, FilePurgeError> {
    let root = state.backup_dir.as_ref().ok_or(FilePurgeError::Disabled)?;
    // `rel` arrives from a request body. safe_join is what stops it being an
    // absolute path or `../` walk that turns this into arbitrary file deletion
    // running as the app user.
    if rel.is_empty() || rel.len() > 4096 || rel.contains('\0') {
        return Err(FilePurgeError::BadPath("not a path inside the backup directory".into()));
    }
    let abs = safe_join(root, rel).map_err(|e| FilePurgeError::BadPath(e.to_string()))?;
    // safe_join checks the TEXT of the path; a directory symlink inside the
    // root still leads out of it, and `remove_file` follows it. The listing
    // never descends into a symlink, so a path through one was never offered:
    // the directory the file is in must really be under the root.
    let real_root = tokio::fs::canonicalize(root).await.context("resolving the backup directory")?;
    let real_dir = match abs.parent().map(tokio::fs::canonicalize) {
        Some(fut) => match fut.await {
            Ok(dir) => dir,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(FilePurgeError::NotFound),
            Err(e) => return Err(anyhow::anyhow!("resolving {}: {e}", abs.display()).into()),
        },
        None => return Err(FilePurgeError::BadPath("not a path inside the backup directory".into())),
    };
    if !real_dir.starts_with(&real_root) {
        return Err(FilePurgeError::BadPath(format!("'{rel}' leads outside the backup directory")));
    }

    let id = parse_blob_id(&abs).ok_or(FilePurgeError::Unrecognised)?;
    let still_unreferenced: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM backups WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .context("re-checking whether the blob has a row")?;
    if still_unreferenced.is_some() {
        return Err(FilePurgeError::NowReferenced);
    }

    let size = match tokio::fs::symlink_metadata(&abs).await {
        Ok(m) if m.is_file() || m.is_symlink() => m.len(),
        Ok(_) => return Err(FilePurgeError::Unrecognised),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(FilePurgeError::NotFound),
        Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", abs.display()).into()),
    };
    match tokio::fs::remove_file(&abs).await {
        Ok(()) => {}
        // Removed between the stat and here — by a second click, say. Not ours
        // to audit.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(FilePurgeError::NotFound),
        Err(e) => return Err(anyhow::anyhow!("removing {}: {e}", abs.display()).into()),
    }

    crate::provision::audit(
        &state.db,
        actor,
        "backup_file_purged",
        Some(rel),
        Some(&format!("{size} bytes, no backup row")),
    )
    .await;
    Ok(size)
}

/// Find a backup's blob on disk, whether or not its row remembers where it is.
///
/// Two ways in, and the second is the reason this function exists. The stored
/// `path` is the ordinary answer. But a backup that sealed cleanly and then
/// failed to record itself (CRYPTARCH-85's `Unrecorded`) has a NULL `path`,
/// because `record_success` -- the call that just failed -- is the only writer
/// of that column. Its blob is on disk and nothing points at it, which is
/// CRYPTARCH-87.
///
/// It is still findable, because `blob_path` puts the backup id -- the row's
/// primary key -- in the filename. Scanning the database's directory for the
/// entry ending `-{id}.dump.zst.enc` identifies it exactly; a UUID suffix
/// cannot match the wrong file, including when the directory also holds a
/// LIVE tenant's blobs under a recycled name. That property was added to
/// `blob_path` for collision avoidance and turns out to double as the recovery
/// key.
///
/// DO NOT be tempted to rebuild the path as `blob_path(db_name, id,
/// created_at)`. `run_job` stamps the filename with a timestamp it takes in the
/// worker, NOT the row's `created_at`, which the database set earlier when
/// `claim` inserted it -- they differ by the claim-to-run gap, so a
/// reconstruction points at a file that was never written. It looks right, and
/// the fixture in the test suite reconstructs exactly that way and passes,
/// because it writes the file and the row from the same value. Match on the id
/// suffix; never recompute the stamp.
///
/// `Ok(None)` means the blob is genuinely absent, which a caller must report
/// differently from having deleted one.
pub async fn locate_blob(
    root: &Path,
    db_name: &str,
    id: uuid::Uuid,
    path: Option<&str>,
) -> anyhow::Result<Option<PathBuf>> {
    // "Could not look" is an error, never `Ok(None)`: every caller treats
    // absent as permission to forget the backup (a purge records "no blob
    // found" and drops the row), and each already handles an error by keeping
    // it. An unreadable directory used to read as an absent file.
    if let Some(rel) = path {
        let abs = safe_join(root, rel)?;
        let exists = tokio::fs::try_exists(&abs).await.with_context(|| format!("checking {}", abs.display()))?;
        return Ok(exists.then_some(abs));
    }

    let dir = safe_join(root, db_name)?;
    let suffix = format!("-{id}.dump.zst.enc");
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    while let Some(entry) = entries.next_entry().await.with_context(|| format!("reading {}", dir.display()))? {
        if entry.file_name().to_string_lossy().ends_with(&suffix) {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn safe_join(root: &Path, rel: &str) -> anyhow::Result<PathBuf> {
    let candidate = Path::new(rel);
    anyhow::ensure!(candidate.is_relative(), "backup path '{rel}' is not relative");
    anyhow::ensure!(
        !candidate.components().any(|c| matches!(c, std::path::Component::ParentDir)),
        "backup path '{rel}' escapes the backup directory"
    );
    Ok(root.join(candidate))
}

/// Fail any backup left `running` by a previous process (CRYPTARCH-57).
///
/// A job's status is only advanced by the task running it, so a restart mid-dump
/// strands the row — and because the per-database lock is a partial unique index
/// on `running`, that database could never be backed up again. Runs at boot,
/// before anything can enqueue.
pub async fn sweep_stale(db: &sqlx::PgPool) -> anyhow::Result<u64> {
    let swept = sqlx::query(
        "UPDATE backups SET status = 'failed', finished_at = now(), \
         error = 'stale — interrupted by a restart' WHERE status = 'running'",
    )
    .execute(db)
    .await
    .context("sweeping stale backup jobs")?
    .rows_affected();
    if swept > 0 {
        tracing::warn!("marked {swept} interrupted backup job(s) failed");
    }
    Ok(swept)
}

/// A job is presumed dead after this long. Generous next to a 1–5 GB dump; the
/// cost of being wrong is a duplicate backup, while the cost of never sweeping
/// is a database that can never be backed up again.
const ABANDONED_AFTER: chrono::TimeDelta = chrono::TimeDelta::hours(6);

/// Fail jobs that are still `running` long past any plausible runtime.
///
/// The boot sweep alone is not enough. `enqueue` spawns the job and drops the
/// handle, so a panic inside it is swallowed: the row stays `running`, and
/// because the per-database lock IS that row, the database can never be backed
/// up again — until the next restart, which on a homelab box may be months
/// away. This runs every scheduler pass, so the wedge lasts one interval
/// instead of until someone notices.
pub async fn sweep_abandoned(db: &sqlx::PgPool) -> anyhow::Result<u64> {
    let swept = sqlx::query(
        "UPDATE backups SET status = 'failed', finished_at = now(), \
         error = 'abandoned — no progress within the maximum runtime' \
         WHERE status = 'running' AND created_at < now() - $1::interval",
    )
    .bind(ABANDONED_AFTER)
    .execute(db)
    .await
    .context("sweeping abandoned backup jobs")?
    .rows_affected();
    if swept > 0 {
        tracing::warn!("marked {swept} abandoned backup job(s) failed (no progress in 6h)");
    }
    Ok(swept)
}

/// Where a backup blob lands, relative to the backup root.
///
/// Keyed by name *and* backup id: database names are freed on delete and
/// reusable, so a deleted `app` and a later new `app` both write under `app/`
/// and would otherwise be able to collide.
pub fn blob_path(db_name: &str, backup_id: uuid::Uuid, at: chrono::DateTime<chrono::Utc>) -> PathBuf {
    let stamp = at.format("%Y%m%dT%H%M%SZ");
    PathBuf::from(db_name).join(format!("{stamp}-{backup_id}.dump.zst.enc"))
}

async fn write_frame(
    out: &mut tokio::fs::File,
    hasher: &mut Sha256,
    written: &mut usize,
    frame: &[u8],
) -> anyhow::Result<()> {
    let len = u32::try_from(frame.len()).context("frame too large")?;
    write_all(out, hasher, written, &len.to_be_bytes()).await?;
    write_all(out, hasher, written, frame).await
}

async fn write_all(
    out: &mut tokio::fs::File,
    hasher: &mut Sha256,
    written: &mut usize,
    bytes: &[u8],
) -> anyhow::Result<()> {
    out.write_all(bytes).await.context("writing backup file")?;
    hasher.update(bytes);
    *written += bytes.len();
    Ok(())
}

/// Read one length-prefixed frame; `None` at a clean end of file.
async fn read_frame(f: &mut tokio::fs::File) -> anyhow::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    let n = read_full(f, &mut len_buf).await?;
    if n == 0 {
        return Ok(None);
    }
    if n < 4 {
        bail!("backup file ends mid-frame — it is truncated");
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    // The length prefix is read before any key is involved, so it is attacker-
    // controlled input driving an allocation. A legitimate frame cannot exceed
    // one plaintext frame plus nonce and tag.
    if len > MAX_FRAME_ON_DISK {
        bail!("backup file declares an implausible frame length ({len} bytes) — it is corrupt");
    }
    let mut frame = vec![0u8; len];
    if read_full(f, &mut frame).await? != len {
        bail!("backup file ends mid-frame — it is truncated");
    }
    Ok(Some(frame))
}

/// Fill `buf` unless the source ends first. A single `read` may return a short
/// count on a pipe for reasons that have nothing to do with EOF, and treating
/// that as the end of the dump would silently back up a fraction of it.
async fn read_full<R: AsyncRead + Unpin>(src: &mut R, buf: &mut [u8]) -> anyhow::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = src.read(&mut buf[filled..]).await.context("reading dump stream")?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Backups are readable by their owner only — they contain every row of a
/// tenant database, sealed but still not something to leave world-readable on a
/// shared host mount.
async fn restrict_permissions(file: &tokio::fs::File) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await
            .context("restricting backup file permissions")?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto() -> Crypto {
        Crypto::from_hex_key(&"ab".repeat(32)).unwrap()
    }

    async fn roundtrip(payload: &[u8]) -> Vec<u8> {
        let dir = tempdir();
        let path = dir.join("blob.enc");
        let c = crypto();
        let id = uuid::Uuid::new_v4();
        seal_stream(&c, id, payload, &path).await.unwrap();
        let mut out = Vec::new();
        open_stream(&c, id, &path, &mut out).await.unwrap();
        out
    }

    fn tempdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("cryptarch-bak-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn roundtrips_empty_and_small_payloads() {
        assert_eq!(roundtrip(b"").await, b"");
        assert_eq!(roundtrip(b"pgdump bytes").await, b"pgdump bytes");
    }

    #[tokio::test]
    async fn roundtrips_across_frame_boundaries() {
        // Exactly one frame, and one frame plus a byte — the boundary where a
        // lookahead bug would show up.
        for len in [FRAME_SIZE, FRAME_SIZE + 1, FRAME_SIZE * 2 + 7] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(roundtrip(&payload).await, payload, "len {len}");
        }
    }

    #[tokio::test]
    async fn checksum_and_size_describe_the_sealed_file() {
        let dir = tempdir();
        let path = dir.join("blob.enc");
        let sealed = seal_stream(&crypto(), uuid::Uuid::new_v4(), &b"hello"[..], &path).await.unwrap();
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(sealed.size_bytes as usize, on_disk.len());
        assert_eq!(sealed.checksum, hex(&Sha256::digest(&on_disk)));
    }

    #[tokio::test]
    async fn truncated_blob_fails_instead_of_restoring_a_prefix() {
        let dir = tempdir();
        let path = dir.join("blob.enc");
        let c = crypto();
        // Two frames' worth, so dropping the tail still leaves a valid-looking
        // first frame behind.
        let payload: Vec<u8> = (0..FRAME_SIZE * 2).map(|i| (i % 251) as u8).collect();
        let id = uuid::Uuid::new_v4();
        seal_stream(&c, id, &payload[..], &path).await.unwrap();

        let full = std::fs::read(&path).unwrap();
        // Cut the final frame off at a frame boundary: header + len + frame1.
        let aux_len = u32::from_be_bytes(full[21..25].try_into().unwrap()) as usize;
        let header_len = V2_HEADER_FIXED + aux_len;
        let frame1_len =
            u32::from_be_bytes(full[header_len..header_len + 4].try_into().unwrap()) as usize;
        std::fs::write(&path, &full[..header_len + 4 + frame1_len]).unwrap();

        let mut out = Vec::new();
        let err = open_stream(&c, id, &path, &mut out).await.unwrap_err();
        assert!(
            err.to_string().contains("failed to decrypt"),
            "expected an authentication failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn wrong_key_fails_to_open() {
        let dir = tempdir();
        let path = dir.join("blob.enc");
        let id = uuid::Uuid::new_v4();
        seal_stream(&crypto(), id, &b"secret"[..], &path).await.unwrap();
        let other = Crypto::from_hex_key(&"cd".repeat(32)).unwrap();
        let mut out = Vec::new();
        assert!(open_stream(&other, id, &path, &mut out).await.is_err());
    }

    #[tokio::test]
    async fn rejects_a_file_that_is_not_a_backup() {
        let dir = tempdir();
        let path = dir.join("nope.enc");
        std::fs::write(&path, b"just some bytes here").unwrap();
        let mut out = Vec::new();
        let err = open_stream(&crypto(), uuid::Uuid::new_v4(), &path, &mut out).await.unwrap_err();
        assert!(err.to_string().contains("not a Cryptarch backup"));
    }

    #[test]
    fn staleness_is_judged_on_the_newest_successful_backup() {
        let now = chrono::Utc::now();
        let budget = chrono::Duration::hours(48);

        assert!(
            classify(now, budget, None).unwrap().contains("no successful backup"),
            "a database with no good backup is always a problem"
        );
        assert_eq!(
            classify(now, budget, Some(now - chrono::Duration::hours(3))),
            None,
            "a recent good backup is fine"
        );
        // A failure sitting on top of a good recent backup is not an alert —
        // the data is still protected.
        assert_eq!(
            classify(now, budget, Some(now - chrono::Duration::hours(47))),
            None,
            "still inside the budget"
        );
        assert!(
            classify(now, budget, Some(now - chrono::Duration::days(5)))
                .unwrap()
                .contains("5 days"),
            "an aged-out backup reports how old it is"
        );
    }

    #[test]
    fn alerts_fire_on_the_edge_not_every_sweep() {
        let mut alerted = std::collections::HashSet::new();
        let stale = || vec![("app".to_string(), Some("no successful backup".to_string()))];
        let healthy = || vec![("app".to_string(), None)];

        let first = transitions(stale().into_iter(), &mut alerted);
        assert_eq!(first.len(), 1, "going stale notifies");
        assert!(first[0].failed);

        assert!(
            transitions(stale().into_iter(), &mut alerted).is_empty(),
            "staying stale must not re-notify every sweep"
        );

        let recovered = transitions(healthy().into_iter(), &mut alerted);
        assert_eq!(recovered.len(), 1, "recovery notifies once");
        assert!(!recovered[0].failed);

        assert!(
            transitions(healthy().into_iter(), &mut alerted).is_empty(),
            "staying healthy is silent"
        );
        // And it can go bad again afterwards — the state is cleared, not stuck.
        assert_eq!(transitions(stale().into_iter(), &mut alerted).len(), 1);
    }

    #[test]
    fn a_healthy_database_never_alerts_on_first_sight() {
        let mut alerted = std::collections::HashSet::new();
        assert!(
            transitions(vec![("app".to_string(), None)].into_iter(), &mut alerted).is_empty(),
            "a fresh boot with good backups must not emit a recovery volley"
        );
    }

    #[test]
    fn durations_read_like_english() {
        assert_eq!(human_duration(chrono::Duration::days(1)), "1 day");
        assert_eq!(human_duration(chrono::Duration::days(3)), "3 days");
        assert_eq!(human_duration(chrono::Duration::hours(5)), "5 hours");
        assert_eq!(human_duration(chrono::Duration::hours(1)), "1 hour");
        assert_eq!(human_duration(chrono::Duration::minutes(9)), "9 minutes");
        // Never "0 minutes" — a just-taken backup still reads as a duration.
        assert_eq!(human_duration(chrono::Duration::seconds(4)), "1 minute");
    }

    #[test]
    fn metadata_db_name_cannot_collide_with_a_tenant() {
        assert!(
            !crate::names::valid_db_name(METADATA_DB),
            "the reserved metadata name must be unprovisionable"
        );
    }

    #[test]
    fn stored_paths_cannot_escape_the_backup_root() {
        let root = Path::new("/srv/cryptarch/backups");
        assert!(safe_join(root, "app/20260719T193045Z-x.dump.zst.enc").is_ok());

        // Path::join REPLACES the base when handed an absolute path, so without
        // this check anyone able to write the metadata database turns the
        // unattended retention pass into an arbitrary-file-delete running as
        // the app user.
        let err = safe_join(root, "/etc/passwd").unwrap_err();
        assert!(err.to_string().contains("not relative"), "got: {err}");

        let err = safe_join(root, "../../etc/passwd").unwrap_err();
        assert!(err.to_string().contains("escapes"), "got: {err}");
        assert!(safe_join(root, "app/../../../etc/shadow").is_err());
    }

    #[test]
    fn blob_path_disambiguates_reused_names() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-07-19T19:30:45Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let a = blob_path("app", uuid::uuid!("11111111-1111-1111-1111-111111111111"), at);
        let b = blob_path("app", uuid::uuid!("22222222-2222-2222-2222-222222222222"), at);
        assert_eq!(
            a.to_str().unwrap(),
            "app/20260719T193045Z-11111111-1111-1111-1111-111111111111.dump.zst.enc"
        );
        assert_ne!(a, b, "same name and second must not collide");
    }
}
