//! CRYPTARCH-78: recovering databases stranded by the removed suspend feature.
//!
//! Suspend wrote to *two* systems: `ALTER ROLE … NOLOGIN` on the managed
//! server, and `status = 'suspended'` in the metadata database. Deleting the
//! feature without repairing those roles would leave the affected databases
//! permanently inert — the portal would show them as healthy while every
//! connection failed, with nothing anywhere explaining why.
//!
//! A SQL migration cannot do this. It reaches the metadata row and not the
//! managed server, so it would produce exactly that lie.
//!
//! # Why there are two tiers, and only one of them acts
//!
//! The set of stranded databases is **not computable after the fact**:
//!
//! * `status` cannot find them all. Suspend was not transactional — it called
//!   the engine first and wrote the metadata row afterwards, outside any
//!   transaction — so a crash between the two leaves `rolcanlogin = false`
//!   with `status = 'active'`. A `WHERE status = 'suspended'` sweep looks
//!   straight past that database.
//! * `rolcanlogin` cannot identify them safely. After CRYPTARCH-78 nothing in
//!   Cryptarch writes `NOLOGIN` ([`DbEngine::enable_login`] cannot express
//!   it), so a disabled role is just as likely to be an administrator cutting
//!   off a compromised tenant by hand — which is *more* likely now that the
//!   portal offers no button for it.
//!
//! One pass can be complete or safe, not both. So:
//!
//! * **Tier A** ([`repair_stranded_logins`]) repairs a worklist frozen at
//!   upgrade time, when only Cryptarch's own suspend path could have written
//!   `'suspended'`. It acts.
//! * **Tier B** ([`survey_disabled_logins`]) reports every *other* disabled
//!   role for a human to judge. It never acts.
//!
//! The invisible strand from the non-transactional suspend lands in Tier B. It
//! is reported rather than repaired because that state is genuinely ambiguous,
//! and the harm being prevented was "permanently inert and nothing says why" —
//! which visibility solves and guessing does not.
//!
//! # Tier A does not exist after the upgrade
//!
//! It is reachable only from the upgrade path, never from normal startup. A
//! managed server that is unreachable during the upgrade is therefore *never*
//! auto-repaired — not on the next boot, not after it comes back. Its
//! databases surface in Tier B for an administrator to re-enable by hand.
//!
//! That is deliberate. The safety of Tier A rests on its worklist being frozen
//! *recently*; a pass that lingers could re-enable a lockout an administrator
//! performed in the meantime. Rather than bound that window with a clock —
//! which only picks the moment at which you stop being wrong — the window is
//! collapsed to zero by construction. "Never reached" resolves to "never
//! repaired", with no stored fact that a metadata restore could rewind.
//!
//! # Identity comes from metadata, state comes from the server
//!
//! `databases` is trusted to say *which roles Cryptarch provisioned on server
//! S* — PostgreSQL records no creator for a role, so there is no server-side
//! fact that fully answers it. It is trusted for nothing else. In particular
//! `status` is never read as truth about the server.
//!
//! Reading `status = 'restoring'` to skip a database mid-restore is *not* an
//! exception to that rule: that value is Cryptarch's own in-flight intent, and
//! this is the only place that knowledge exists.
//!
//! Because metadata can be *behind* the server — restore the metadata database
//! from yesterday and today's provisioned databases vanish from `databases`
//! while still existing on the box — Tier B additionally cross-checks against
//! the roles the panel actually administers. Disagreement between the two is
//! itself a finding.

use crate::servers::ServerRegistry;
use anyhow::Context;
use uuid::Uuid;

/// Marker role recording that Tier A's one attempt has been spent on a server.
///
/// The leading underscore is a security control, not a style choice.
/// [`crate::names::valid_db_name`] requires a leading lowercase *letter*, so no
/// tenant can ever provision a database — and therefore a role — of this name.
/// Without it, `cryptarch_repair_78` is a perfectly legal database name: a
/// tenant could provision it, Tier A's `CREATE ROLE` would fail with "already
/// exists", the pass would read that as *already attempted here*, and the
/// repair would be skipped for every database on that server. A tenant must not
/// be able to suppress a security repair by choosing a name.
///
/// Same guard, and the same reasoning, as [`crate::backup::METADATA_DB`].
pub const REPAIR_MARKER_ROLE: &str = "_cryptarch_repair_78";

/// Every role Cryptarch creates on a managed server for **its own purposes**,
/// rather than on behalf of a user.
///
/// These are all panel-administered — PostgreSQL 16+ grants a `CREATEROLE`
/// creator its new roles automatically, and some are granted explicitly on top
/// — and none of them has a `databases` row, because none of them is a tenant.
/// So every one of them would otherwise appear in the Tier B report forever, as
/// either "disabled outside Cryptarch" or "unknown to metadata", on every
/// server. A permanent false positive is how a security report dies.
///
/// This has now happened twice — the repair marker, and the edge auth role —
/// which makes it a class rather than an incident. **Add to this list at the
/// point the role is created**, not when it turns up in a report.
pub const PANEL_OWNED_ROLES: &[&str] = &[REPAIR_MARKER_ROLE, crate::edge::AUTH_ROLE];

/// What the marker means: **Tier A's one attempt has been spent on this
/// server** — written once the attempt concludes, whatever its outcome,
/// provided it actually ran.
///
/// Deliberately *not* "the repair completed". If it meant completion, a partial
/// pass would force a choice between writing it (stranding the unrepaired
/// remainder forever) and not writing it (leaving the server open to a replay
/// that re-enables an administrator's lockout). Both are wrong, because the
/// question was wrong. What is being defended against was never "we didn't
/// finish" — it is "we did it twice".
///
/// It lives on the managed server rather than in the metadata database because
/// the metadata database can be restored from backup, which would resurrect the
/// worklist and roll back any completion flag stored there, while an
/// administrator's manual `NOLOGIN` on the managed server survives untouched.
/// Storing the mitigation in the only thing that can be rewound independently
/// of what it protects is how the replay happens.
///
/// The honest claim is the weaker one: **the marker is in a different backup
/// domain from the metadata database** — not that it cannot be lost. Restoring
/// the managed server itself rewinds it too (arguably correctly, since that
/// server rolled back as well), and an administrator can drop the role. The
/// role carries a comment saying what it is, to make the second less likely.
const MARKER_COMMENT: &str =
    "Cryptarch: CRYPTARCH-78 login repair has been attempted on this server. \
     Dropping this role lets that one-time repair run again on the next upgrade.";

/// Outcome of a per-database repair attempt. Every variant is recorded; the
/// pass never silently consumes a worklist entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairOutcome {
    /// Login re-enabled on the server and the metadata row settled.
    Repaired,
    /// The row named a database the server does not have. Nothing was
    /// re-enabled — granting login to a role whose database is gone is not a
    /// repair — and the anomaly is reported.
    DatabaseMissing,
    /// Mid-restore. Left alone deliberately; the restore owns this database.
    SkippedRestoring,
    /// The attempt ran and failed. Stays visible rather than being dropped.
    Failed(String),
}

/// One database's repair result, for the upgrade log and the admin report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairRecord {
    pub server_id: Uuid,
    pub db_name: String,
    pub outcome: RepairOutcome,
}

/// Why a role appears in the Tier B report.
///
/// A closed vocabulary with an explicit unknown, because the report makes a
/// claim about *who acted*. Attributing Cryptarch's own failed operation to a
/// human administrator is worse than a stale report: it is a false statement in
/// the document somebody consults during an incident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisabledCause {
    /// Metadata says this database is mid-delete. Cryptarch disabled the role
    /// itself and the delete did not finish. (Populated once CRYPTARCH-79
    /// lands; the variant exists first so the classifier is exhaustive.)
    FailedDelete,
    /// The row looks healthy and the role is not on the repair worklist, so
    /// the most likely explanation is a deliberate `ALTER ROLE … NOLOGIN` by
    /// an administrator.
    DisabledOutsideCryptarch,
    /// Not attributable. Its own state — never rendered as either neighbour,
    /// and never actioned automatically. Reporting *unknown* as a human
    /// lockout asserts a falsehood; reporting it as a failed delete invites
    /// somebody to auto-repair it.
    ///
    /// # Why there is no fourth `FailedRepair` variant
    ///
    /// The tempting case is a role that is disabled, whose row reads `active`,
    /// and which *is* on the repair worklist. It looks like "Tier A tried and
    /// failed", and naming it that would be a guess with a label on it.
    ///
    /// Two different histories produce that exact state, and nothing
    /// observable separates them:
    ///
    /// 1. **Tier A ran here and succeeded.** The ordering is engine-first,
    ///    row-settled-after, so a settled row means [`DbEngine::enable_login`]
    ///    returned `Ok`. If the role is disabled *again*, something re-disabled
    ///    it afterwards — and after CRYPTARCH-78 nothing in Cryptarch can. So:
    ///    a human.
    /// 2. **Tier A never ran here.** The server was unreachable during the
    ///    upgrade, so it is permanently Tier B and the worklist entry was never
    ///    consumed; the row reached `active` by some other route. Once restore
    ///    lands, a completed replace does exactly that — it settles the row to
    ///    `active` and deliberately leaves the role alone. So: Cryptarch's own
    ///    pre-78 suspend, and no human involved at all.
    ///
    /// Same residue, opposite answers to "who did this". `Unknown` is the only
    /// honest classification, and this comment exists so the next reader
    /// doesn't think harder and add the variant.
    Unknown,
}

/// A role the panel administers whose login is disabled.
#[derive(Debug, Clone)]
pub struct DisabledRole {
    pub server_id: Uuid,
    pub role_name: String,
    /// `None` when the role exists on the server but no `databases` row names
    /// it — the metadata-is-behind-the-server case that the cross-check exists
    /// to surface.
    pub db_name: Option<String>,
    pub cause: DisabledCause,
}

/// How completely a server could be surveyed.
///
/// Three states, not two. "Nothing found" and "we could not look" are the
/// distinction everybody remembers; the one that gets missed is that the check
/// is *per role*, and a single role's check can fail on a perfectly reachable
/// server — the role vanished mid-pass, a permission error, a statement
/// timeout. Those must not land in "checked, none found".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurveyCoverage {
    /// Every candidate role was checked.
    Complete { roles_checked: usize },
    /// The server answered, but some roles could not be checked. The report
    /// must not render as clean.
    Partial { roles_checked: usize, roles_failed: usize },
    /// The server could not be reached at all.
    Unreachable { detail: String },
    /// We did not look, and that is not a failure — the server is registered
    /// in metadata but not in live service (an admin disabled it).
    ///
    /// A fourth state because "we didn't look because you turned it off" is
    /// genuinely different from "we couldn't reach it", and both are different
    /// from "we looked and found nothing". Without it, a disabled server is
    /// invisible to BOTH tiers: Tier A never attempts it so it falls to Tier B
    /// by construction, and Tier B never enumerates it — each tier's silence
    /// justified by the other's responsibility. Its databases still exist, its
    /// roles still exist, and any disabled login is still disabled.
    NotSurveyed { reason: String },
}

impl SurveyCoverage {
    /// Whether this coverage permits the phrase "none found" to mean anything.
    /// Used by the renderer so an empty report states what it covered rather
    /// than merely that it was empty.
    pub fn is_conclusive(&self) -> bool {
        matches!(self, SurveyCoverage::Complete { .. })
    }
}

/// Result of surveying one server for Tier B.
#[derive(Debug, Clone)]
pub struct Survey {
    pub server_id: Uuid,
    pub coverage: SurveyCoverage,
    pub disabled: Vec<DisabledRole>,
    /// Roles the panel administers that no `databases` row names. Evidence
    /// that the identity source is incomplete — after a metadata restore,
    /// databases provisioned since the backup exist on the server but are
    /// absent from `databases`, and a survey driven only by metadata would
    /// report "checked, none found" about roles it never knew to look at.
    pub unknown_to_metadata: Vec<String>,
}

/// Roles the panel role administers on this server.
///
/// A **semi-join**, not `SELECT … DISTINCT`. Every provisioned role appears in
/// `pg_auth_members` *twice*: once from the explicit `GRANT … WITH INHERIT
/// FALSE, SET TRUE` that `create_user_db` issues, and once from the automatic
/// grant PostgreSQL 16+ makes to a `CREATEROLE` creator. The catalog keys on
/// grantor, so those are genuinely separate rows. `DISTINCT` would collapse
/// them only while the projection happens to contain nothing grant-specific —
/// add `admin_option` later and the de-duplication silently stops working
/// while still visibly present in the query. A semi-join cannot multiply rows
/// whatever is projected.
///
/// Cryptarch's own roles are excluded by name — see [`PANEL_OWNED_ROLES`], and
/// note the parameter is a *set*, not a single name: there are two already, and
/// a signature taking one is a signature that cannot express the truth.
///
/// **`session_user`, deliberately not `CURRENT_ROLE`.** `CURRENT_ROLE` follows
/// `SET ROLE`, and this codebase issues `SET ROLE` on *pooled* connections —
/// see `PostgresEngine::drop_user_db`, which resets it on the way out with the
/// failure ignored. A connection that returns to the pool still wearing a
/// tenant's role would make this enumerate *that tenant's* memberships. A
/// tenant administers nothing, so the query would return empty and the survey
/// would report "checked, none found" having never computed the real answer —
/// a silent wrong answer, in the safe-looking direction, inside the security
/// report. `session_user` is the connection's login role and `SET ROLE` cannot
/// move it. Verified on PG 17.10: after `SET ROLE tenant`, the `CURRENT_ROLE`
/// form returns 0 rows where the `session_user` form returns the correct set.
pub const PANEL_ADMINISTERED_ROLES_SQL: &str = "\
    SELECT r.rolname, r.rolcanlogin \
    FROM pg_roles r \
    WHERE r.oid IN (SELECT roleid FROM pg_auth_members WHERE member = session_user::regrole) \
      AND r.rolname <> ALL($1)";

/// Classify a disabled role, from recorded intent rather than inferred cause.
///
/// Database-existence is *residue*, and reading cause out of residue is the
/// mistake this whole change exists to correct. The server cannot say *why* a
/// role is disabled, because "why" is not a server-side fact at any level of
/// cleverness — so the answer is taken from what Cryptarch recorded before it
/// acted.
pub fn classify(db_status: Option<&str>, on_repair_worklist: bool) -> DisabledCause {
    match (db_status, on_repair_worklist) {
        // Cryptarch recorded the intent to delete before it began. Whichever
        // step failed, this is ours.
        (Some("deleting"), _) => DisabledCause::FailedDelete,
        // A healthy row, not on the worklist, login disabled: nothing in
        // Cryptarch can have written that.
        (Some("active"), false) => DisabledCause::DisabledOutsideCryptarch,
        // Everything else — no row at all, a status we have no story for, or a
        // worklist entry that was never repaired.
        _ => DisabledCause::Unknown,
    }
}

/// The migration that freezes the worklist. Tier A's eligibility is defined
/// entirely by this version appearing during *this process's* migration step.
pub const REPAIR_MIGRATION_VERSION: i64 = 16;

/// Whether migration [`REPAIR_MIGRATION_VERSION`] is recorded as applied.
///
/// Answers `false` when `_sqlx_migrations` does not exist yet, which is the
/// correct answer for a database that has never been migrated.
pub async fn repair_migration_applied(db: &sqlx::PgPool) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = $1 AND success)",
    )
    .bind(REPAIR_MIGRATION_VERSION)
    .fetch_one(db)
    .await
    .unwrap_or(false)
}

/// Run Tier A across every managed server, then Tier B regardless.
///
/// # Why this is not simply called from `main` after migrating
///
/// It nearly is — but the guard in front of it is the whole of claim C3, so
/// read this before "simplifying" the call site.
///
/// This application has **no separate upgrade path**: `MIGRATOR.run` executes
/// on every boot, so migrating *is* normal startup. "Tier A is structurally
/// absent from normal startup" therefore cannot mean "it lives somewhere
/// normal startup doesn't reach", because there is nowhere else.
///
/// The tempting implementation — call this every boot and let the marker stop
/// it — looks already-protected and is not. For a server that was **reached**
/// at the original upgrade the marker returns `Ok(false)` and it skips, which
/// is fine. For a server that was **never reached** there is no marker, so it
/// would retry on every boot forever, against a freeze that gets staler each
/// time. That is TM2 unbounded: the precise risk the design collapsed the
/// window to zero to avoid, reintroduced by an implementation that appears
/// safe.
///
/// So the caller runs this **iff migration [`REPAIR_MIGRATION_VERSION`] went
/// from not-applied to applied during this process's migration step**. That
/// gives the properties actually claimed:
///
/// * **Nothing stored to consult or rewind.** The eligibility fact exists only
///   inside one process lifetime and is gone when it exits, so there is no row
///   a later reader can wire up as a gate — which `0016_repair_78.sql` already
///   forbids in as many words.
/// * **A metadata restore behaves as designed.** Restored to pre-78, the
///   migration is absent again, the next boot observes the transition, and
///   Tier A runs — with the marker stopping it on every server that was
///   reached. That is the documented residual, arrived at by construction
///   rather than by exception.
/// * **A crash mid-repair stays terminal.** The migration is already recorded,
///   so the next boot sees no transition and Tier A never runs again. The
///   remainder falls to Tier B, consistent with claim-first and with the
///   marker meaning *the attempt was spent*.
///
/// The alternatives were considered and are worse: an environment variable is
/// an operator-gated flag someone forgets to set or leaves set; a table row is
/// the metadata rollback domain the migration comment forbids branching on.
///
/// On a genuinely fresh install this also fires, with an empty worklist. That
/// is harmless and mildly desirable — the attempt is spent on each server with
/// nothing to repair, which is exactly true, and it forecloses a later replay.
pub async fn run_upgrade_repair(db: &sqlx::PgPool, registry: &ServerRegistry) {
    for server_id in registry.ids() {
        match repair_stranded_logins(db, registry, server_id).await {
            Ok(AttemptOutcome::Walked(records)) => {
                let repaired = records
                    .iter()
                    .filter(|r| r.outcome == RepairOutcome::Repaired)
                    .count();
                tracing::info!(
                    "CRYPTARCH-78 repair on {server_id}: attempt spent, \
                     {repaired} of {} entries repaired",
                    records.len()
                );
                for r in records.iter().filter(|r| r.outcome != RepairOutcome::Repaired) {
                    tracing::warn!(
                        "CRYPTARCH-78 repair on {server_id}: '{}' not repaired: {:?}",
                        r.db_name,
                        r.outcome
                    );
                }
            }
            Ok(AttemptOutcome::AlreadySpent) => {
                tracing::info!(
                    "CRYPTARCH-78 repair on {server_id}: attempt already spent, skipping"
                );
            }
            Ok(AttemptOutcome::CouldNotAsk(detail)) => {
                // Not repaired now, and not repairable later — this server is
                // permanently Tier B. Said plainly because an operator has to
                // finish the job by hand.
                tracing::warn!(
                    "CRYPTARCH-78 repair on {server_id}: could not reach the server \
                     ({detail}). Its attempt was NOT spent and will NOT be retried; \
                     any disabled logins there must be re-enabled from the admin page."
                );
            }
            Err(e) => tracing::error!("CRYPTARCH-78 repair on {server_id} failed: {e:#}"),
        }

        // Tier B runs regardless of what Tier A did — including on a server
        // whose attempt was already spent, which is the one most likely to be
        // carrying the remainder that fell through when it was spent.
        match survey_disabled_logins(db, registry, server_id).await {
            Ok(s) if !s.disabled.is_empty() || !s.unknown_to_metadata.is_empty() => {
                tracing::warn!(
                    "CRYPTARCH-78 survey on {server_id}: {} disabled role(s), {} unknown to \
                     metadata, coverage {:?}",
                    s.disabled.len(),
                    s.unknown_to_metadata.len(),
                    s.coverage
                );
            }
            Ok(s) if !s.coverage.is_conclusive() => {
                // "Could not look" is not "looked and found nothing".
                tracing::warn!(
                    "CRYPTARCH-78 survey on {server_id}: INCOMPLETE ({:?}) — this is not a \
                     clean result",
                    s.coverage
                );
            }
            Ok(_) => {}
            Err(e) => tracing::error!("CRYPTARCH-78 survey on {server_id} failed: {e:#}"),
        }
    }
}

/// What Tier A did with a server's single attempt.
///
/// The per-database records live **inside** the `Walked` variant rather than
/// beside the outcome. That is deliberate, and it is the same move as removing
/// the `false` from `set_login`: returning `(AttemptOutcome, Vec<RepairRecord>)`
/// would let a caller destructure and read the `Vec` without ever matching the
/// outcome — and *"already spent, so nothing was done"* and *"walked the list,
/// nothing needed doing"* are both the empty vector. Two outcomes one bit
/// apart, with the collapsing direction cheaper to write. Here there is no
/// `Vec` to read without having answered the question first, so the ambiguity
/// stops being something callers must remember and becomes something they
/// cannot express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The claim was won and the worklist was walked. Carries what happened to
    /// every entry — including the empty case, which here unambiguously means
    /// *this server had nothing to repair*.
    Walked(Vec<RepairRecord>),
    /// The marker already existed. Tier A does nothing here — and this is the
    /// design working, not a failure. **Tier B still runs**: a server whose
    /// attempt was already spent is precisely the one most likely to be
    /// carrying the remainder that fell through when it was spent.
    AlreadySpent,
    /// The server could not be asked. Nothing was claimed, so nothing was
    /// repaired, and the attempt is **not** spent. Recorded for the operator —
    /// and nothing branches on that record. **Tier B still runs.**
    CouldNotAsk(String),
}

/// Tier A. Claim this server's one attempt, then repair the frozen worklist.
///
/// **The claim happens before the loop, not after.** The marker records that
/// the attempt has been *spent*, and an attempt is spent the moment it begins.
/// Claiming afterwards would mean a crash mid-loop leaves repaired databases
/// behind with no evidence on the server that anything was attempted — and
/// would let a later replay run against a stale freeze on a box where work has
/// already happened. Claiming first means a crash leaves the remainder
/// unrepaired, and the remainder falls to Tier B exactly like every other
/// unrepairable thing. That is already the chosen disposition for a partial
/// pass; claim-first makes a crash and a failure produce the same answer
/// instead of two.
///
/// Ordering *within* a database is equally fixed: the engine call happens
/// first, and the metadata row is settled only once it has succeeded. The
/// reverse ordering is what created the strand being repaired.
pub async fn repair_stranded_logins(
    db: &sqlx::PgPool,
    registry: &ServerRegistry,
    server_id: Uuid,
) -> anyhow::Result<AttemptOutcome> {
    let Some(engine) = registry.get(server_id) else {
        return Ok(AttemptOutcome::CouldNotAsk("no engine for server".into()));
    };

    // THE CALL SITE. Three outcomes, three paths — never `unwrap_or(false)`,
    // which would read "could not ask" as "already done" and skip the repair
    // on a server nobody ever reached. That is the bug the engine's SQLSTATE
    // discrimination exists to prevent; collapsing it here would reintroduce
    // it one layer up.
    match engine.claim_repair_attempt(REPAIR_MARKER_ROLE, MARKER_COMMENT).await {
        Ok(true) => {}
        Ok(false) => return Ok(AttemptOutcome::AlreadySpent),
        Err(e) => {
            let detail = format!("{e:#}");
            // Informational only; eligibility is structural.
            let _ = sqlx::query(
                "INSERT INTO repair_unreachable_78 (server_id, detail) VALUES ($1, $2) \
                 ON CONFLICT (server_id) DO UPDATE SET detail = EXCLUDED.detail",
            )
            .bind(server_id)
            .bind(&detail)
            .execute(db)
            .await;
            return Ok(AttemptOutcome::CouldNotAsk(detail));
        }
    }

    let entries: Vec<(Uuid, std::string::String)> = sqlx::query_as(
        "SELECT w.db_id, w.db_name FROM repair_worklist_78 w \
         WHERE w.server_id = $1 AND w.settled_at IS NULL",
    )
    .bind(server_id)
    .fetch_all(db)
    .await
    .context("reading the repair worklist")?;

    let mut records = Vec::with_capacity(entries.len());
    for (db_id, db_name) in entries {
        // Cryptarch's own in-flight intent — the one thing `status` legitimately
        // answers. A restore owns this database right now; leave it alone.
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM databases WHERE id = $1")
                .bind(db_id)
                .fetch_optional(db)
                .await
                .context("reading the database's status")?;
        let outcome = if status.as_deref() == Some("restoring") {
            RepairOutcome::SkippedRestoring
        } else {
            match engine.database_exists(&db_name).await {
                // Re-enabling login for a role whose database is gone is not a
                // repair — it hands out a credential for nothing.
                Ok(false) => RepairOutcome::DatabaseMissing,
                Ok(true) => match engine.enable_login(&db_name).await {
                    Ok(()) => {
                        // Engine first, row second. Only now is it true.
                        match sqlx::query(
                            "UPDATE databases SET status = 'active' \
                             WHERE id = $1 AND status = 'suspended'",
                        )
                        .bind(db_id)
                        .execute(db)
                        .await
                        {
                            Ok(_) => RepairOutcome::Repaired,
                            Err(e) => RepairOutcome::Failed(format!("settling the row: {e}")),
                        }
                    }
                    Err(e) => RepairOutcome::Failed(format!("enabling login: {e:#}")),
                },
                Err(e) => RepairOutcome::Failed(format!("checking the database: {e:#}")),
            }
        };

        // Every entry is settled with what actually happened. A worklist entry
        // is never silently consumed.
        let (label, detail) = match &outcome {
            RepairOutcome::Repaired => ("repaired", None),
            RepairOutcome::DatabaseMissing => ("database_missing", None),
            RepairOutcome::SkippedRestoring => ("skipped_restoring", None),
            RepairOutcome::Failed(d) => ("failed", Some(d.clone())),
        };
        let _ = sqlx::query(
            "UPDATE repair_worklist_78 SET outcome = $2, detail = $3, settled_at = now() \
             WHERE db_id = $1",
        )
        .bind(db_id)
        .bind(label)
        .bind(detail)
        .execute(db)
        .await;

        records.push(RepairRecord { server_id, db_name, outcome });
    }

    Ok(AttemptOutcome::Walked(records))
}

/// Tier B. Survey one server for disabled roles. Never mutates anything.
///
/// Runs regardless of what Tier A did — including on a server whose attempt was
/// already spent, which is the one most likely to have a remainder in it.
pub async fn survey_disabled_logins(
    db: &sqlx::PgPool,
    registry: &ServerRegistry,
    server_id: Uuid,
) -> anyhow::Result<Survey> {
    let Some(engine) = registry.get(server_id) else {
        return Ok(Survey {
            server_id,
            coverage: SurveyCoverage::Unreachable { detail: "no engine for server".into() },
            disabled: Vec::new(),
            unknown_to_metadata: Vec::new(),
        });
    };

    let roles = match engine.login_states(PANEL_OWNED_ROLES).await {
        Ok(r) => r,
        // "Could not look" must never render as "looked, found nothing".
        Err(e) => {
            return Ok(Survey {
                server_id,
                coverage: SurveyCoverage::Unreachable { detail: format!("{e:#}") },
                disabled: Vec::new(),
                unknown_to_metadata: Vec::new(),
            })
        }
    };

    // Identity from metadata. Held separately from the server's answer so the
    // two can be compared rather than one silently standing in for the other.
    let named: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, status FROM databases WHERE server_id = $1",
    )
    .bind(server_id)
    .fetch_all(db)
    .await
    .context("reading this server's databases")?;

    let on_worklist: Vec<String> = sqlx::query_scalar(
        "SELECT db_name FROM repair_worklist_78 WHERE server_id = $1",
    )
    .bind(server_id)
    .fetch_all(db)
    .await
    .context("reading the repair worklist")?;

    let mut disabled = Vec::new();
    let mut unknown_to_metadata = Vec::new();
    for role in &roles {
        let row = named.iter().find(|(n, _)| *n == role.role_name);
        if row.is_none() {
            // The panel administers a role that no `databases` row names. After
            // a metadata restore this is every database provisioned since the
            // backup — the identity source being behind the server. Reported
            // whether or not the role can log in, because the disagreement is
            // itself the finding.
            unknown_to_metadata.push(role.role_name.clone());
        }
        if role.can_login {
            continue;
        }
        disabled.push(DisabledRole {
            server_id,
            role_name: role.role_name.clone(),
            db_name: row.map(|(n, _)| n.clone()),
            cause: classify(
                row.map(|(_, s)| s.as_str()),
                on_worklist.contains(&role.role_name),
            ),
        });
    }

    Ok(Survey {
        server_id,
        coverage: SurveyCoverage::Complete { roles_checked: roles.len() },
        disabled,
        unknown_to_metadata,
    })
}

/// Recover databases stranded by a delete that failed partway (CRYPTARCH-80).
///
/// # Why this reverts rather than only retrying
///
/// `delete_db` records `deleting` before it calls the engine, and
/// `drop_user_db` disables login as its first step precisely so that a failure
/// there destroys nothing. But "destroys nothing" is not "harmless": the
/// backup scheduler selects its targets by status, so from the moment the row
/// reads `deleting` that database has **left the backup schedule**. A failure
/// at the first step therefore leaves a fully working, tenant-serving database
/// that has quietly stopped being protected — and it is invisible to the login
/// report by construction, because its role is still enabled.
///
/// The evidence that makes it invisible is the same evidence that makes it
/// safe to undo:
///
/// * **role still `LOGIN` and the database still exists** ⇒ the first step
///   never completed ⇒ nothing happened ⇒ revert the row to `active`. Backups
///   resume, and no human is needed. Sound because after CRYPTARCH-78 nothing
///   else writes `NOLOGIN`, and `ALTER ROLE … NOLOGIN` is idempotent, so an
///   already-disabled role cannot masquerade as this case.
/// * **role `NOLOGIN`** ⇒ a later step failed ⇒ leave it. That is genuine
///   unfinished destruction and needs the operator-triggered retry.
///
/// # Why it runs on the scheduler pass and not at boot
///
/// The neighbouring sweeps are boot-time, and consistency will look like the
/// right instinct here. It is not: the harm accrues *while* the row is
/// stranded, so a boot-only sweep bounds the exposure by the uptime of the
/// process — on a small deployment, months. Periodic bounds it by one
/// scheduler interval, which is roughly one missed backup. The precedent is
/// the backup enqueue wedge, which got age-based sweeping on every pass for
/// exactly this reason.
pub async fn sweep_stranded_deletes(
    db: &sqlx::PgPool,
    registry: &ServerRegistry,
) -> anyhow::Result<usize> {
    let stranded: Vec<(Uuid, std::string::String, Uuid)> = sqlx::query_as(
        "SELECT id, name, server_id FROM databases WHERE status = 'deleting'",
    )
    .fetch_all(db)
    .await
    .context("listing stranded deletes")?;

    let mut reverted = 0usize;
    for (id, name, server_id) in stranded {
        let Some(engine) = registry.get(server_id) else { continue };

        // Ask the SERVER, not the row. Both halves are required: a role that
        // can log in whose database is already gone is NOT this case.
        let roles = match engine.login_states(PANEL_OWNED_ROLES).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("stranded-delete sweep: cannot survey {server_id}: {e:#}");
                continue;
            }
        };
        let can_log_in = roles.iter().any(|r| r.role_name == name && r.can_login);
        let db_exists = match engine.database_exists(&name).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("stranded-delete sweep: cannot check '{name}': {e:#}");
                continue;
            }
        };

        if !(can_log_in && db_exists) {
            // Destruction began. Not ours to undo — an operator retries it.
            continue;
        }

        let updated = sqlx::query(
            "UPDATE databases SET status = 'active', status_changed_at = now() \
             WHERE id = $1 AND status = 'deleting'",
        )
        .bind(id)
        .execute(db)
        .await;
        match updated {
            Ok(r) if r.rows_affected() == 1 => {
                reverted += 1;
                // Audited WITH THE REASON. Two bare status changes, `deleting`
                // then `active`, read as the system arguing with itself, and
                // send the next reader hunting for a bug in the delete path
                // instead of finding the one that already happened.
                crate::provision::audit(
                    db,
                    "system",
                    "delete_reverted",
                    Some(&name),
                    Some(
                        "delete failed before anything was changed — login still enabled \
                         and the database still present, so the row was returned to active \
                         and backups resume",
                    ),
                )
                .await;
                tracing::info!(
                    "stranded-delete sweep: '{name}' was never actually deleted; \
                     returned to active"
                );
            }
            Ok(_) => {}
            Err(e) => tracing::error!("stranded-delete sweep: could not revert '{name}': {e}"),
        }
    }
    Ok(reverted)
}

/// Work that only a human can finish, and how long it has been waiting.
///
/// Nothing here is repaired automatically, by design: completing a delete
/// destroys data, and re-enabling a login nobody can attribute would undo an
/// administrator's lockout. But "nothing automatic does it" quietly also means
/// "nothing guarantees anything ever does" — and this stack has now produced
/// three such obligations, each originally announced once in a log line at the
/// moment it arose. A permanent obligation announced once is write-only.
///
/// So they are aged and alerted, on the same edge-triggered path as backup
/// staleness: an obligation older than the threshold fires once, and stops
/// being mentioned when it is discharged.
#[derive(Debug, Clone)]
pub struct Outstanding {
    pub what: String,
    pub detail: String,
    pub age_secs: i64,
}

/// Obligations older than `older_than_secs`. Zero disables the check.
pub async fn outstanding_work(db: &sqlx::PgPool, older_than_secs: u64) -> Vec<Outstanding> {
    if older_than_secs == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();

    let stranded: Vec<(std::string::String, i64)> = sqlx::query_as(
        "SELECT name, EXTRACT(EPOCH FROM (now() - status_changed_at))::bigint \
         FROM databases WHERE status = 'deleting' \
           AND status_changed_at < now() - make_interval(secs => $1)",
    )
    .bind(older_than_secs as f64)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    for (name, age_secs) in stranded {
        out.push(Outstanding {
            what: format!("unfinished delete: {name}"),
            detail: format!(
                "A delete of '{name}' began and did not finish. Nothing will retry it \
                 automatically — finishing it destroys data, so it needs an administrator. \
                 See the login report."
            ),
            age_secs,
        });
    }

    let unreachable: Vec<(std::string::String, i64)> = sqlx::query_as(
        "SELECT s.name, EXTRACT(EPOCH FROM (now() - r.noticed_at))::bigint \
         FROM repair_unreachable_78 r JOIN managed_servers s ON s.id = r.server_id \
         WHERE r.noticed_at < now() - make_interval(secs => $1)",
    )
    .bind(older_than_secs as f64)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    for (name, age_secs) in unreachable {
        out.push(Outstanding {
            what: format!("upgrade repair never ran: {name}"),
            detail: format!(
                "Server '{name}' could not be reached when the one-time login repair ran, \
                 and it will not be retried. Any login disabled by the old suspend feature \
                 is still disabled there and must be re-enabled by hand."
            ),
            age_secs,
        });
    }
    out
}

/// One server's survey plus the metadata needed to judge it.
pub struct ServerReport {
    pub server_name: String,
    pub survey: Survey,
    /// How many databases metadata says live on this server, or `None` if the
    /// count could not be determined.
    ///
    /// `Option`, not a defaulted `0`, because this value is the SOLE input to
    /// the "sources disagree" finding: `Complete { roles_checked: 0 }` is only
    /// a finding when databases are known to exist here. An `unwrap_or(0)`
    /// would make a failed count silently suppress the page's most valuable
    /// result and render the cleanest possible screen — the exact collapse
    /// this page was built to prevent, inside the page.
    pub known_databases: Option<i64>,
}

/// Render the Tier B report.
///
/// # The renderer's job is to make three states unconfusable
///
/// [`SurveyCoverage`] has three variants because three different things are
/// true, and every tempting simplification here collapses them:
///
/// * **Coverage is the outer question, emptiness the inner one.** `if
///   findings.is_empty() { "No issues found" }` is one line that eats all
///   three states. Emptiness only *means* anything once coverage is
///   `Complete`.
/// * **The summary is where they die.** Most people read only the headline,
///   and a headline computed by flattening every server cannot say anything
///   but "clean". So it always carries two numbers, even when the second is
///   zero: how many servers were checked, and how many could not be.
/// * **Inconclusive does not sort with clean.** An unreachable server has zero
///   findings, so any ordering by finding count files it next to the healthy
///   ones, where it reads as fine. It is listed first.
/// * **`Complete { roles_checked: 0 }` on a server that has databases is
///   itself a finding**, not an empty state: it means the panel administers no
///   roles there at all, while metadata says databases exist -- the two
///   sources disagreeing, which is exactly what the cross-check is for.
/// * **Three states need three badges.** Reusing the failure badge for
///   "could not look" merges it with "looked and found something", which is
///   the same collapse expressed in colour.
///
/// What one server's report says, decided once, server-side, for every page
/// that shows it. The coverage states stay distinct
/// all the way out: "could not look", "looked at part", "did not look", "could
/// not count", "the sources disagree", "looked: clean", "looked: findings".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// Not checked at all: unreachable. Not a clean result.
    NotChecked { detail: &'a str },
    /// Some roles could not be checked. Findings are real; absence proves nothing.
    Partial { roles_checked: usize, roles_failed: usize },
    /// Not surveyed on purpose (the server is disabled). Not a clean result.
    NotSurveyed { reason: &'a str },
    /// No roles administered, and the database count could not be read —
    /// so whether zero is a disagreement cannot be said.
    Inconclusive,
    /// No roles administered while metadata lists databases here: a finding.
    SourcesDisagree { known_databases: i64 },
    /// Every role checked; nothing found.
    Clean { roles_checked: usize },
    /// Every role checked; findings listed.
    Findings { roles_checked: usize },
}

impl ServerReport {
    pub fn verdict(&self) -> Verdict<'_> {
        match &self.survey.coverage {
            SurveyCoverage::Unreachable { detail } => Verdict::NotChecked { detail },
            SurveyCoverage::Partial { roles_checked, roles_failed } => {
                Verdict::Partial { roles_checked: *roles_checked, roles_failed: *roles_failed }
            }
            SurveyCoverage::NotSurveyed { reason } => Verdict::NotSurveyed { reason },
            SurveyCoverage::Complete { roles_checked } => {
                if *roles_checked == 0 && self.known_databases.is_none() {
                    Verdict::Inconclusive
                } else if *roles_checked == 0 && self.known_databases.unwrap_or(0) > 0 {
                    Verdict::SourcesDisagree { known_databases: self.known_databases.unwrap_or(0) }
                } else if self.survey.disabled.is_empty() && self.survey.unknown_to_metadata.is_empty() {
                    Verdict::Clean { roles_checked: *roles_checked }
                } else {
                    Verdict::Findings { roles_checked: *roles_checked }
                }
            }
        }
    }
}

/// The report's headline: always both numbers. A summary that can only say
/// "clean" lies whenever anything was inconclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ReportSummary {
    pub findings: usize,
    pub checked: usize,
    pub unchecked: usize,
}

/// Counted from the verdicts, so the headline cannot read clean over a
/// server whose card does not: an inconclusive one is unchecked, and sources
/// that disagree are a finding (S6b/c audit P2 — both used to count as a
/// clean check).
pub fn summarize(reports: &[ServerReport]) -> ReportSummary {
    let mut s = ReportSummary { findings: 0, checked: 0, unchecked: 0 };
    for r in reports {
        match r.verdict() {
            Verdict::NotChecked { .. } | Verdict::Partial { .. } | Verdict::NotSurveyed { .. }
            | Verdict::Inconclusive => s.unchecked += 1,
            Verdict::SourcesDisagree { .. } => {
                s.checked += 1;
                s.findings += 1;
            }
            Verdict::Clean { .. } => s.checked += 1,
            Verdict::Findings { .. } => {
                s.checked += 1;
                s.findings += r.survey.disabled.len() + r.survey.unknown_to_metadata.len();
            }
        }
    }
    s
}

/// Inconclusive first — never ordered by finding count, which files an
/// unreachable server next to the healthy ones.
pub fn ordered(reports: &[ServerReport]) -> Vec<&ServerReport> {
    let mut ordered: Vec<&ServerReport> = reports.iter().collect();
    ordered.sort_by_key(|r| r.survey.coverage.is_conclusive());
    ordered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::valid_db_name;

    /// The marker name must be unreachable to a tenant. If this ever fails, a
    /// tenant can provision the marker and suppress the repair for every
    /// database on that server.
    #[test]
    fn marker_role_cannot_collide_with_a_tenant_name() {
        assert!(
            !valid_db_name(REPAIR_MARKER_ROLE),
            "a tenant must not be able to provision '{REPAIR_MARKER_ROLE}' and \
             thereby suppress the CRYPTARCH-78 repair"
        );
        // And the specific reason it is unreachable, pinned: the leading
        // underscore. Without it the name is perfectly legal.
        assert!(REPAIR_MARKER_ROLE.starts_with('_'));
        assert!(valid_db_name(REPAIR_MARKER_ROLE.trim_start_matches('_')));
    }

    #[test]
    fn marker_excluded_from_the_panel_administered_query() {
        // The query must exclude Cryptarch's own roles as a bind parameter,
        // rather than relying on a caller to filter afterwards — and it must
        // exclude a SET, not one name. There are two already, and a signature
        // that can only express one is how the second gets discovered in a
        // report rather than excluded at the point it is created.
        assert!(PANEL_ADMINISTERED_ROLES_SQL.contains("rolname <> ALL($1)"));
        assert!(
            PANEL_OWNED_ROLES.len() >= 2,
            "if this ever shrinks to one, check nothing has been dropped from \
             the set rather than relaxing the assertion"
        );
        assert!(PANEL_OWNED_ROLES.contains(&REPAIR_MARKER_ROLE));
        assert!(PANEL_OWNED_ROLES.contains(&crate::edge::AUTH_ROLE));
    }

    /// TRIPWIRE, NOT COVERAGE. These assert the *shape* of the query string so
    /// a later tidy-up cannot quietly reintroduce row multiplication or the
    /// `CURRENT_ROLE` bug. They do not test behaviour, and they pass on plenty
    /// of shapes that still multiply — `CROSS JOIN LATERAL`, a subquery
    /// carrying its own join, an `EXISTS` containing one.
    ///
    /// The behavioural guarantee — one role with *both* grant rows yields
    /// exactly one row — needs a live server and lands with the
    /// implementation, in `repair_survey_counts_each_role_once`. Do not read
    /// this test as that guarantee.
    #[test]
    fn panel_administered_query_shape_tripwire() {
        assert!(PANEL_ADMINISTERED_ROLES_SQL.contains("IN (SELECT roleid FROM pg_auth_members"));
        assert!(
            !PANEL_ADMINISTERED_ROLES_SQL.contains("DISTINCT"),
            "DISTINCT stops collapsing as soon as a grant-specific column is \
             projected, while still looking like de-duplication"
        );
        assert!(
            !PANEL_ADMINISTERED_ROLES_SQL.contains("JOIN pg_auth_members"),
            "an inner join returns one row per grant, so every role is counted twice"
        );
        assert!(
            !PANEL_ADMINISTERED_ROLES_SQL.contains("CURRENT_ROLE"),
            "CURRENT_ROLE follows SET ROLE, which this codebase issues on pooled \
             connections; a leaked tenant role makes the survey silently empty"
        );
        assert!(PANEL_ADMINISTERED_ROLES_SQL.contains("session_user"));
    }

    #[test]
    fn unknown_is_its_own_state_not_a_lean() {
        // A mid-delete row is ours, whichever step failed.
        assert_eq!(classify(Some("deleting"), false), DisabledCause::FailedDelete);
        // A healthy row we never disabled is somebody else's doing.
        assert_eq!(
            classify(Some("active"), false),
            DisabledCause::DisabledOutsideCryptarch
        );
        // No metadata row at all is NOT evidence of a human. This is the
        // metadata-behind-the-server case, and calling it a lockout would put
        // a false statement about who acted into an incident report.
        assert_eq!(classify(None, false), DisabledCause::Unknown);
        // A worklist entry that was never repaired is ours, but we cannot say
        // what happened — so it is not attributed either way.
        assert_eq!(classify(Some("active"), true), DisabledCause::Unknown);
    }

    fn report(coverage: SurveyCoverage, known_databases: i64) -> ServerReport {
        let known_databases = Some(known_databases);
        ServerReport {
            server_name: "box".into(),
            survey: Survey {
                server_id: Uuid::nil(),
                coverage,
                disabled: Vec::new(),
                unknown_to_metadata: Vec::new(),
            },
            known_databases,
        }
    }

    /// The verdict is decided once, for every page: each coverage state has
    /// its own, and "zero roles" splits three ways on what metadata knows.
    #[test]
    fn every_coverage_state_has_its_own_verdict() {
        assert_eq!(report(SurveyCoverage::Unreachable { detail: "down".into() }, 1).verdict(),
                   Verdict::NotChecked { detail: "down" });
        assert_eq!(report(SurveyCoverage::Partial { roles_checked: 2, roles_failed: 1 }, 3).verdict(),
                   Verdict::Partial { roles_checked: 2, roles_failed: 1 });
        assert_eq!(report(SurveyCoverage::NotSurveyed { reason: "off".into() }, 1).verdict(),
                   Verdict::NotSurveyed { reason: "off" });
        assert_eq!(report(SurveyCoverage::Complete { roles_checked: 0 }, 2).verdict(),
                   Verdict::SourcesDisagree { known_databases: 2 });
        assert_eq!(report(SurveyCoverage::Complete { roles_checked: 0 }, 0).verdict(),
                   Verdict::Clean { roles_checked: 0 }, "an empty server, known to be empty");
        let uncounted = ServerReport { known_databases: None, ..report(SurveyCoverage::Complete { roles_checked: 0 }, 0) };
        assert_eq!(uncounted.verdict(), Verdict::Inconclusive);
        assert_eq!(report(SurveyCoverage::Complete { roles_checked: 3 }, 3).verdict(), Verdict::Clean { roles_checked: 3 });
        let mut found = report(SurveyCoverage::Complete { roles_checked: 3 }, 3);
        found.survey.unknown_to_metadata.push("ghost".into());
        assert_eq!(found.verdict(), Verdict::Findings { roles_checked: 3 });
    }

    /// The summary carries both numbers, always.
    ///
    /// Most people read only the headline, and a headline computed by
    /// flattening cannot say anything but "clean". One unreachable server
    /// beside two clean ones must not produce a clean headline.
    #[test]
    fn the_summary_cannot_say_clean_over_a_disagreement_or_an_inconclusive_server() {
        let disagree = summarize(&[report(SurveyCoverage::Complete { roles_checked: 0 }, 2)]);
        assert_eq!(disagree, ReportSummary { findings: 1, checked: 1, unchecked: 0 });
        let uncounted = ServerReport { known_databases: None, ..report(SurveyCoverage::Complete { roles_checked: 0 }, 0) };
        assert_eq!(summarize(&[uncounted]), ReportSummary { findings: 0, checked: 0, unchecked: 1 });
        let partial = report(SurveyCoverage::Partial { roles_checked: 1, roles_failed: 1 }, 2);
        assert_eq!(summarize(&[partial]).unchecked, 1, "partial is not a conclusive check");
    }

    #[test]
    fn the_summary_cannot_say_clean_when_anything_was_unchecked() {
        let mixed = summarize(&[
            report(SurveyCoverage::Complete { roles_checked: 2 }, 2),
            report(SurveyCoverage::Complete { roles_checked: 1 }, 1),
            report(SurveyCoverage::Unreachable { detail: "down".into() }, 4),
        ]);
        assert_eq!(mixed, ReportSummary { findings: 0, checked: 2, unchecked: 1 });
        // Nothing missed is a count of zero, stated — the page words both.
        let allgood = summarize(&[report(SurveyCoverage::Complete { roles_checked: 2 }, 2)]);
        assert_eq!(allgood, ReportSummary { findings: 0, checked: 1, unchecked: 0 });
    }

    /// An unreachable server has zero findings, so any ordering by finding
    /// count files it next to the healthy ones, where it reads as fine.
    #[test]
    fn inconclusive_servers_are_listed_first() {
        let reports = [
            ServerReport {
                server_name: "healthy".into(),
                ..report(SurveyCoverage::Complete { roles_checked: 1 }, 1)
            },
            ServerReport {
                server_name: "silent".into(),
                ..report(SurveyCoverage::Unreachable { detail: "down".into() }, 1)
            },
        ];
        let names: Vec<&str> = ordered(&reports).iter().map(|r| r.server_name.as_str()).collect();
        assert_eq!(names, ["silent", "healthy"], "the server we could not check must not sort below the ones we could");
    }

    #[test]
    fn partial_coverage_never_reads_as_clean() {
        assert!(SurveyCoverage::Complete { roles_checked: 3 }.is_conclusive());
        // The one that gets missed: the server was reachable, but a role's
        // own check failed. "None found" must not be sayable here.
        assert!(!SurveyCoverage::Partial { roles_checked: 2, roles_failed: 1 }.is_conclusive());
        assert!(!SurveyCoverage::Unreachable { detail: "timeout".into() }.is_conclusive());
    }
}
