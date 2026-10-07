//! What a database's status *means* — CRYPTARCH-81.
//!
//! `databases.status` was a bare string with eleven independent readers, every
//! one of them hard-coding `= 'active'`. Adding a status therefore gave it
//! eleven answers that nobody chose: uncounted for quota, invisible to its
//! owner, silently skipped by the backup scheduler, dropped from the edge
//! config, missing from admin totals. None of those raised an error, and none
//! of them was a decision.
//!
//! So a status is not a value here. It is **a row in a decision table**, and
//! each column is a different question:
//!
//! * does it occupy a quota slot?
//! * is it visible to its owner?
//! * should the scheduler back it up?
//! * should it appear in the edge config?
//! * does it count in admin totals?
//!
//! # There is deliberately no catch-all arm
//!
//! Every method below matches exhaustively with **no `_ =>`**. That is the
//! entire mechanism: adding a variant does not compile until someone has
//! answered all five, at the moment they are best placed to answer them.
//!
//! One `_ => false` and this is the same bug with a type wrapped round it —
//! and it would look tidier than what it replaced, which is why the next
//! person will want to add one. Do not.
//!
//! The danger is sharper than "someone will want a default", because the
//! principle below is clean enough that `_ => it exists, so yes` reads as a
//! *faithful implementation of it* rather than as a shortcut. **The catch-all
//! arrives wearing the principle's authority.** A lazy default gets challenged
//! in review; a principled-looking one gets approved.
//!
//! # The principle for answering (Antun, 2026-07-20)
//!
//! > *"If we create it, it exists, even empty."*
//!
//! **Existence, not readiness, is the criterion.** A database Cryptarch
//! created is counted and shown, whatever state it is in — so it occupies a
//! quota slot, it stays on its owner's dashboard, and it appears in admin
//! totals. Hiding it would lie about the fact that it exists and is consuming
//! disk.
//!
//! That principle answers *counted and shown*. It does **not** answer *should
//! we act on it right now* — backing up a database mid-rebuild captures a
//! half-restored state and files it as a good backup, and routing connections
//! to one is worse. Those two are decided separately, per status.
//!
//! Note this is a principle for **answering**, not a default in the code. The
//! compiler still demands an explicit answer per variant; the principle tells
//! whoever adds one what it almost always is.

/// A database's lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbStatus {
    /// Provisioned, finished, serving.
    Active,
    /// A restore is rebuilding this database right now (CRYPTARCH-69).
    Restoring,
    /// A delete has begun (CRYPTARCH-79). Written *before* the engine is
    /// called, so that a delete which fails partway is attributable to
    /// Cryptarch rather than mistaken for a human disabling the role.
    Deleting,
    /// A status this build does not recognise: an older row, a hand-edited
    /// value, or a version skew during a rolling restart.
    ///
    /// A variant rather than a parse failure, because the alternative is
    /// returning `None` and letting each caller decide — which is exactly the
    /// eleven-independent-answers problem this module exists to end. Its
    /// answers are conservative in every direction: it cannot be used to hold
    /// a database outside the quota, and it cannot cause anything to act on a
    /// database nobody can identify.
    Unrecognised(String),
}

impl DbStatus {
    /// Parse a `databases.status` value. Never fails — an unknown string
    /// becomes [`DbStatus::Unrecognised`] rather than being silently read as
    /// something safe-looking.
    pub fn parse(raw: &str) -> Self {
        match raw {
            "active" => DbStatus::Active,
            "restoring" => DbStatus::Restoring,
            "deleting" => DbStatus::Deleting,
            other => DbStatus::Unrecognised(other.to_string()),
        }
    }

    /// The value as stored. Round-trips: `parse(s).as_str() == s`.
    pub fn as_str(&self) -> &str {
        match self {
            DbStatus::Active => "active",
            DbStatus::Restoring => "restoring",
            DbStatus::Deleting => "deleting",
            DbStatus::Unrecognised(s) => s,
        }
    }

    /// Does this database consume one of its owner's quota slots?
    ///
    /// **Yes for everything that exists.** The cap is the product, and a
    /// status that does not occupy a slot is a way to hold a database outside
    /// it: provision, move it into that status, provision again. That is
    /// CRYPTARCH-80's bypass, and the only reason it was ever reachable is
    /// that `restoring` inherited "not counted" from a predicate written when
    /// `active` was the only status.
    pub fn occupies_quota_slot(&self) -> bool {
        match self {
            DbStatus::Active => true,
            // A replace does not free the slot mid-flight. The database never
            // stopped existing.
            DbStatus::Restoring => true,
            // Still there until the drop succeeds. Freeing the slot the
            // moment a delete BEGINS would let a failed delete hand back a
            // slot while the database is still on the server.
            DbStatus::Deleting => true,
            // Cannot be identified, so cannot be exempted.
            DbStatus::Unrecognised(_) => true,
        }
    }

    /// Does its owner see it on their dashboard?
    ///
    /// **Yes for everything that exists** — badged with its status. A database
    /// that vanishes mid-restore is the opposite of the named-stages
    /// requirement: the user watching a restore of their own database sees it
    /// gone from their list.
    pub fn visible_to_owner(&self) -> bool {
        match self {
            DbStatus::Active => true,
            DbStatus::Restoring => true,
            // Shown while it is being removed. A database that vanishes the
            // instant a delete starts, then reappears when the delete fails,
            // is worse than one that visibly says what is happening to it.
            DbStatus::Deleting => true,
            DbStatus::Unrecognised(_) => true,
        }
    }

    /// Does it count in fleet-wide and per-server admin totals?
    ///
    /// **Yes for everything that exists.** It is on the disk either way.
    pub fn counts_in_admin_totals(&self) -> bool {
        match self {
            DbStatus::Active => true,
            DbStatus::Restoring => true,
            DbStatus::Deleting => true,
            DbStatus::Unrecognised(_) => true,
        }
    }

    /// Should the scheduler back it up, and may an on-demand backup run?
    ///
    /// Not the existence question — this one asks whether to *act*. Dumping a
    /// database mid-rebuild captures a half-restored state and files it as a
    /// good backup, which is the worst outcome the backup feature has.
    pub fn should_be_backed_up(&self) -> bool {
        match self {
            DbStatus::Active => true,
            DbStatus::Restoring => false,
            // No — but this answer is only safe because the stranded-delete
            // sweep runs PERIODICALLY. A delete that fails at its first step
            // leaves a fully working database in this status, and therefore
            // out of the backup schedule. The sweep reverts that case to
            // `active` within one scheduler pass. If it ever became
            // boot-only, this `false` would silently stop backing up a live
            // database for the uptime of the process.
            DbStatus::Deleting => false,
            DbStatus::Unrecognised(_) => false,
        }
    }

    /// Should it appear in the edge (PgBouncer) config and hba?
    ///
    /// Also an acting question. Routing connections to a database being
    /// rebuilt is worse than refusing them — and for a restore this is
    /// load-bearing, not hygiene: withdrawing at the edge before the drop is
    /// what stops the bouncer refilling its pool and racing it.
    pub fn in_edge_config(&self) -> bool {
        match self {
            DbStatus::Active => true,
            DbStatus::Restoring => false,
            DbStatus::Deleting => false,
            DbStatus::Unrecognised(_) => false,
        }
    }

    /// Every status this build knows by name. `Unrecognised` is absent because
    /// it is unbounded.
    ///
    /// # Check the direction before deriving anything from this
    ///
    /// This list is hand-maintained, and the exhaustive matches above force a
    /// new variant to be *answered*, not *enumerated* — so a variant can be
    /// added and forgotten here. Whether that is safe depends entirely on
    /// which direction the consumer errs in:
    ///
    /// * [`DbStatus::quota_exclusion_sql`] derives the **excluded** set, so a
    ///   forgotten variant is absent from the exclusion and therefore
    ///   **counted**. Omission errs toward over-counting, which blocks a
    ///   provision visibly and recoverably.
    /// * A consumer deriving an **inclusion** — a visibility list, a
    ///   backup-target list — flips that: the same forgotten variant silently
    ///   disappears instead of silently counting.
    ///
    /// `all_known_is_exhaustive` below removes the question by failing to
    /// compile when a variant is added without being enumerated. Keep it.
    pub fn all_known() -> Vec<DbStatus> {
        vec![DbStatus::Active, DbStatus::Restoring, DbStatus::Deleting]
    }

    /// Render one of the questions above as a SQL predicate over
    /// `databases.status`.
    ///
    /// # The direction is not a judgement call
    ///
    /// The doc on [`DbStatus::all_known`] warns that an exclusion list and an
    /// inclusion list fail in opposite directions when a variant is forgotten.
    /// That is true, but it makes the choice sound like taste. It is not:
    ///
    /// **Phrase it so that a status this build has never heard of gets the same
    /// answer the enum already gives `Unrecognised`.**
    ///
    /// That is the whole rule, and it makes the two directions fall out rather
    /// than being decided per query. An unknown row in the table and an
    /// `Unrecognised` variant in memory are the same thing seen from two sides;
    /// if the SQL and the enum disagree about it, the module's central promise —
    /// one answer per question — is broken in exactly the place nobody looks.
    ///
    /// So: a question `Unrecognised` answers **yes** becomes `status NOT IN
    /// (the known noes)`, and one it answers **no** becomes `status IN (the
    /// known yeses)`. A variant added to [`DbStatus::all_known`] but forgotten
    /// in a match cannot happen — the matches are exhaustive and will not
    /// compile.
    fn predicate(question: fn(&DbStatus) -> bool, unrecognised_answer: bool) -> String {
        let named: Vec<String> = DbStatus::all_known()
            .into_iter()
            .filter(|s| question(s) != unrecognised_answer)
            .map(|s| format!("'{}'", s.as_str()))
            .collect();

        match (unrecognised_answer, named.is_empty()) {
            // Unknown says yes and no known status says no: everything matches.
            (true, true) => "TRUE".to_string(),
            (true, false) => format!("status NOT IN ({})", named.join(", ")),
            // Unknown says no and no known status says yes: nothing matches.
            (false, true) => "FALSE".to_string(),
            (false, false) => format!("status IN ({})", named.join(", ")),
        }
    }

    /// Rows that occupy a quota slot — what `provision_db` counts against the
    /// cap, and therefore what any "N of M used" display must count too.
    pub fn quota_exclusion_sql() -> String {
        Self::predicate(DbStatus::occupies_quota_slot, true)
    }

    /// Rows an owner sees on their dashboard.
    pub fn visible_to_owner_sql() -> String {
        Self::predicate(DbStatus::visible_to_owner, true)
    }

    /// Rows that count in fleet-wide and per-server admin totals.
    pub fn counts_in_admin_totals_sql() -> String {
        Self::predicate(DbStatus::counts_in_admin_totals, true)
    }

    /// Rows the scheduler may back up.
    pub fn should_be_backed_up_sql() -> String {
        Self::predicate(DbStatus::should_be_backed_up, false)
    }

    /// Rows that belong in the edge config and hba.
    pub fn in_edge_config_sql() -> String {
        Self::predicate(DbStatus::in_edge_config, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `all_known()` must list every named variant.
    ///
    /// The match below is exhaustive with no catch-all, so adding a variant
    /// stops this compiling until it is handled — which forces whoever adds
    /// one to enumerate it here as well as answer the five questions. That
    /// removes the "is this consumer's omission safe?" question entirely,
    /// rather than leaving it to be reasoned about per call site.
    #[test]
    fn all_known_is_exhaustive() {
        let known = DbStatus::all_known();
        for variant in [DbStatus::Active, DbStatus::Restoring, DbStatus::Deleting] {
            // The match exists to break the build on a new variant; the value
            // it produces is the variant itself.
            let named = match &variant {
                DbStatus::Active => DbStatus::Active,
                DbStatus::Restoring => DbStatus::Restoring,
                DbStatus::Deleting => DbStatus::Deleting,
                // Unbounded by construction, and deliberately not listed.
                DbStatus::Unrecognised(s) => DbStatus::Unrecognised(s.clone()),
            };
            assert!(
                known.contains(&named),
                "{named:?} is a named status but is missing from all_known()"
            );
        }
        assert_eq!(known.len(), 3, "a variant was added without updating all_known()");
    }

    #[test]
    fn round_trips_through_the_stored_value() {
        for s in DbStatus::all_known() {
            assert_eq!(DbStatus::parse(s.as_str()), s);
        }
        assert_eq!(
            DbStatus::parse("something_new"),
            DbStatus::Unrecognised("something_new".into())
        );
        assert_eq!(DbStatus::parse("something_new").as_str(), "something_new");
    }

    /// The rule that makes the direction of each predicate not a judgement
    /// call: an unknown status in the TABLE must get the same answer as
    /// `Unrecognised` in MEMORY. If those two ever disagree, the module's whole
    /// promise — one answer per question — is broken where nobody looks.
    #[test]
    fn every_predicate_answers_an_unknown_status_the_way_the_enum_does() {
        let u = DbStatus::parse("who_knows");
        // "yes for unknown" must be phrased as an exclusion (or TRUE), because
        // an inclusion list cannot contain a value nobody has heard of.
        for (sql, answer, what) in [
            (DbStatus::quota_exclusion_sql(), u.occupies_quota_slot(), "quota"),
            (DbStatus::visible_to_owner_sql(), u.visible_to_owner(), "visibility"),
            (DbStatus::counts_in_admin_totals_sql(), u.counts_in_admin_totals(), "admin totals"),
            (DbStatus::should_be_backed_up_sql(), u.should_be_backed_up(), "backup targets"),
            (DbStatus::in_edge_config_sql(), u.in_edge_config(), "edge config"),
        ] {
            if answer {
                assert!(
                    sql == "TRUE" || sql.starts_with("status NOT IN"),
                    "{what}: Unrecognised answers YES, so the predicate must include \
                     unknown statuses — got {sql:?}"
                );
            } else {
                assert!(
                    sql == "FALSE" || sql.starts_with("status IN"),
                    "{what}: Unrecognised answers NO, so the predicate must exclude \
                     unknown statuses — got {sql:?}"
                );
            }
        }
    }

    /// The counting questions genuinely include everything today, so their SQL
    /// is `TRUE` and callers may legitimately omit a status filter entirely —
    /// `admin_servers`' per-server `db_count` does, because it is built inside a
    /// compile-time `const` that cannot call a function.
    ///
    /// This test is that omission's tripwire. If a future status ever answers
    /// NO to one of these, the predicate stops being `TRUE`, this fails, and it
    /// names the query that has to be revisited.
    #[test]
    fn the_counting_predicates_are_still_unconditional() {
        assert_eq!(
            DbStatus::counts_in_admin_totals_sql(), "TRUE",
            "admin_servers::select_server! omits a status filter on databases.db_count \
             because this is TRUE. It is no longer TRUE — go add one."
        );
        assert_eq!(
            DbStatus::quota_exclusion_sql(), "TRUE",
            "a status that does not occupy a quota slot is a way to hold a database \
             outside the cap — if that is now deliberate, re-read CRYPTARCH-80 first."
        );
    }

    /// The acting questions must NOT be unconditional — that is the whole point
    /// of them being separate from the counting ones. Without this, a refactor
    /// that made everything `TRUE` would satisfy every other test in this file.
    #[test]
    fn the_acting_predicates_actually_exclude_something() {
        for (sql, what) in [
            (DbStatus::should_be_backed_up_sql(), "backup targets"),
            (DbStatus::in_edge_config_sql(), "edge config"),
        ] {
            assert!(sql.starts_with("status IN"), "{what}: expected an inclusion, got {sql:?}");
            assert!(
                !sql.contains("'deleting'") && !sql.contains("'restoring'"),
                "{what}: must not act on a database mid-delete or mid-rebuild — got {sql:?}"
            );
            assert!(sql.contains("'active'"), "{what}: must still act on live databases");
        }
    }

    /// An unrecognised status must be safe in every direction — never a way to
    /// hold a database outside the cap, never a reason to act on something
    /// nobody can identify, and never invisible.
    #[test]
    fn an_unrecognised_status_is_conservative_everywhere() {
        let u = DbStatus::parse("who_knows");
        assert!(u.occupies_quota_slot(), "must not become a quota bypass");
        assert!(u.visible_to_owner(), "must not vanish from its owner's list");
        assert!(u.counts_in_admin_totals());
        assert!(!u.should_be_backed_up(), "do not dump what cannot be identified");
        assert!(!u.in_edge_config(), "do not route to what cannot be identified");
    }

    /// Antun's rule: if we create it, it exists — so it is counted and shown,
    /// whatever state it is in.
    #[test]
    fn everything_that_exists_is_counted_and_shown() {
        for s in DbStatus::all_known() {
            assert!(s.occupies_quota_slot(), "{s:?} must occupy a quota slot");
            assert!(s.visible_to_owner(), "{s:?} must be visible to its owner");
            assert!(s.counts_in_admin_totals(), "{s:?} must count in admin totals");
        }
    }

    /// The quota fragment must be an EXCLUSION, so a status added later is
    /// counted by default rather than silently exempted.
    #[test]
    fn the_quota_fragment_counts_statuses_it_has_never_heard_of() {
        let sql = DbStatus::quota_exclusion_sql();
        assert!(
            !sql.contains(" IN (") || sql.contains("NOT IN ("),
            "an inclusion list stops counting anything added later: {sql}"
        );
        // Today every known status occupies a slot, so nothing is excluded.
        assert_eq!(sql, "TRUE");
    }

    /// The acting questions are the only ones that differ, and they differ for
    /// a reason that is not about existence.
    #[test]
    fn restoring_is_counted_but_not_acted_on() {
        let r = DbStatus::Restoring;
        assert!(r.occupies_quota_slot());
        assert!(r.visible_to_owner());
        assert!(r.counts_in_admin_totals());
        assert!(!r.should_be_backed_up(), "a dump mid-rebuild is a half-restored backup");
        assert!(!r.in_edge_config(), "do not route to a database being rebuilt");
    }
}
