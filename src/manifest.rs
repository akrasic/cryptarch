//! What a backup contains, recorded at dump time (CRYPTARCH-67).
//!
//! A restore has to answer questions the dump itself cannot: what encoding and
//! collation to create the target database with, which extensions it needs,
//! and whether the archive carries RLS policies or grants that name roles which
//! may not exist any more. The original plan was to answer those by querying
//! the live source at restore time. That is wrong twice: it is impossible for
//! the case that matters most — restoring a database that no longer exists —
//! and it is *misleading* even when a source does exist, because the live
//! catalog describes the database as it is NOW, not as the blob is. Policies
//! added since the dump would be warned about though they are not in the
//! archive; policies dropped since would be silently absent though they are.
//!
//! So the survey happens at dump time and travels inside the blob's
//! authenticated header. Integrity, not secrecy, is the property that matters
//! here: a forgeable "no hazards" would be read as reassurance at exactly the
//! moment someone is deciding whether a restore is safe.
//!
//! # Scope: this inventories RESTORE-RESOLUTION hazards, not security exposure
//!
//! The question asked here is "what stops cleanly resolving after a restore
//! under a different identity" — policies and grants naming roles that may not
//! exist, functions whose effective privileges change, extensions needing a
//! superuser. It is NOT an audit of who can read the data.
//!
//! The two diverge on `PUBLIC` specifically. A `GRANT ... TO PUBLIC` is not
//! recorded, because PUBLIC always exists and therefore always resolves. But on
//! a shared server a restored copy carrying such a grant is readable by every
//! role on that server, including tenants with no business in it. Whether that
//! is even reachable depends on the restore's flags — `--no-privileges` strips
//! grants entirely and the question disappears. Anything built on top of this
//! must not present it as a completeness claim it does not make.
//!
//! # Known bound: the survey and the dump see different snapshots
//!
//! `survey()` runs on its own connection and `pg_dump` on another, so a policy
//! dropped between the two makes the manifest report it while the archive lacks
//! it — harmless — and one CREATED between them makes the manifest silent about
//! something the archive contains, which is a small hole in the guarantee
//! below. Closing it properly means exporting a snapshot and handing it to
//! `pg_dump --snapshot`; until then this is a documented bound, not an
//! assumption to build on. Anything reasoning about the manifest must not
//! treat it as describing the same instant as the dump.
//!
//! # The rule this module exists to enforce
//!
//! **An operator is never told "no hazards" about a blob we have not actually
//! inspected.** Absence of a manifest, an unreadable manifest, or a manifest
//! written before a hazard category existed all mean UNKNOWN — never "none".
//! Every type here is shaped to make the safe answer the easy one, because the
//! unsafe answer (`Vec::default()` → empty → "we checked, it's clean") is what
//! you get for free from serde otherwise.

use serde::{Deserialize, Serialize};

/// Schema version written by this build.
pub const SCHEMA: u32 = 2;

/// Schema version at which each hazard category began being recorded.
///
/// This is the answer to "a manifest older than a hazard category has no field
/// for it, and every natural default reads as 'no hazards of that kind'". A
/// category's absence is only ever reported as *unknown* below its introducing
/// version, never as empty.
mod introduced {
    pub const POLICIES: u32 = 1;
    pub const FORCE_RLS: u32 = 1;
    /// Bumped to 2: schema 1 enumerated grants only on tables, views and
    /// matviews, missing sequences, foreign tables, schemas, functions and
    /// default ACLs — all of which the deleted-database restore path replays.
    /// A schema-1 manifest therefore cannot answer the grants question, and
    /// this is what makes it report UNKNOWN rather than a short list read as
    /// complete.
    pub const NON_OWNER_GRANTS: u32 = 2;
    pub const SECURITY_DEFINER: u32 = 1;
    pub const FOREIGN_SERVERS: u32 = 1;
    pub const EVENT_TRIGGERS: u32 = 1;
}

/// A fact we either know or explicitly do not.
///
/// Deliberately not `Option<T>`: `Option` invites `unwrap_or_default()`, which
/// turns "we don't know" into "there are none" at the call site with no
/// ceremony. `Known` makes the caller name the unknown case, and carries the
/// reason so the UI can say *why* it cannot answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Known<T> {
    Known(T),
    Unknown(&'static str),
}

impl<T> Known<T> {
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known(_))
    }

    /// The value, or `None` if unknown. Named so that reaching for it reads as
    /// a decision rather than an accessor.
    pub fn known_or_none(&self) -> Option<&T> {
        match self {
            Self::Known(v) => Some(v),
            Self::Unknown(_) => None,
        }
    }

    pub fn why_unknown(&self) -> Option<&'static str> {
        match self {
            Self::Known(_) => None,
            Self::Unknown(why) => Some(why),
        }
    }
}

/// A value we either read, or explicitly failed to read.
///
/// The serialisable sibling of [`Known`], for facts that come from columns
/// which do not exist on every server version. `Option<String>` cannot express
/// the difference between "this server has nothing to say" and "we never
/// managed to ask", and that difference is the whole point: a `None` collation
/// version reads as "no drift risk recorded" when it may mean "the query
/// failed". This is the same trap as an empty `aux` meaning no hazards, one
/// file over.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Recorded<T> {
    /// Read successfully. `None` inside means the server genuinely has no value.
    Value(Option<T>),
    NotRecorded { why: String },
}

impl<T> Recorded<T> {
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Value(v) => v.as_ref(),
            Self::NotRecorded { .. } => None,
        }
    }
    pub fn was_read(&self) -> bool {
        matches!(self, Self::Value(_))
    }
}

/// Properties of the source database that a restore must reproduce and cannot
/// recover from the dump itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DbProperties {
    pub encoding: String,
    pub collate: String,
    pub ctype: String,
    /// `c`, `i` (ICU), or `b` on newer servers — how collation is resolved.
    pub locale_provider: Recorded<String>,
    /// Named `daticulocale` before PostgreSQL 17 and `datlocale` from 17 on.
    pub icu_locale: Recorded<String>,
    /// The collation library version the source was using. A restore onto a box
    /// with a different one silently produces wrong index ordering on text
    /// columns — the same species of failure as a partial backup that looks
    /// complete. Which is why it must not be able to read as absent when it was
    /// merely unasked.
    pub coll_version: Recorded<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Extension {
    pub name: String,
    pub version: String,
    /// Trusted extensions can be created by a database owner; untrusted ones
    /// need a superuser, which the panel role deliberately is not. Recording it
    /// lets a restore predict the failure instead of discovering it.
    pub trusted: bool,
}

/// A policy, WITHOUT its expression.
///
/// `pg_policies.qual` is deliberately not stored: policy expressions embed
/// literals (`USING (tenant_id = 'acme-corp')`), so keeping them verbatim would
/// leak tenant data into a record described as holding none. The name, table
/// and referenced roles are what a restore decision actually needs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyRef {
    pub name: String,
    pub table: String,
    pub roles: Vec<String>,
}

/// A privilege held by someone other than the owner.
///
/// `kind` matters because the enumeration spans several catalogs: a role named
/// only in a schema or sequence grant is just as capable of aborting a restore
/// as one named on a table, and the operator needs to know where to look.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GrantRef {
    /// "table", "sequence", "schema", "function", "default" …
    pub kind: String,
    pub object: String,
    pub grantee: String,
    pub privilege: String,
}

/// Everything that makes restoring under a different identity risky.
///
/// Every field is REQUIRED in the serialized form. `#[serde(default)]` here
/// would be the classic version of this bug: a manifest missing its `policies`
/// field would deserialize to an empty vector, which reads as "checked, found
/// nothing" when it means "never recorded".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Hazards {
    pub rls_tables: Vec<String>,
    pub force_rls_tables: Vec<String>,
    pub policies: Vec<PolicyRef>,
    pub non_owner_grants: Vec<GrantRef>,
    pub security_definer_functions: Vec<String>,
    pub foreign_servers: Vec<String>,
    pub event_triggers: Vec<String>,
    pub large_objects: i64,
}

impl Hazards {
    /// Is there anything here that makes a restore under a new role risky?
    pub fn any(&self) -> bool {
        !self.force_rls_tables.is_empty()
            || !self.policies.is_empty()
            || !self.non_owner_grants.is_empty()
            || !self.security_definer_functions.is_empty()
            || !self.foreign_servers.is_empty()
            || !self.event_triggers.is_empty()
    }
}

/// The recorded description of one backup's contents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub db_name: String,
    pub owner: String,
    /// The database's id at backup time. Names are freed on delete and
    /// reusable, so this is what tells a restore whether the `app` it is about
    /// to reconstruct is the same `app` that was backed up, or a stranger's.
    pub database_id: Option<uuid::Uuid>,
    pub server_id: Option<uuid::Uuid>,
    pub taken_at: chrono::DateTime<chrono::Utc>,
    pub server_version: String,
    pub client_version: String,
    pub properties: DbProperties,
    pub extensions: Vec<Extension>,
    pub hazards: Hazards,
}

/// What we know about a blob's manifest — including that we do not have one.
///
/// The three non-present cases are distinct on purpose. "This backup predates
/// manifests" and "this manifest is corrupt" call for different operator
/// responses, and neither is "there are no hazards".
#[derive(Debug, Clone)]
pub enum ManifestState {
    Present(Box<Manifest>),
    /// The blob carries no manifest at all — written before manifests existed.
    Absent,
    /// A manifest is there but cannot be trusted: unparseable, or written by a
    /// schema this build does not understand.
    Unreadable(String),
}

impl ManifestState {
    /// Decode a blob's `aux` section.
    ///
    /// An EMPTY aux is [`ManifestState::Absent`], not an empty manifest. Every
    /// blob written before this feature has a zero-length aux, and empty and
    /// absent are the same bytes — which is exactly why this is spelled out
    /// here rather than left to whatever `serde` does with `[]`.
    pub fn decode(aux: &[u8]) -> Self {
        if aux.is_empty() {
            return Self::Absent;
        }
        // Read the schema before the body: a manifest from a future build may
        // contain categories this one has never heard of, and parsing it with
        // today's struct would silently drop them.
        let value: serde_json::Value = match serde_json::from_slice(aux) {
            Ok(v) => v,
            Err(e) => return Self::Unreadable(format!("manifest is not valid JSON: {e}")),
        };
        let schema = match value.get("schema").and_then(|s| s.as_u64()) {
            Some(s) => s as u32,
            None => return Self::Unreadable("manifest has no schema version".into()),
        };
        if schema > SCHEMA {
            return Self::Unreadable(format!(
                "manifest was written by a newer Cryptarch (schema {schema}, this build reads {SCHEMA})"
            ));
        }
        match serde_json::from_value::<Manifest>(value) {
            Ok(m) => Self::Present(Box::new(m)),
            Err(e) => Self::Unreadable(format!("manifest could not be read: {e}")),
        }
    }

    /// The hazards, or why they are not knowable.
    ///
    /// A category recorded only from a later schema resolves to `Unknown`, not
    /// to an empty list — a manifest predating a hazard category says nothing
    /// about it, and saying nothing is not the same as saying none.
    pub fn hazards(&self) -> Known<&Hazards> {
        match self {
            // Covers both "taken before manifests existed" and "the survey
            // failed at backup time" — from a restore's point of view they are
            // the same answer, and it is not "none".
            Self::Absent => Known::Unknown(
                "no record of this backup's contents was stored, so its hazards are unknown",
            ),
            Self::Unreadable(_) => {
                Known::Unknown("the record of this backup's contents could not be read")
            }
            Self::Present(m) => {
                let needed = [
                    introduced::POLICIES,
                    introduced::FORCE_RLS,
                    introduced::NON_OWNER_GRANTS,
                    introduced::SECURITY_DEFINER,
                    introduced::FOREIGN_SERVERS,
                    introduced::EVENT_TRIGGERS,
                ];
                if needed.iter().any(|v| m.schema < *v) {
                    return Known::Unknown(
                        "this backup predates some of the checks Cryptarch now makes",
                    );
                }
                Known::Known(&m.hazards)
            }
        }
    }

    /// The database properties a restore needs to recreate the target.
    pub fn properties(&self) -> Known<&DbProperties> {
        match self {
            Self::Present(m) => Known::Known(&m.properties),
            Self::Absent => Known::Unknown(
                "no record of this backup's encoding and collation was stored",
            ),
            Self::Unreadable(_) => {
                Known::Unknown("the record of this backup's contents could not be read")
            }
        }
    }

    pub fn manifest(&self) -> Option<&Manifest> {
        match self {
            Self::Present(m) => Some(m),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A complete manifest with hazards (one policy); shared with the web
    /// module's badge tests.
    pub(crate) fn sample() -> Manifest {
        Manifest {
            schema: SCHEMA,
            db_name: "alice_app".into(),
            owner: "alice_app".into(),
            database_id: Some(uuid::Uuid::nil()),
            server_id: Some(uuid::Uuid::nil()),
            taken_at: chrono::Utc::now(),
            server_version: "17.5".into(),
            client_version: "pg_dump (PostgreSQL) 18.4".into(),
            properties: DbProperties {
                encoding: "UTF8".into(),
                collate: "en_US.utf8".into(),
                ctype: "en_US.utf8".into(),
                locale_provider: Recorded::Value(Some("c".into())),
                icu_locale: Recorded::Value(None),
                coll_version: Recorded::Value(Some("2.41".into())),
            },
            extensions: vec![Extension {
                name: "pgcrypto".into(),
                version: "1.3".into(),
                trusted: true,
            }],
            hazards: Hazards {
                rls_tables: vec!["events".into()],
                force_rls_tables: vec![],
                policies: vec![PolicyRef {
                    name: "tenant_isolation".into(),
                    table: "events".into(),
                    roles: vec!["reporting".into()],
                }],
                non_owner_grants: vec![],
                security_definer_functions: vec![],
                foreign_servers: vec![],
                event_triggers: vec![],
                large_objects: 0,
            },
        }
    }

    #[test]
    fn an_empty_aux_means_unknown_not_none() {
        // THE trap: every blob written before manifests existed has a
        // zero-length aux, and empty and absent are the same bytes. If this
        // ever returns Known(empty), a restore of an older backup will report
        // "no hazards" about a database nobody ever inspected.
        let state = ManifestState::decode(&[]);
        assert!(matches!(state, ManifestState::Absent));
        assert!(!state.hazards().is_known(), "an absent manifest must not read as 'no hazards'");
        assert!(!state.properties().is_known());
        assert!(state.hazards().why_unknown().unwrap().contains("unknown"));
    }

    #[test]
    fn a_missing_hazard_field_is_an_error_not_an_empty_list() {
        // Without `deny_unknown_fields` and required fields, a manifest missing
        // `policies` would deserialize to an empty Vec, which reads as
        // "checked, found nothing".
        let mut value = serde_json::to_value(sample()).unwrap();
        value["hazards"].as_object_mut().unwrap().remove("policies");
        let bytes = serde_json::to_vec(&value).unwrap();

        let state = ManifestState::decode(&bytes);
        assert!(
            matches!(state, ManifestState::Unreadable(_)),
            "a manifest missing a hazard field must not parse, got {state:?}"
        );
        assert!(!state.hazards().is_known());
    }

    #[test]
    fn a_manifest_predating_a_widened_check_reports_unknown_not_a_short_list() {
        // Schema 1 enumerated grants on tables only. Schema 2 added sequences,
        // schemas, functions and default ACLs — all of which a restore replays.
        // A schema-1 manifest therefore cannot answer the grants question, and
        // reporting its short list as complete is exactly the failure this
        // whole module exists to prevent. It must read as UNKNOWN.
        let mut m = sample();
        m.schema = 1;
        let state = ManifestState::decode(&serde_json::to_vec(&m).unwrap());
        assert!(
            matches!(state, ManifestState::Present(_)),
            "an older manifest still parses"
        );
        assert!(
            !state.hazards().is_known(),
            "but its hazards are not answerable, because one category post-dates it"
        );
        assert!(state.hazards().why_unknown().unwrap().contains("predates"));
        // Properties are unaffected — they did not change between schemas.
        assert!(state.properties().is_known());
    }

    #[test]
    fn a_manifest_from_a_newer_build_is_unreadable_not_trusted() {
        // A future schema may record categories this build has never heard of;
        // parsing it with today's struct would silently drop them and report
        // whatever remained as the whole truth.
        let mut value = serde_json::to_value(sample()).unwrap();
        value["schema"] = serde_json::json!(SCHEMA + 1);
        let state = ManifestState::decode(&serde_json::to_vec(&value).unwrap());
        match &state {
            ManifestState::Unreadable(why) => assert!(why.contains("newer")),
            other => panic!("expected Unreadable, got {other:?}"),
        }
        assert!(!state.hazards().is_known());
    }

    #[test]
    fn corrupt_bytes_are_unreadable_not_empty() {
        for bad in [&b"{"[..], &b"not json at all"[..], &[0xff, 0xfe][..]] {
            let state = ManifestState::decode(bad);
            assert!(
                matches!(state, ManifestState::Unreadable(_)),
                "corrupt manifest must be Unreadable, got {state:?}"
            );
            assert!(!state.hazards().is_known());
        }
    }

    #[test]
    fn a_manifest_without_a_schema_is_unreadable() {
        let mut value = serde_json::to_value(sample()).unwrap();
        value.as_object_mut().unwrap().remove("schema");
        let state = ManifestState::decode(&serde_json::to_vec(&value).unwrap());
        assert!(matches!(state, ManifestState::Unreadable(_)));
    }

    #[test]
    fn a_complete_manifest_round_trips_and_reports_its_hazards() {
        let m = sample();
        let bytes = serde_json::to_vec(&m).unwrap();
        let state = ManifestState::decode(&bytes);
        let hazards = state.hazards();
        assert!(hazards.is_known(), "a current manifest is knowable");
        let h = hazards.known_or_none().unwrap();
        assert_eq!(h.policies.len(), 1);
        assert!(h.any(), "a policy naming another role is a hazard");
        assert_eq!(state.properties().known_or_none().unwrap().encoding, "UTF8");
    }

    #[test]
    fn policy_expressions_are_never_recorded() {
        // Policy expressions embed literals — `USING (tenant_id = 'acme-corp')`
        // is tenant data. The serialized form must carry names and roles only.
        let json = serde_json::to_string(&sample()).unwrap();
        assert!(json.contains("tenant_isolation"), "policy name is recorded");
        assert!(!json.contains("qual"), "policy expressions must not be stored");
        assert!(!json.contains("USING"), "policy expressions must not be stored");
    }

    #[test]
    fn an_empty_hazard_set_is_distinguishable_from_an_unknown_one() {
        let mut m = sample();
        m.hazards = Hazards {
            rls_tables: vec![],
            force_rls_tables: vec![],
            policies: vec![],
            non_owner_grants: vec![],
            security_definer_functions: vec![],
            foreign_servers: vec![],
            event_triggers: vec![],
            large_objects: 0,
        };
        let state = ManifestState::decode(&serde_json::to_vec(&m).unwrap());
        let hazards = state.hazards();
        assert!(hazards.is_known(), "an inspected database with no hazards IS knowable");
        assert!(!hazards.known_or_none().unwrap().any());

        // …and that is a different answer from never having looked.
        assert!(!ManifestState::decode(&[]).hazards().is_known());
    }
}
