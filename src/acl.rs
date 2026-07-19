//! The ACL model and hba renderer (CRYPTARCH-12) — MySQL `user@host`
//! semantics, delivered at the edge.
//!
//! `acl_entries` is the source of truth; this module renders it into the
//! bouncer's hba file deterministically and reloads the console. Suspended
//! databases contribute no lines (unreachable at the edge, not just
//! role-disabled). A database with no entries is unreachable — default-deny
//! is structural: PgBouncer rejects whatever no hba line admits.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::Crypto;
use crate::edge;

/// One rendered rule: database + user (identical by construction) + source.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AclRule {
    pub db_name: String,
    pub cidr: String,
}

/// Deterministic hba render. Pure — unit-tested hard, no I/O.
///
/// Layout: checksum header (drift detection), console line, one line per
/// rule ordered (db, cidr). `hostssl` when the server terminates TLS at the
/// edge, plain `host` otherwise.
pub fn render_hba(rules: &[AclRule], tls_mode: &str) -> String {
    // Exhaustive on purpose: a future third mode must not silently fail
    // open toward no-TLS.
    let conn_type = match tls_mode {
        "edge" => "hostssl",
        "off" => "host",
        other => {
            tracing::error!("unknown tls_mode '{other}' — rendering as plain host");
            "host"
        }
    };
    let mut sorted: Vec<&AclRule> = rules.iter().collect();
    sorted.sort_by(|a, b| (&a.db_name, &a.cidr).cmp(&(&b.db_name, &b.cidr)));

    let mut body = String::new();
    body.push_str("host pgbouncer pgbadmin 0.0.0.0/0 scram-sha-256\n");
    for r in sorted {
        // Values are schema-validated (CIDR column, name allowlist), but the
        // renderer is the last line of defense — and it must hold in release
        // builds, not just under debug_assert. A value that could smuggle a
        // second rule drops the rule (fail closed) and screams.
        if r.db_name.contains(char::is_whitespace) || r.cidr.contains(char::is_whitespace) {
            tracing::error!(
                "refusing to render ACL rule with whitespace (db={:?}, cidr={:?}) — upstream invariant broken",
                r.db_name, r.cidr
            );
            continue;
        }
        body.push_str(&format!(
            "{conn_type} {db} {db} {cidr} scram-sha-256\n",
            db = r.db_name,
            cidr = r.cidr,
        ));
    }

    let checksum = hex(&Sha256::digest(body.as_bytes()));
    format!(
        "# managed by cryptarch — rendered from acl_entries; do not hand-edit\n\
         # checksum: {checksum}\n\
         {body}"
    )
}

/// Extract the checksum a rendered file claims, for drift detection.
pub fn claimed_checksum(content: &str) -> Option<&str> {
    content
        .lines()
        .find_map(|l| l.strip_prefix("# checksum: "))
        .map(str::trim)
}

/// Recompute the checksum of a file's body (everything after the header).
pub fn body_checksum(content: &str) -> String {
    let body: String = content
        .lines()
        .filter(|l| !l.starts_with('#'))
        .fold(String::new(), |mut acc, l| {
            acc.push_str(l);
            acc.push('\n');
            acc
        });
    hex(&Sha256::digest(body.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Load the active rules for a server: entries whose database is active.
pub async fn load_rules(db: &sqlx::PgPool, server_id: Uuid) -> anyhow::Result<Vec<AclRule>> {
    Ok(sqlx::query_as::<_, AclRule>(
        "SELECT d.name AS db_name, a.cidr::text AS cidr \
         FROM acl_entries a JOIN databases d ON d.id = a.database_id \
         WHERE d.server_id = $1 AND d.status = 'active'",
    )
    .bind(server_id)
    .fetch_all(db)
    .await?)
}

/// Outcome of an edge sync, for UI/audit.
pub enum SyncOutcome {
    /// Written and reloaded (rule count).
    Applied(usize),
    /// Rendered but nowhere to write — no conf dir configured.
    ManualPlacement { hba: String, knobs: String },
}

/// Serializes read-state → render → write → RELOAD so two concurrent ACL
/// mutations can't interleave into a stale final file (single process, so a
/// process-wide lock suffices; the critical section is milliseconds).
static EDGE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Render the server's ACL state, write it to the bouncer conf dir, RELOAD.
/// The single choke-point every ACL mutation and lifecycle change funnels
/// through. Failure marks the server edge_dirty (bannered in the UI until a
/// sync succeeds) AND surfaces to the caller — a revocation that didn't
/// reach the edge must never look like it did.
pub async fn sync_edge(
    db: &sqlx::PgPool,
    crypto: &Crypto,
    server_id: Uuid,
) -> anyhow::Result<SyncOutcome> {
    let result = sync_edge_inner(db, crypto, server_id).await;
    // ManualPlacement is a MODE, not a failure — the operator owns the file
    // there, and flagging it dirty forever would cry wolf. Only a real
    // failed Applied-path sync is dirty.
    let dirty = result.is_err();
    let _ = sqlx::query(
        "UPDATE managed_servers SET edge_dirty = $2, \
         edge_synced_at = CASE WHEN $2 THEN edge_synced_at ELSE now() END \
         WHERE id = $1",
    )
    .bind(server_id)
    .bind(dirty)
    .execute(db)
    .await;
    result
}

async fn sync_edge_inner(
    db: &sqlx::PgPool,
    crypto: &Crypto,
    server_id: Uuid,
) -> anyhow::Result<SyncOutcome> {
    let _guard = EDGE_LOCK.lock().await;

    let (conf_dir, bouncer_dsn_enc, tls_mode): (Option<String>, Vec<u8>, String) =
        sqlx::query_as(
            "SELECT bouncer_conf_dir, bouncer_admin_dsn_enc, tls_mode \
             FROM managed_servers WHERE id = $1",
        )
        .bind(server_id)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no such server"))?;

    let rules = load_rules(db, server_id).await?;
    let rendered = render_hba(&rules, &tls_mode);

    // Knobs ride the same sync: pool settings are edge state exactly like
    // ACLs, and a single RELOAD applies both files.
    let knobs = crate::bouncer::load_server_knobs(db, server_id).await?;
    let overrides = crate::bouncer::load_overrides(db, server_id).await?;
    let rendered_knobs = crate::bouncer::render_knobs(&knobs, &overrides);

    let Some(dir) = conf_dir.filter(|d| !d.is_empty()) else {
        return Ok(SyncOutcome::ManualPlacement { hba: rendered, knobs: rendered_knobs });
    };

    let dir = std::path::Path::new(&dir);
    let path = dir.join("pgbouncer_hba.conf");
    edge::atomic_write(&path, &rendered, 0o644)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    let knobs_path = dir.join(crate::bouncer::KNOBS_FILE);
    edge::atomic_write(&knobs_path, &rendered_knobs, 0o644)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", knobs_path.display()))?;

    if !bouncer_dsn_enc.is_empty() {
        let dsn = crypto.open(&bouncer_dsn_enc)?;
        edge::console_command(&dsn, "RELOAD").await?;
    }
    Ok(SyncOutcome::Applied(rules.len()))
}

/// Disconnect live edge sessions for one database (suspend/delete). Console
/// KILL is best-effort: the hba line is already gone, so new connections are
/// refused regardless; KILL just evicts the ones already inside.
pub async fn kill_db_sessions(db: &sqlx::PgPool, crypto: &Crypto, server_id: Uuid, db_name: &str) {
    let dsn_enc: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT bouncer_admin_dsn_enc FROM managed_servers WHERE id = $1")
            .bind(server_id)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    let Some(enc) = dsn_enc.filter(|e| !e.is_empty()) else { return };
    let Ok(dsn) = crypto.open(&enc) else { return };
    // KILL takes a database name; ours are allowlist-validated identifiers.
    if let Err(e) = edge::console_command(&dsn, &format!("KILL {db_name}")).await {
        tracing::warn!("console KILL {db_name}: {e} (non-fatal — hba already denies)");
    }
    let _ = edge::console_command(&dsn, &format!("RESUME {db_name}")).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(db: &str, cidr: &str) -> AclRule {
        AclRule { db_name: db.into(), cidr: cidr.into() }
    }

    #[test]
    fn renders_deterministically_sorted() {
        let a = render_hba(&[rule("beta", "10.0.0.0/24"), rule("alpha", "10.1.0.0/16")], "off");
        let b = render_hba(&[rule("alpha", "10.1.0.0/16"), rule("beta", "10.0.0.0/24")], "off");
        assert_eq!(a, b);
        let alpha_pos = a.find("alpha").unwrap();
        let beta_pos = a.find("beta").unwrap();
        assert!(alpha_pos < beta_pos, "rules must be sorted by (db, cidr)");
    }

    #[test]
    fn console_line_always_present_and_first_rule() {
        let out = render_hba(&[], "off");
        assert!(out.contains("host pgbouncer pgbadmin 0.0.0.0/0 scram-sha-256"));
        // empty ACL = deny everything except console
        assert_eq!(out.lines().filter(|l| !l.starts_with('#')).count(), 1);
    }

    #[test]
    fn tls_mode_switches_conn_type() {
        let off = render_hba(&[rule("app", "10.0.0.0/24")], "off");
        assert!(off.contains("\nhost app app 10.0.0.0/24 scram-sha-256"));
        let edge = render_hba(&[rule("app", "10.0.0.0/24")], "edge");
        assert!(edge.contains("\nhostssl app app 10.0.0.0/24 scram-sha-256"));
        // console line stays plain host either way (compose-internal hop)
        assert!(edge.contains("host pgbouncer pgbadmin"));
    }

    #[test]
    fn checksum_roundtrip_and_tamper_detection() {
        let out = render_hba(&[rule("app", "10.0.0.0/24")], "off");
        let claimed = claimed_checksum(&out).expect("header present");
        assert_eq!(claimed, body_checksum(&out), "fresh render must verify");

        let tampered = out.replace("10.0.0.0/24", "0.0.0.0/0");
        assert_ne!(claimed_checksum(&tampered).unwrap(), body_checksum(&tampered));
    }

    #[test]
    fn multiple_cidrs_per_db() {
        let out = render_hba(
            &[rule("app", "10.0.0.0/24"), rule("app", "10.10.12.33/32")],
            "off",
        );
        assert_eq!(out.matches("host app app").count(), 2);
    }
}
