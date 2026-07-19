//! Bouncer knobs renderer (CRYPTARCH-32) — pool settings as portal state.
//!
//! `managed_servers` + per-database overrides are the source of truth; this
//! module renders them into an ini fragment (`cryptarch_bouncer.ini`) that
//! the operator's `pgbouncer.ini` pulls in via `%include` at its end — so
//! rendered values win over the static baseline. Written and RELOADed by the
//! same edge-sync choke point as the hba file.
//!
//! Database name == role name by construction, so per-database limits ride
//! `[users]` lines (`max_user_connections`, `pool_mode`) — no backend
//! host/port knowledge needed, which a `[databases]` line would require.

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The rendered fragment's filename inside the bouncer conf dir.
pub const KNOBS_FILE: &str = "cryptarch_bouncer.ini";

/// Server-wide pool settings (the `[pgbouncer]` section of the fragment).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ServerKnobs {
    pub pool_mode: String,
    pub default_pool_size: i32,
    pub max_client_conn: i32,
    /// 0 = unlimited (PgBouncer's convention).
    pub max_db_connections: i32,
    /// 0 = unlimited.
    pub max_user_connections: i32,
}

/// One database's overrides (a `[users]` line — db name == role name).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DbOverride {
    pub db_name: String,
    pub pool_mode: Option<String>,
    pub max_connections: Option<i32>,
}

fn valid_mode(mode: &str) -> bool {
    matches!(mode, "session" | "transaction")
}

/// Deterministic knobs render. Pure — unit-tested hard, no I/O.
///
/// Layout: checksum header (drift detection), bare `[pgbouncer]`-section keys,
/// then one `[users]` line per database that overrides anything, sorted by
/// name.
///
/// DELIBERATELY HEADERLESS: the fragment must NOT open its own `[pgbouncer]`
/// section. PgBouncer (verified on 1.24.1) treats a second `[pgbouncer]`
/// header as a section reset — every key the fragment doesn't repeat
/// (auth_type, admin_users, auth_hba_file, ...) reverts to its default,
/// which locks out the console and breaks consumer auth. Instead the
/// `%include` sits at the very end of the operator's ini, inside its still
/// open `[pgbouncer]` section, and these keys simply continue it.
pub fn render_knobs(server: &ServerKnobs, overrides: &[DbOverride]) -> String {
    // Values are schema-validated (CHECK constraints), but the renderer is
    // the last line of defense: an unknown mode falls back to session (the
    // transparent default) and screams rather than emitting garbage config.
    let pool_mode = if valid_mode(&server.pool_mode) {
        server.pool_mode.as_str()
    } else {
        tracing::error!("unknown pool_mode '{}' — rendering as session", server.pool_mode);
        "session"
    };
    let mut body = format!(
        "pool_mode = {pool_mode}\n\
         default_pool_size = {}\n\
         max_client_conn = {}\n\
         max_db_connections = {}\n\
         max_user_connections = {}\n",
        server.default_pool_size,
        server.max_client_conn,
        server.max_db_connections,
        server.max_user_connections,
    );

    let mut with_overrides: Vec<&DbOverride> = overrides
        .iter()
        .filter(|o| o.pool_mode.is_some() || o.max_connections.is_some())
        .collect();
    with_overrides.sort_by(|a, b| a.db_name.cmp(&b.db_name));

    let mut user_lines = String::new();
    for o in with_overrides {
        // Names are allowlist-validated upstream, but a value that could
        // smuggle a second directive drops the line (fail closed) and screams.
        if o.db_name.contains(char::is_whitespace)
            || o.db_name.contains('=')
            || o.db_name.contains('[')
        {
            tracing::error!(
                "refusing to render knobs for db {:?} — upstream name invariant broken",
                o.db_name
            );
            continue;
        }
        let mut opts = Vec::new();
        if let Some(mode) = o.pool_mode.as_deref() {
            if valid_mode(mode) {
                opts.push(format!("pool_mode={mode}"));
            } else {
                tracing::error!("unknown pool_mode override '{mode}' for {} — dropped", o.db_name);
            }
        }
        if let Some(n) = o.max_connections {
            opts.push(format!("max_user_connections={n}"));
        }
        if !opts.is_empty() {
            user_lines.push_str(&format!("{} = {}\n", o.db_name, opts.join(" ")));
        }
    }
    if !user_lines.is_empty() {
        body.push_str("\n[users]\n");
        body.push_str(&user_lines);
    }

    let checksum = hex(&Sha256::digest(body.as_bytes()));
    format!(
        "; managed by cryptarch — rendered from pool settings; do not hand-edit\n\
         ; checksum: {checksum}\n\
         {body}"
    )
}

/// Extract the checksum a rendered fragment claims, for drift detection.
pub fn claimed_checksum(content: &str) -> Option<&str> {
    content
        .lines()
        .find_map(|l| l.strip_prefix("; checksum: "))
        .map(str::trim)
}

/// Recompute the checksum of a fragment's body (everything after comments).
pub fn body_checksum(content: &str) -> String {
    let body: String = content
        .lines()
        .filter(|l| !l.starts_with(';'))
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

/// Load a server's pool settings.
pub async fn load_server_knobs(db: &sqlx::PgPool, server_id: Uuid) -> anyhow::Result<ServerKnobs> {
    Ok(sqlx::query_as::<_, ServerKnobs>(
        "SELECT pool_mode, default_pool_size, max_client_conn, \
                max_db_connections, max_user_connections \
         FROM managed_servers WHERE id = $1",
    )
    .bind(server_id)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| anyhow::anyhow!("no such server"))?)
}

/// Load all per-database overrides for a server. Suspended databases keep
/// their lines — the limit must survive a suspend/resume cycle, and the hba
/// (not this file) is what makes a suspended db unreachable.
pub async fn load_overrides(db: &sqlx::PgPool, server_id: Uuid) -> anyhow::Result<Vec<DbOverride>> {
    Ok(sqlx::query_as::<_, DbOverride>(
        "SELECT name AS db_name, pool_mode, max_connections \
         FROM databases WHERE server_id = $1",
    )
    .bind(server_id)
    .fetch_all(db)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> ServerKnobs {
        ServerKnobs {
            pool_mode: "session".into(),
            default_pool_size: 10,
            max_client_conn: 100,
            max_db_connections: 0,
            max_user_connections: 0,
        }
    }

    fn ovr(db: &str, mode: Option<&str>, max: Option<i32>) -> DbOverride {
        DbOverride {
            db_name: db.into(),
            pool_mode: mode.map(String::from),
            max_connections: max,
        }
    }

    #[test]
    fn renders_server_knobs_headerless() {
        let out = render_knobs(&server(), &[]);
        // A second [pgbouncer] header resets unmentioned keys to defaults
        // (verified on 1.24.1: kills console auth) — the fragment must
        // continue the enclosing section, never re-open it.
        assert!(!out.contains("[pgbouncer]"));
        assert!(out.contains("pool_mode = session\n"));
        assert!(out.contains("default_pool_size = 10\n"));
        assert!(out.contains("max_client_conn = 100\n"));
        assert!(out.contains("max_db_connections = 0\n"));
        assert!(out.contains("max_user_connections = 0\n"));
        // no overrides → no [users] section at all
        assert!(!out.contains("[users]"));
    }

    #[test]
    fn renders_overrides_sorted_and_only_when_set() {
        let out = render_knobs(
            &server(),
            &[
                ovr("zeta", None, Some(5)),
                ovr("alpha", Some("transaction"), None),
                ovr("noop", None, None), // nothing set → no line
            ],
        );
        assert!(out.contains("[users]\n"));
        assert!(out.contains("alpha = pool_mode=transaction\n"));
        assert!(out.contains("zeta = max_user_connections=5\n"));
        assert!(!out.contains("noop"));
        let alpha = out.find("alpha").unwrap();
        let zeta = out.find("zeta").unwrap();
        assert!(alpha < zeta, "overrides must be sorted by db name");
    }

    #[test]
    fn combined_override_renders_both_options() {
        let out = render_knobs(&server(), &[ovr("app", Some("transaction"), Some(7))]);
        assert!(out.contains("app = pool_mode=transaction max_user_connections=7\n"));
    }

    #[test]
    fn deterministic_regardless_of_input_order() {
        let a = render_knobs(&server(), &[ovr("a", None, Some(1)), ovr("b", None, Some(2))]);
        let b = render_knobs(&server(), &[ovr("b", None, Some(2)), ovr("a", None, Some(1))]);
        assert_eq!(a, b);
    }

    #[test]
    fn fails_closed_on_smuggled_names_and_modes() {
        let out = render_knobs(
            &server(),
            &[
                ovr("evil name", None, Some(1)),
                ovr("evil=x", None, Some(1)),
                ovr("[databases]", None, Some(1)),
                ovr("okay", Some("statement"), Some(3)), // bad mode dropped, limit kept
            ],
        );
        assert!(!out.contains("evil"));
        assert!(!out.contains("[databases]"));
        assert!(out.contains("okay = max_user_connections=3\n"));
        assert!(!out.contains("statement"));
    }

    #[test]
    fn unknown_server_mode_falls_back_to_session() {
        let mut s = server();
        s.pool_mode = "statement".into();
        let out = render_knobs(&s, &[]);
        assert!(out.contains("pool_mode = session\n"));
    }

    #[test]
    fn checksum_roundtrip_and_tamper_detection() {
        let out = render_knobs(&server(), &[ovr("app", None, Some(5))]);
        let claimed = claimed_checksum(&out).expect("header present");
        assert_eq!(claimed, body_checksum(&out), "fresh render must verify");

        let tampered = out.replace("max_user_connections=5", "max_user_connections=500");
        assert_ne!(claimed_checksum(&tampered).unwrap(), body_checksum(&tampered));
    }
}
