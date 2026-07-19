//! The edge plumbing (CRYPTARCH-11): PgBouncer console client, the
//! auth_query shim, config writers, and the idempotent server-init routine.
//!
//! Division of labour with the DBA: Cryptarch's panel role is deliberately
//! not superuser, so the one-time superuser bootstrap (below) is pasted by a
//! human; init detects a missing bootstrap and shows exactly that SQL rather
//! than failing cryptically. Everything else — the auth role, the shim
//! function, config rendering, RELOAD — Cryptarch does itself, idempotently.

use anyhow::{bail, Context};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use crate::crypto::Crypto;
use crate::names;

/// The SQL a superuser must run once per managed server before init can
/// complete. Rendered in the UI when init detects it's missing, with the
/// panel role taken from the live connection (current_user), never guessed.
/// Requires PostgreSQL 16+ (role-grant option syntax used elsewhere in init).
pub fn bootstrap_sql(panel_role: &str) -> String {
    let quoted = format!("\"{}\"", panel_role.replace('"', "\"\""));
    format!(
        "-- Cryptarch server bootstrap: run ONCE as a superuser on the managed server.\n\
         -- (The panel role itself is intentionally not superuser. PostgreSQL 16+.)\n\
         GRANT SELECT ON pg_shadow TO {quoted};\n\
         CREATE SCHEMA IF NOT EXISTS cryptarch AUTHORIZATION {quoted};"
    )
}

/// Auth role name — one per managed server, created and owned by the panel.
pub const AUTH_ROLE: &str = "cryptarch_auth";

/// The auth_query line the bouncer ini must carry (with auth_user = cryptarch_auth,
/// auth_dbname = postgres so the shim is installed exactly once).
pub const AUTH_QUERY: &str = "SELECT usename, passwd FROM cryptarch.get_auth($1)";

/// Outcome of one init step, for the UI report.
pub struct StepResult {
    pub step: String,
    pub outcome: Result<String, String>,
}

fn ok(step: &str, msg: impl Into<String>) -> StepResult {
    StepResult { step: step.into(), outcome: Ok(msg.into()) }
}
fn fail(step: &str, msg: impl Into<String>) -> StepResult {
    StepResult { step: step.into(), outcome: Err(msg.into()) }
}

pub struct InitOutcome {
    pub steps: Vec<StepResult>,
    /// 'ready' | 'needs_bootstrap' | 'failed'
    pub status: &'static str,
    /// Set when the auth role password was (re)generated and the conf dir is
    /// NOT writable — the operator must place it in userlist.txt by hand.
    pub manual_userlist_line: Option<String>,
    /// The actual panel role (current_user on the admin DSN) — used to render
    /// bootstrap SQL with the right name instead of a guessed one.
    pub panel_role: Option<String>,
}

/// Idempotent server-init. Safe to re-run; every run re-asserts the shim,
/// the auth role, and (when reachable) the edge config baseline.
pub async fn run_init(
    db: &sqlx::PgPool,
    crypto: &Crypto,
    server_id: Uuid,
) -> anyhow::Result<InitOutcome> {
    let row: (Vec<u8>, Option<String>, Vec<u8>, String) = sqlx::query_as(
        "SELECT admin_dsn_enc, bouncer_conf_dir, bouncer_admin_dsn_enc, name \
         FROM managed_servers WHERE id = $1",
    )
    .bind(server_id)
    .fetch_optional(db)
    .await?
    .context("no such server")?;
    let (admin_dsn_enc, conf_dir, bouncer_dsn_enc, server_name) = row;

    let admin_dsn = crypto.open(&admin_dsn_enc).context("decrypting admin DSN")?;
    let mut steps = Vec::new();

    let pool = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&admin_dsn)
        .await
    {
        Ok(p) => {
            steps.push(ok("Admin connection", "connected"));
            p
        }
        Err(e) => {
            steps.push(fail("Admin connection", e.to_string()));
            return finish(db, server_id, steps, "failed", None, None).await;
        }
    };
    let panel_role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|_| "cryptarch_admin".into());

    // 1. Bootstrap present? (pg_shadow readable + cryptarch schema usable)
    let shadow_ok = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pg_shadow WHERE usename = current_user")
        .fetch_one(&pool)
        .await
        .is_ok();
    let schema_ok = sqlx::query_scalar::<_, bool>(
        "SELECT has_schema_privilege(current_user, 'cryptarch', 'CREATE')",
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(false);
    if !shadow_ok || !schema_ok {
        steps.push(fail(
            "Superuser bootstrap",
            format!(
                "missing (pg_shadow readable: {shadow_ok}, cryptarch schema: {schema_ok}) — \
                 run the bootstrap SQL shown below as a superuser, then re-run init"
            ),
        ));
        return finish(db, server_id, steps, "needs_bootstrap", None, Some(panel_role)).await;
    }
    steps.push(ok("Superuser bootstrap", "pg_shadow readable, cryptarch schema present"));

    // 2. Auth role. Re-runs REUSE the stored password (re-asserted with
    // ALTER, which is idempotent) — rotating on every init would invalidate
    // a remote bouncer's userlist copy and make "shown once" a lie. A fresh
    // password is generated only when none is stored or it won't decrypt.
    // Ordering: store the encrypted copy BEFORE touching PG, so a crash
    // between the two heals on re-run instead of stranding a secret.
    let (auth_pw_enc_existing,): (Vec<u8>,) =
        sqlx::query_as("SELECT auth_pw_enc FROM managed_servers WHERE id = $1")
            .bind(server_id)
            .fetch_one(db)
            .await?;
    let (auth_pw, reused) = match crypto.open(&auth_pw_enc_existing) {
        Ok(pw) if !pw.is_empty() => (pw, true),
        _ => (names::generate_password(), false),
    };
    if !reused {
        let enc = crypto.seal(&auth_pw)?;
        sqlx::query("UPDATE managed_servers SET auth_pw_enc = $2 WHERE id = $1")
            .bind(server_id)
            .bind(&enc)
            .execute(db)
            .await?;
    }
    // Plaintext never travels in DDL — the managed server's statement logs
    // would otherwise capture it. Send the SCRAM verifier instead.
    let verifier = postgres_protocol::password::scram_sha_256(auth_pw.as_bytes());
    let role_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(AUTH_ROLE)
            .fetch_one(&pool)
            .await?;
    let role_res = if role_exists {
        sqlx::query(&format!("ALTER ROLE {AUTH_ROLE} LOGIN PASSWORD '{verifier}'"))
            .execute(&pool)
            .await
    } else {
        sqlx::query(&format!("CREATE ROLE {AUTH_ROLE} LOGIN PASSWORD '{verifier}'"))
            .execute(&pool)
            .await
    };
    match role_res {
        Ok(_) => steps.push(ok(
            "Auth role",
            match (role_exists, reused) {
                (false, _) => "created",
                (true, true) => "re-asserted (stored password reused)",
                (true, false) => "password set (no stored copy was usable)",
            },
        )),
        Err(e) => {
            steps.push(fail("Auth role", e.to_string()));
            return finish(db, server_id, steps, "failed", None, Some(panel_role)).await;
        }
    }
    // PG16: creating a role grants the creator ADMIN OPTION but not SET —
    // the verification step below needs SET ROLE, so self-grant it (allowed
    // via ADMIN OPTION). INHERIT FALSE: no passive privilege accumulation.
    if let Err(e) = sqlx::query(&format!(
        "GRANT {AUTH_ROLE} TO CURRENT_USER WITH INHERIT FALSE, SET TRUE"
    ))
    .execute(&pool)
    .await
    {
        steps.push(fail("Auth role membership", e.to_string()));
        return finish(db, server_id, steps, "failed", None, Some(panel_role)).await;
    }

    // 3. The shim. SECURITY DEFINER owned by the panel role (which has the
    // bootstrap's pg_shadow grant). Fixed search_path; EXECUTE only for the
    // auth role.
    // NOT usesuper: the bouncer only ever needs consumer credentials — a
    // compromised auth role must not be able to harvest superuser verifiers.
    let shim = "CREATE OR REPLACE FUNCTION cryptarch.get_auth(uname TEXT) \
         RETURNS TABLE(usename TEXT, passwd TEXT) \
         LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS \
         'SELECT usename::text, passwd::text FROM pg_shadow \
          WHERE usename = uname AND NOT usesuper'"
        .to_string();
    let grants = [
        "REVOKE ALL ON FUNCTION cryptarch.get_auth(TEXT) FROM PUBLIC".to_string(),
        format!("GRANT EXECUTE ON FUNCTION cryptarch.get_auth(TEXT) TO {AUTH_ROLE}"),
        format!("GRANT USAGE ON SCHEMA cryptarch TO {AUTH_ROLE}"),
    ];
    if let Err(e) = sqlx::query(&shim).execute(&pool).await {
        steps.push(fail("auth_query shim", e.to_string()));
        return finish(db, server_id, steps, "failed", None, Some(panel_role)).await;
    }
    for g in &grants {
        if let Err(e) = sqlx::query(g).execute(&pool).await {
            steps.push(fail("auth_query shim grants", e.to_string()));
            return finish(db, server_id, steps, "failed", None, Some(panel_role)).await;
        }
    }
    steps.push(ok("auth_query shim", "cryptarch.get_auth installed, EXECUTE granted to auth role"));

    // 4. Verify the shim end-to-end as the auth role (SET ROLE — we hold
    // ADMIN on it as creator). The auth role's own row is the probe: it
    // exists and we just set its SCRAM verifier.
    let verify = async {
        let mut conn = pool.acquire().await?;
        sqlx::query(&format!("SET ROLE {AUTH_ROLE}")).execute(&mut *conn).await?;
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM cryptarch.get_auth($1)")
            .bind(AUTH_ROLE)
            .fetch_one(&mut *conn)
            .await?;
        sqlx::query("RESET ROLE").execute(&mut *conn).await?;
        anyhow::Ok(n)
    };
    match verify.await {
        Ok(n) if n > 0 => steps.push(ok("Shim verification", "auth role can resolve credentials")),
        Ok(_) => steps.push(fail("Shim verification", "shim returned no rows for a known role")),
        Err(e) => {
            steps.push(fail("Shim verification", e.to_string()));
            return finish(db, server_id, steps, "failed", None, Some(panel_role)).await;
        }
    }

    // 5. Edge config: write userlist line + deny-all hba baseline when the
    // conf dir is reachable; otherwise hand the operator the line to place.
    let userlist_line = format!("\"{AUTH_ROLE}\" \"{auth_pw}\"");
    let mut manual_line = None;
    match conf_dir.as_deref().filter(|d| !d.is_empty()) {
        Some(dir) => {
            match write_edge_baseline(dir, &userlist_line) {
                Ok(report) => steps.push(ok("Edge config", report)),
                Err(e) => {
                    steps.push(fail("Edge config", e.to_string()));
                    return finish(db, server_id, steps, "failed", None, Some(panel_role)).await;
                }
            }
            match write_knobs_baseline(db, server_id, dir).await {
                Ok(report) => steps.push(ok("Pool settings", report)),
                Err(e) => {
                    steps.push(fail("Pool settings", e.to_string()));
                    return finish(db, server_id, steps, "failed", None, Some(panel_role)).await;
                }
            }
        }
        None => {
            steps.push(ok(
                "Edge config",
                "no conf dir configured — place the userlist line manually (shown below)",
            ));
            manual_line = Some(userlist_line.clone());
        }
    }

    // 6. RELOAD via console, if we have a console DSN.
    if !bouncer_dsn_enc.is_empty() {
        let bdsn = crypto.open(&bouncer_dsn_enc).context("decrypting bouncer DSN")?;
        match console_command(&bdsn, "RELOAD").await {
            Ok(_) => steps.push(ok("Bouncer RELOAD", "console acknowledged")),
            Err(e) => {
                steps.push(fail("Bouncer RELOAD", e.to_string()));
                return finish(db, server_id, steps, "failed", manual_line, Some(panel_role)).await;
            }
        }
    } else {
        steps.push(ok("Bouncer RELOAD", "skipped — no console DSN configured"));
    }

    tracing::info!("server-init completed for '{server_name}'");
    finish(db, server_id, steps, "ready", manual_line, Some(panel_role)).await
}

async fn finish(
    db: &sqlx::PgPool,
    server_id: Uuid,
    steps: Vec<StepResult>,
    status: &'static str,
    manual_userlist_line: Option<String>,
    panel_role: Option<String>,
) -> anyhow::Result<InitOutcome> {
    sqlx::query("UPDATE managed_servers SET init_status = $2 WHERE id = $1")
        .bind(server_id)
        .bind(status)
        .execute(db)
        .await?;
    Ok(InitOutcome { steps, status, manual_userlist_line, panel_role })
}

/// Write the auth-role userlist line (preserving other entries, e.g. the
/// console admin) and — only when no hba exists at all — a console-only
/// baseline. Never clobbers an existing hba: the acl renderer (CRYPTARCH-12)
/// owns replacement, operators own their hand-written files. Returns a
/// human-readable report of what was done.
fn write_edge_baseline(dir: &str, userlist_line: &str) -> anyhow::Result<String> {
    let dir = std::path::Path::new(dir);
    if !dir.is_dir() {
        bail!("{} is not a directory (from Cryptarch's vantage point)", dir.display());
    }
    // Guard against a mistyped path quietly collecting files: the dir must
    // already look like a bouncer config dir.
    if !dir.join("pgbouncer.ini").is_file() {
        bail!(
            "{} has no pgbouncer.ini — refusing to write edge config into a \
             directory that isn't a bouncer config dir",
            dir.display()
        );
    }

    // userlist.txt: replace our auth-role line, keep everything else.
    let userlist = dir.join("userlist.txt");
    let existing = std::fs::read_to_string(&userlist).unwrap_or_default();
    let mut lines: Vec<String> = existing
        .lines()
        .filter(|l| !l.trim_start().starts_with(&format!("\"{AUTH_ROLE}\"")))
        .map(String::from)
        .collect();
    lines.push(userlist_line.to_string());
    let mut content = lines.join("\n");
    content.push('\n');
    // 0640 keeps the auth secret off world-readable; the bouncer may read
    // via group. Falls back to 0644 with a loud warning when the group
    // arrangement isn't possible (dev host UIDs vs container uid 70).
    let mode = write_secret(&userlist, &content).context("writing userlist.txt")?;

    // hba baseline only when nothing exists — a missing hba means the
    // bouncer would refuse everything including the console.
    let hba = dir.join("pgbouncer_hba.conf");
    let hba_report = if std::fs::metadata(&hba).map(|m| m.len() > 0).unwrap_or(false) {
        "existing hba left untouched"
    } else {
        let baseline = "# managed by cryptarch — baseline written by server-init\n\
                        # (the ACL renderer replaces this from acl_entries)\n\
                        host pgbouncer pgbadmin 0.0.0.0/0 scram-sha-256\n";
        atomic_write(&hba, baseline, 0o644).context("writing hba baseline")?;
        "hba baseline written (console-only)"
    };
    Ok(format!("userlist updated (mode {mode:o}), {hba_report}"))
}

/// Render the server's pool settings into the knobs fragment (CRYPTARCH-32)
/// and make sure the operator's pgbouncer.ini actually pulls it in. Returns
/// a human-readable report.
async fn write_knobs_baseline(
    db: &sqlx::PgPool,
    server_id: Uuid,
    dir: &str,
) -> anyhow::Result<String> {
    let knobs = crate::bouncer::load_server_knobs(db, server_id).await?;
    let overrides = crate::bouncer::load_overrides(db, server_id).await?;
    let rendered = crate::bouncer::render_knobs(&knobs, &overrides);
    let dir = std::path::Path::new(dir);
    atomic_write(&dir.join(crate::bouncer::KNOBS_FILE), &rendered, 0o644)
        .with_context(|| format!("writing {}", crate::bouncer::KNOBS_FILE))?;
    let include_report = ensure_include(dir)?;
    Ok(format!("{} rendered, {include_report}", crate::bouncer::KNOBS_FILE))
}

/// Make pgbouncer.ini `%include` the knobs fragment, appending the directive
/// when missing. Appending (rather than refusing) is the one edit we make to
/// the operator's file: it's a single idempotent line, end-of-file placement
/// is load-bearing (later values override the static baseline), and without
/// it every knob in the portal is a silent no-op.
///
/// Placement is doubly load-bearing: the fragment is HEADERLESS (see
/// `bouncer::render_knobs` — a re-opened `[pgbouncer]` section resets
/// unmentioned keys), so the include must land while the ini's `[pgbouncer]`
/// section is still open. Appending at EOF only achieves that when
/// `[pgbouncer]` is the file's last section — verified below, refused
/// loudly otherwise rather than silently injecting keys into `[databases]`.
///
/// The path in the directive must be the BOUNCER's view of the conf dir, not
/// ours (we may see a host-side mount like ./dev-bouncer). Derived from the
/// ini's own auth_hba_file line; /etc/pgbouncer when absent.
fn ensure_include(dir: &std::path::Path) -> anyhow::Result<&'static str> {
    let ini_path = dir.join("pgbouncer.ini");
    let ini = std::fs::read_to_string(&ini_path)
        .with_context(|| format!("reading {}", ini_path.display()))?;
    let already = ini.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with("%include") && l.contains(crate::bouncer::KNOBS_FILE)
    });
    if already {
        return Ok("%include already present");
    }
    let last_section = ini
        .lines()
        .map(str::trim)
        .rfind(|l| l.starts_with('['));
    if last_section != Some("[pgbouncer]") {
        bail!(
            "pgbouncer.ini's last section is {} — the knobs %include must sit at the end \
             of the [pgbouncer] section. Move that section last (or add the %include \
             there yourself) and re-run init.",
            last_section.unwrap_or("missing")
        );
    }
    let container_dir = ini
        .lines()
        .find_map(|l| {
            let l = l.trim_start();
            l.strip_prefix("auth_hba_file")
                .and_then(|rest| rest.trim_start().strip_prefix('='))
                .map(str::trim)
                .and_then(|p| std::path::Path::new(p).parent())
                .and_then(|d| d.to_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "/etc/pgbouncer".into());
    let mut updated = ini;
    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&format!(
        "\n; added by cryptarch server-init — pool settings rendered by the portal\n\
         %include {container_dir}/{}\n",
        crate::bouncer::KNOBS_FILE
    ));
    atomic_write(&ini_path, &updated, 0o644).context("appending %include to pgbouncer.ini")?;
    Ok("%include appended to pgbouncer.ini")
}

/// Atomic write: temp file in the same dir, set mode, rename over. A crash
/// mid-write must never truncate the live file (a half-written userlist
/// would lock out the very console RELOAD needs).
pub(crate) fn atomic_write(path: &std::path::Path, content: &str, mode: u32) -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = path.parent().context("path has no parent")?;
    // Unique tmp per write: concurrent writers must not share a tmp path
    // (interleaved write + double rename = lost update or ENOENT).
    let tmp = dir.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("cryptarch"),
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::write(&tmp, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    }
    let _ = mode; // non-unix: default perms
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Write a secret-bearing file: try 0640, fall back to 0644 with a warning.
/// Returns the mode actually used.
fn write_secret(path: &std::path::Path, content: &str) -> anyhow::Result<u32> {
    atomic_write(path, content, 0o640)?;
    // If the bouncer can't read 0640 (different uid/gid arrangement), the
    // operator will see auth failures immediately; dev harness needs 0644
    // because the container reads as uid 70 with no shared group.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata(path)?.uid();
        // Heuristic: when we're not root (dev on host), uid-70 bouncer can't
        // group-read our 0640 file — relax to 0644 and say so.
        if uid != 0 {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
            tracing::warn!(
                "{} written 0644 (world-readable): running unprivileged, container \
                 bouncer reads as uid 70. In production run the app as root in its \
                 container or arrange a shared group for 0640.",
                path.display()
            );
            return Ok(0o644);
        }
    }
    Ok(0o640)
}

/// Run one command on the PgBouncer admin console (simple query protocol),
/// returning column names and rows — SHOW POOLS/STATS render as real tables.
pub async fn console_table(
    console_dsn: &str,
    cmd: &str,
) -> anyhow::Result<(Vec<String>, Vec<Vec<String>>)> {
    let (client, connection) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio_postgres::connect(console_dsn, tokio_postgres::NoTls),
    )
    .await
    .context("console connect timed out")?
    .context("connecting to bouncer console")?;
    let handle = tokio::spawn(async move {
        // Connection task ends when the client drops; errors here are
        // expected on close for the console.
        let _ = connection.await;
    });
    let msgs = tokio::time::timeout(std::time::Duration::from_secs(5), client.simple_query(cmd))
        .await
        .with_context(|| format!("console command {cmd} timed out"))?
        .with_context(|| format!("console command {cmd}"))?;
    drop(client);
    let _ = handle.await;
    let mut headers = Vec::new();
    let mut rows = Vec::new();
    for msg in msgs {
        if let tokio_postgres::SimpleQueryMessage::Row(r) = msg {
            if headers.is_empty() {
                headers = r.columns().iter().map(|c| c.name().to_string()).collect();
            }
            let mut cells = Vec::new();
            for i in 0..r.len() {
                cells.push(r.get(i).unwrap_or("").to_string());
            }
            rows.push(cells);
        }
    }
    Ok((headers, rows))
}

/// Flattened variant for callers that only need lines (RELOAD, KILL, logs).
pub async fn console_command(console_dsn: &str, cmd: &str) -> anyhow::Result<Vec<String>> {
    let (_, rows) = console_table(console_dsn, cmd).await?;
    Ok(rows.into_iter().map(|cells| cells.join(" | ")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cryptarch_edge_{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ensure_include_appends_with_container_path_and_is_idempotent() {
        let dir = temp_dir();
        std::fs::write(
            dir.join("pgbouncer.ini"),
            "[pgbouncer]\nauth_hba_file = /opt/bouncer/pgbouncer_hba.conf\n",
        )
        .unwrap();

        assert_eq!(ensure_include(&dir).unwrap(), "%include appended to pgbouncer.ini");
        let ini = std::fs::read_to_string(dir.join("pgbouncer.ini")).unwrap();
        // The directive must carry the BOUNCER's view of the conf dir,
        // derived from auth_hba_file — not our host-side path.
        assert!(ini.contains("%include /opt/bouncer/cryptarch_bouncer.ini"), "{ini}");

        assert_eq!(ensure_include(&dir).unwrap(), "%include already present");
        let again = std::fs::read_to_string(dir.join("pgbouncer.ini")).unwrap();
        assert_eq!(ini, again, "second run must not append twice");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ensure_include_refuses_when_pgbouncer_section_not_last() {
        let dir = temp_dir();
        // [databases] last: appending would inject bare keys into it.
        std::fs::write(
            dir.join("pgbouncer.ini"),
            "[pgbouncer]\npool_mode = session\n\n[databases]\n* = host=db\n",
        )
        .unwrap();
        let err = ensure_include(&dir).unwrap_err().to_string();
        assert!(err.contains("[databases]"), "{err}");
        let ini = std::fs::read_to_string(dir.join("pgbouncer.ini")).unwrap();
        assert!(!ini.contains("%include"), "refusal must not modify the file");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ensure_include_falls_back_to_etc_pgbouncer() {
        let dir = temp_dir();
        std::fs::write(dir.join("pgbouncer.ini"), "[pgbouncer]\npool_mode = session\n").unwrap();
        ensure_include(&dir).unwrap();
        let ini = std::fs::read_to_string(dir.join("pgbouncer.ini")).unwrap();
        assert!(ini.contains("%include /etc/pgbouncer/cryptarch_bouncer.ini"), "{ini}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
