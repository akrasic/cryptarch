//! Runtime configuration, read from the environment at startup.

use anyhow::Context;

#[derive(Debug, Clone)]
pub struct Config {
    /// DSN for Cryptarch's own metadata database (the `cryptarch` DB).
    pub metadata_dsn: String,
    /// Address the HTTP server binds to (e.g. `0.0.0.0:8080`).
    pub bind_addr: String,
    /// Bootstrap admin username, created on first run if no users exist.
    pub bootstrap_admin: String,
    /// Bootstrap admin password (first run only).
    pub bootstrap_admin_password: String,
    /// Default per-user database quota for newly created users.
    pub default_quota: i32,
    /// Path to the at-rest encryption key file (64 hex chars = 32 bytes).
    /// Encrypts stored admin DSNs; kept on disk, never in the metadata DB.
    pub key_file: String,
    /// Mark session cookies Secure (HTTPS-only). On by default; the dev
    /// harness disables it because dev runs over plain HTTP on the LAN.
    pub secure_cookies: bool,
    /// Dev-only escape hatch: allow a SUPERUSER admin role to pass the role
    /// gate when engines connect. The dev harness sets this because its seed
    /// uses the container's postgres superuser. NEVER set in production —
    /// the whole spine assumes the panel role can't read tenant data.
    pub allow_superuser_admin: bool,
    /// Seed managed server — a dev/bootstrap convenience. When set, its row is
    /// upserted (DSN encrypted at rest) before the DB-backed registry loads;
    /// the database is authoritative for all other servers (CRYPTARCH-10 adds
    /// CRUD). `None` skips seeding; provisioning is enabled by whatever active
    /// servers the registry loads.
    pub seed_server: Option<SeedServer>,
    /// Who may reach the bouncer's admin console, as a CIDR (CRYPTARCH-104).
    /// Rendered into the hba file. Defaults to loopback only; the compose
    /// stack sets its pinned `backend` subnet, which tenants are not on.
    pub console_cidr: Option<String>,
    /// Seconds between background health sweeps (CRYPTARCH-43). 0 disables
    /// the loop entirely.
    pub health_interval_secs: u64,
    /// Where health transitions are delivered (ntfy topic URL or a webhook).
    /// None = no notifications; transitions still hit the audit log.
    pub notify_url: Option<String>,
    /// "ntfy" (default) or "json".
    pub notify_format: String,
    /// Root directory for backup blobs (CRYPTARCH-55). Meant to be a host bind
    /// mount, not a docker volume: an operator has to be able to rsync these
    /// off the box with ordinary tools for them to count as safety. None
    /// disables backups entirely.
    pub backup_dir: Option<String>,
    /// Bearer token a Prometheus scrape must present (CRYPTARCH-98). Unset
    /// leaves /metrics returning 404 — the endpoint carries tenant database
    /// names, and the app port is published on every interface.
    pub metrics_token: Option<String>,
    /// Seconds between scheduled backup sweeps (CRYPTARCH-61). 0 disables the
    /// loop; manual "Back up now" still works.
    pub backup_interval_secs: u64,
    /// Successful backups kept per database. 0 keeps everything forever.
    pub backup_keep: i64,
    /// Alert when a database's newest good backup is older than this. 0
    /// disables the staleness check.
    pub backup_stale_after_secs: u64,
}

/// Connection details for the v0.1 in-memory managed server.
#[derive(Debug, Clone)]
pub struct SeedServer {
    pub name: String,
    pub host: String,
    pub port: u16,
    /// Admin DSN — must be a role with CREATEDB CREATEROLE (not superuser in
    /// production). Stored in the metadata DB encrypted at rest (AES-256-GCM,
    /// key from CRYPTARCH_KEY_FILE); the plaintext lives only in process env
    /// and memory.
    pub admin_dsn: String,
    /// Default "Allowed from" for databases provisioned onto this server —
    /// the compose stack sets its db-network subnet here so the provision
    /// form comes prefilled and nobody has to know a CIDR. Optional; when
    /// absent the stored value (admin-editable) is left untouched.
    pub default_consumer_cidr: Option<String>,
    /// The in-stack dial address ("host:port", e.g. "bouncer:6432") — what a
    /// container ON the db network dials, as opposed to the advertised
    /// (outside) address. Seeded as a listener labeled "db network" so every
    /// database page offers the in-stack connection string (CRYPTARCH-40).
    pub stack_listener: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let cfg = Self::read()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reject a configuration that would boot into a state nobody wants
    /// (CRYPTARCH-105).
    ///
    /// Separate from reading so the checks are one readable list rather than
    /// scattered through field initialisers, and so a test can build a Config
    /// and validate it without touching process env.
    fn validate(&self) -> anyhow::Result<()> {
        check_bootstrap_password(&self.bootstrap_admin_password)
    }
}

/// The bootstrap password rules, split out so they can be tested without
/// building a whole `Config` or touching process environment.
fn check_bootstrap_password(password: &str) -> anyhow::Result<()> {
        // `env()` only fails on a MISSING variable — `Ok("")` sails through it.
        // docker compose turns an absent `.env` line into exactly that: the
        // variable is set, to nothing. `CRYPTARCH_ADMIN_PASSWORD:
        // ${CRYPTARCH_ADMIN_PASSWORD}` with no value therefore bootstrapped an
        // admin whose password was the empty string, on a stack that otherwise
        // came up clean and green.
        //
        // Note the asymmetry this closes: every human-chosen password in the
        // product is held to `MIN_PASSWORD_LEN` (profile.rs, admin.rs). The one
        // that creates the first superuser was held to nothing.
        anyhow::ensure!(
            !password.is_empty(),
            "CRYPTARCH_ADMIN_PASSWORD is set but empty — refusing to bootstrap an admin \
             with no password. (docker compose sets a variable to the empty string when \
             its .env line is missing; use ${{CRYPTARCH_ADMIN_PASSWORD:?set it}} to catch \
             that in compose too.)"
        );
        anyhow::ensure!(
            password.chars().count() >= crate::profile::MIN_PASSWORD_LEN,
            "CRYPTARCH_ADMIN_PASSWORD must be at least {} characters — the bootstrap admin \
             is the account that can reach every other one",
            crate::profile::MIN_PASSWORD_LEN,
        );
        // And the ceiling every login is held to (CRYPTARCH-128) — above it the
        // login path refuses before verifying, so a longer bootstrap password
        // would create an admin that can never sign in.
        anyhow::ensure!(
            password.len() <= crate::auth::MAX_PASSWORD_LEN,
            "CRYPTARCH_ADMIN_PASSWORD must be at most {} bytes",
            crate::auth::MAX_PASSWORD_LEN,
        );
    Ok(())
}

impl Config {
    fn read() -> anyhow::Result<Self> {
        Ok(Self {
            metadata_dsn: env("CRYPTARCH_METADATA_DSN")?,
            bind_addr: std::env::var("CRYPTARCH_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            bootstrap_admin: std::env::var("CRYPTARCH_ADMIN").unwrap_or_else(|_| "admin".into()),
            bootstrap_admin_password: env("CRYPTARCH_ADMIN_PASSWORD")?,
            default_quota: std::env::var("CRYPTARCH_DEFAULT_QUOTA")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
            key_file: env("CRYPTARCH_KEY_FILE")?,
            secure_cookies: !std::env::var("CRYPTARCH_INSECURE_COOKIES")
                .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
            allow_superuser_admin: std::env::var("CRYPTARCH_ALLOW_SUPERUSER_ADMIN")
                .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
            seed_server: SeedServer::from_env(),
            console_cidr: std::env::var("CRYPTARCH_CONSOLE_CIDR")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            health_interval_secs: std::env::var("CRYPTARCH_HEALTH_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            notify_url: std::env::var("CRYPTARCH_NOTIFY_URL")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            notify_format: std::env::var("CRYPTARCH_NOTIFY_FORMAT")
                .unwrap_or_else(|_| "ntfy".into()),
            metrics_token: std::env::var("CRYPTARCH_METRICS_TOKEN")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            backup_dir: std::env::var("CRYPTARCH_BACKUP_DIR")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            backup_interval_secs: std::env::var("CRYPTARCH_BACKUP_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(86_400),
            backup_keep: std::env::var("CRYPTARCH_BACKUP_KEEP")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(7),
            backup_stale_after_secs: std::env::var("CRYPTARCH_BACKUP_STALE_AFTER_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(172_800),
        })
    }
}

impl SeedServer {
    /// Build from env if `CRYPTARCH_SEED_SERVER_DSN` is set; otherwise `None`.
    fn from_env() -> Option<Self> {
        let admin_dsn = std::env::var("CRYPTARCH_SEED_SERVER_DSN").ok()?;
        Some(Self {
            name: std::env::var("CRYPTARCH_SEED_SERVER_NAME").unwrap_or_else(|_| "default".into()),
            host: std::env::var("CRYPTARCH_SEED_SERVER_HOST").unwrap_or_else(|_| "localhost".into()),
            port: std::env::var("CRYPTARCH_SEED_SERVER_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5432),
            admin_dsn,
            default_consumer_cidr: std::env::var("CRYPTARCH_SEED_SERVER_DEFAULT_CIDR")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
            stack_listener: std::env::var("CRYPTARCH_SEED_SERVER_STACK_LISTENER")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty()),
        })
    }
}

fn env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).with_context(|| format!("missing required env var {key}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRYPTARCH-105. The empty case is the one that actually happened:
    /// `env()` fails only on a MISSING variable, and docker compose turns a
    /// missing `.env` line into a variable set to "". So the check that
    /// mattered was never "is it absent" but "is it blank".
    #[test]
    fn an_empty_bootstrap_password_is_refused() {
        let err = check_bootstrap_password("").expect_err("empty must not bootstrap an admin");
        assert!(
            err.to_string().contains("empty"),
            "the message must name the cause an operator can act on, got: {err}"
        );
    }

    #[test]
    fn a_short_bootstrap_password_is_refused() {
        // One under the limit, so this pins the boundary rather than just
        // "short strings are rejected".
        let short: String = "a".repeat(crate::profile::MIN_PASSWORD_LEN - 1);
        assert!(check_bootstrap_password(&short).is_err(), "{short:?} must be refused");
    }

    /// The positive case, without which both assertions above are satisfied by
    /// a function that rejects everything — including every real deployment.
    #[test]
    fn an_adequate_bootstrap_password_is_accepted() {
        let ok: String = "a".repeat(crate::profile::MIN_PASSWORD_LEN);
        assert!(check_bootstrap_password(&ok).is_ok(), "exactly at the limit must pass");
        assert!(check_bootstrap_password("a-perfectly-ordinary-passphrase").is_ok());
    }

    #[test]
    fn a_bootstrap_password_nobody_could_log_in_with_is_refused() {
        let too_long = "x".repeat(crate::auth::MAX_PASSWORD_LEN + 1);
        assert!(check_bootstrap_password(&too_long).is_err());
        assert!(check_bootstrap_password(&"x".repeat(crate::auth::MAX_PASSWORD_LEN)).is_ok());
    }

    /// The bootstrap admin is held to the same bar as every human-chosen
    /// password. It used to be held to none, which is how an empty one got in.
    #[test]
    fn the_bootstrap_bar_is_the_same_constant_users_are_held_to() {
        let one_short: String = "x".repeat(crate::profile::MIN_PASSWORD_LEN - 1);
        let exactly: String = "x".repeat(crate::profile::MIN_PASSWORD_LEN);
        assert!(check_bootstrap_password(&one_short).is_err());
        assert!(check_bootstrap_password(&exactly).is_ok());
    }
}
