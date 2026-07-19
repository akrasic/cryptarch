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
    /// Seconds between background health sweeps (CRYPTARCH-43). 0 disables
    /// the loop entirely.
    pub health_interval_secs: u64,
    /// Where health transitions are delivered (ntfy topic URL or a webhook).
    /// None = no notifications; transitions still hit the audit log.
    pub notify_url: Option<String>,
    /// "ntfy" (default) or "json".
    pub notify_format: String,
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
