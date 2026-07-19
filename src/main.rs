//! Cryptarch — self-service, multi-engine, multi-server database provisioning.
//!
//! Boot sequence: read config, connect to the metadata database, run migrations,
//! then serve. All real logic lives in the library (`lib.rs`) so the
//! integration tests exercise the same code paths.

use anyhow::Context;
use cryptarch::{auth, config, crypto, servers, web, MIGRATOR};
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = config::Config::from_env().context("loading config")?;

    let db = PgPoolOptions::new()
        .max_connections(8)
        // Fail requests in seconds when the metadata db is saturated or
        // gone — the 30s sqlx default reads as a hung app.
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&cfg.metadata_dsn)
        .await
        .context("connecting to metadata database")?;

    MIGRATOR
        .run(&db)
        .await
        .context("running metadata migrations")?;

    auth::bootstrap_admin(
        &db,
        &cfg.bootstrap_admin,
        &cfg.bootstrap_admin_password,
        cfg.default_quota,
    )
    .await
    .context("bootstrapping admin user")?;

    let crypto = crypto::Crypto::from_key_file(&cfg.key_file)
        .context("loading at-rest encryption key")?;

    if cfg.allow_superuser_admin {
        tracing::warn!("CRYPTARCH_ALLOW_SUPERUSER_ADMIN is set — dev mode only, never production");
    }
    let servers = servers::ServerRegistry::build(
        &db,
        &crypto,
        cfg.seed_server.as_ref(),
        cfg.allow_superuser_admin,
    )
    .await
    .context("building server registry")?;

    tracing::info!("cryptarch metadata ready (default quota {})", cfg.default_quota);

    let state = web::AppState {
        sessions: auth::SessionStore::new(db.clone()),
        db,
        servers,
        crypto,
        secure_cookies: cfg.secure_cookies,
        login_throttle: web::LoginThrottle::default(),
        allow_superuser: cfg.allow_superuser_admin,
        health: cryptarch::health::HealthRegistry::default(),
    };
    // Background health loop (CRYPTARCH-43). 0 = disabled; transitions audit
    // as `system` and go out via the configured notifier.
    if cfg.health_interval_secs > 0 {
        let notifier = cryptarch::health::Notifier::from_config(
            cfg.notify_url.as_deref(),
            &cfg.notify_format,
        );
        tracing::info!(
            "health loop every {}s, notifications {}",
            cfg.health_interval_secs,
            if cfg.notify_url.is_some() { "on" } else { "off (audit only)" }
        );
        tokio::spawn(cryptarch::health::run_loop(
            state.clone(),
            cfg.health_interval_secs,
            notifier,
        ));
    }
    let app = web::router(state);

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr)
        .await
        .with_context(|| format!("binding {}", cfg.bind_addr))?;
    tracing::info!("cryptarch listening on {}", cfg.bind_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving HTTP")?;
    tracing::info!("drained — bye");
    Ok(())
}

/// Resolve on SIGINT or SIGTERM so in-flight requests (provisioning DDL,
/// edge syncs) drain instead of dying mid-transaction on redeploys.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!("installing SIGTERM handler: {e}");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => tracing::info!("SIGINT — graceful shutdown"),
        _ = terminate => tracing::info!("SIGTERM — graceful shutdown"),
    }
}
