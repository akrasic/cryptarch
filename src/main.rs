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

    // Observed either side of the migration step, and nowhere else. This pair
    // IS claim C3: the CRYPTARCH-78 repair runs only on the boot that applies
    // migration 0016, so it cannot be reached from an ordinary startup.
    //
    // Do not replace this with "call the repair after migrating and let the
    // marker stop it" — see `repair::run_upgrade_repair`. That version is
    // unbounded for a server that was never reached, because such a server has
    // no marker to stop it and would be retried on every boot forever against
    // an increasingly stale freeze.
    let repair_applied_before = cryptarch::repair::repair_migration_applied(&db).await;

    MIGRATOR
        .run(&db)
        .await
        .context("running metadata migrations")?;

    let is_upgrade_boot =
        !repair_applied_before && cryptarch::repair::repair_migration_applied(&db).await;

    // Computed now, on the main task, rather than lazily inside the first
    // login handler — where its Argon2 hash would run on an async worker
    // (CRYPTARCH-128). Cheap once; the login path depends on it existing.
    std::sync::LazyLock::force(&auth::DUMMY_HASH);

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

    // Before the registry decrypts a single stored DSN, and long before the
    // backup scheduler seals anything (CRYPTARCH-107). Loading a key always
    // succeeds; this is what makes loading the WRONG one fail.
    crypto::verify_or_establish_canary(&db, &crypto).await?;

    if cfg.allow_superuser_admin {
        tracing::warn!("CRYPTARCH_ALLOW_SUPERUSER_ADMIN is set — dev mode only, never production");
    }
    // Before anything can render an hba file (CRYPTARCH-104).
    if let Some(cidr) = cfg.console_cidr.clone() {
        cryptarch::acl::set_console_cidr(cidr);
    }
    tracing::info!("bouncer console reachable from {}", cryptarch::acl::console_cidr());
    // CRYPTARCH-103. Secure cookies are the right default and stay the default,
    // but they are also a silent failure: a browser drops a Secure cookie from
    // a plain-http origin without telling anyone, so login "succeeds", writes a
    // session row, redirects — and bounces straight back to /login. It is
    // indistinguishable from a wrong password, and the README's own first-run
    // step tells the operator to open http://<host>:8080. One line at boot
    // turns that evening into ten seconds.
    // `info!`, not `warn!`. Secure cookies are the correct default, so this
    // fires on every healthy boot — and a warning present in the healthy state
    // is one operators learn to skim past, which costs the genuinely alarming
    // ones their signal.
    if cfg.secure_cookies {
        tracing::info!(
            "session cookies are marked Secure, so sign-in only works over https:// \
             (or http://localhost). If you are reaching Cryptarch by plain http on a LAN \
             address, logins will appear to fail silently — put TLS in front of it, or set \
             CRYPTARCH_INSECURE_COOKIES=1 to accept the risk on a trusted network."
        );
    }
    let servers = servers::ServerRegistry::build(
        &db,
        &crypto,
        cfg.seed_server.as_ref(),
        cfg.allow_superuser_admin,
    )
    .await
    .context("building server registry")?;

    // After the registry exists (it needs engines), and before serving — a
    // stranded database should be repaired before anyone can try to use it.
    if is_upgrade_boot {
        tracing::info!("CRYPTARCH-78: upgrade boot — running the one-time login repair");
        cryptarch::repair::run_upgrade_repair(&db, &servers).await;
    }

    tracing::info!("cryptarch metadata ready (default quota {})", cfg.default_quota);

    let state = web::AppState {
        jobs: web::JobTracker::default(),
        sessions: auth::SessionStore::new(db.clone()),
        db,
        servers,
        crypto,
        secure_cookies: cfg.secure_cookies,
        login_throttle: web::LoginThrottle::default(),
        allow_superuser: cfg.allow_superuser_admin,
        health: cryptarch::health::HealthRegistry::default(),
        backup_dir: cfg.backup_dir.as_ref().map(std::path::PathBuf::from),
        metrics_token: cfg.metrics_token.clone(),
        metadata_dsn: Some(cfg.metadata_dsn.clone()),
    };

    let schedule = cryptarch::backup::Schedule {
        interval_secs: cfg.backup_interval_secs,
        keep: cfg.backup_keep,
        stale_after_secs: cfg.backup_stale_after_secs,
        // Replaced below, once it is known whether the scheduler drives
        // backups or is running for maintenance alone.
        backups_enabled: false,
    };

    // The CLI path (`cryptarch backup ...`) runs the same job body as the
    // scheduler and then exits, so external cron can drive backups without a
    // second implementation to keep in sync.
    //
    // Resolved BEFORE the startup sweep, which is a server-only step. Running
    // it here would be actively harmful: `cryptarch backup --all` against a
    // live server would fail that server's in-flight jobs, release the
    // per-database lock they hold, and let the CLI start a second concurrent
    // pg_dump of the same database.
    if let Some(request) = cli_backup_request()? {
        return run_cli_backup(state, request).await;
    }

    let notifier =
        cryptarch::health::Notifier::from_config(cfg.notify_url.as_deref(), &cfg.notify_format);
    match cfg.backup_dir.as_deref() {
        Some(dir) => {
            tracing::info!("backups enabled, blobs under {dir}");
            // Backups interrupted by the last shutdown are still marked
            // `running`, and the per-database lock would block those databases
            // forever. Clear them before the server can accept a new one.
            if let Err(e) = cryptarch::backup::sweep_stale(&state.db).await {
                tracing::error!("stale backup sweep failed: {e:#}");
            }
            // Same treatment for restores (CRYPTARCH-69): the per-target lock
            // IS the running row, so a restart mid-restore would otherwise
            // leave that database permanently un-restorable.
            if let Err(e) = cryptarch::restore::sweep_stale(&state.db).await {
                tracing::error!("stale restore sweep failed: {e:#}");
            }
        }
        None => tracing::info!("backups disabled (CRYPTARCH_BACKUP_DIR unset)"),
    }

    // The loop always runs, because it carries maintenance that is not a
    // backup concern — the CRYPTARCH-80 stranded-delete sweep. Gating it on
    // backups would leave that sweep dead in two supported configurations
    // (backup dir unset, or externally-driven backups with interval 0), where
    // a delete failing at its first step would strand a live database
    // permanently instead of for one pass. Each half of the pass is gated
    // separately inside `sweep`.
    let backups_enabled = cfg.backup_dir.is_some() && cfg.backup_interval_secs > 0;
    let schedule = cryptarch::backup::Schedule { backups_enabled, ..schedule };
    if backups_enabled {
        tracing::info!(
            "backup loop every {}s, keeping {} per database, stale after {}s",
            cfg.backup_interval_secs,
            if cfg.backup_keep > 0 { cfg.backup_keep.to_string() } else { "all".into() },
            cfg.backup_stale_after_secs,
        );
    } else {
        tracing::info!(
            "backups not on the scheduler; maintenance loop every {}s",
            cryptarch::backup::MAINTENANCE_INTERVAL_SECS
        );
    }
    let schedule = cryptarch::backup::Schedule {
        interval_secs: if backups_enabled {
            cfg.backup_interval_secs
        } else {
            cryptarch::backup::MAINTENANCE_INTERVAL_SECS
        },
        ..schedule
    };
    tokio::spawn(cryptarch::backup::run_loop(state.clone(), schedule, notifier));
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
    // The SPA shell's CSP hash, computed at boot (dec D7) so a shell that cannot
    // be hashed reliably is reported here rather than as a blank page.
    match cryptarch::web::spa::check_shell() {
        Ok(n) => tracing::info!("SPA shell: {n} inline script(s) admitted by hash"),
        Err(e) => tracing::error!("SPA shell cannot be hashed reliably, /app will not load: {e}"),
    }
    if cryptarch::web::spa::is_placeholder() {
        tracing::warn!(
            "this binary embeds a PLACEHOLDER frontend — /app shows no UI. \
             Build it with `npm ci && npm run build` in frontend/, then rebuild."
        );
    }
    // Cloned before the state moves into the router — shutdown needs it after.
    let jobs = state.jobs.clone();
    let app = web::router(state);

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr)
        .await
        .with_context(|| format!("binding {}", cfg.bind_addr))?;
    tracing::info!("cryptarch listening on {}", cfg.bind_addr);

    // HTTP first, then the background jobs (CRYPTARCH-113). `with_graceful_
    // shutdown` drains CONNECTIONS only; the backup and restore runners are
    // spawned tasks with no relationship to it, so returning here used to drop
    // the runtime out from under a running dump — leaving a full-size partial
    // blob, because run_job's cleanup lives on an error path a dropped future
    // never reaches.
    //
    // Two bounds on top of that (CRYPTARCH-128). The job tracker stops
    // admitting new jobs the moment the signal arrives, not once HTTP has
    // drained. And HTTP itself gets HTTP_GRACE: graceful shutdown waits for
    // every connection with a request in progress, and nothing else bounds
    // that — a client that has opened a request and stalled would hold the
    // process up until the orchestrator SIGKILLs it, skipping the job drain.
    // HTTP_GRACE + the 20s job drain must stay under the compose file's
    // stop_grace_period (40s).
    const HTTP_GRACE: std::time::Duration = std::time::Duration::from_secs(8);
    let (signalled_tx, signalled_rx) = tokio::sync::oneshot::channel::<()>();
    let on_signal = {
        let jobs = jobs.clone();
        async move {
            shutdown_signal().await;
            jobs.close();
            let _ = signalled_tx.send(());
        }
    };
    let serving = std::future::IntoFuture::into_future(
        axum::serve(listener, app).with_graceful_shutdown(on_signal),
    );
    let serve = tokio::select! {
        r = serving => r.context("serving HTTP"),
        _ = async {
            // Pending forever unless the signal fired; then the grace period.
            if signalled_rx.await.is_ok() {
                tokio::time::sleep(HTTP_GRACE).await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::warn!("HTTP requests still open {HTTP_GRACE:?} after the shutdown signal — dropping them");
            Ok(())
        }
    };

    // Bounded: a multi-gigabyte dump can outlast any shutdown anyone will wait
    // through, and an orchestrator that lost patience would SIGKILL us — which
    // skips this path entirely and is strictly worse. Short jobs get the
    // seconds they need to settle their row; anything longer is logged and left
    // to the abandoned-job sweep. Runs even if serving errored.
    // Docker's default stop timeout is 10s, which would SIGKILL this halfway;
    // docker-compose.yml raises `stop_grace_period` above it for that reason.
    jobs.drain(std::time::Duration::from_secs(20)).await;
    serve?;
    tracing::info!("drained — bye");
    Ok(())
}

/// What `cryptarch backup ...` was asked to do.
enum BackupRequest {
    All,
    One(String),
}

/// Parse the `backup` subcommand, if that is how we were invoked.
///
/// Hand-rolled rather than pulling in an argument parser: the server takes no
/// arguments at all, so the entire surface is this one subcommand.
fn cli_backup_request() -> anyhow::Result<Option<BackupRequest>> {
    let mut args = std::env::args().skip(1);
    let Some(first) = args.next() else {
        return Ok(None);
    };
    if first != "backup" {
        anyhow::bail!("unknown argument '{first}' (usage: cryptarch [backup --all | backup --db NAME])");
    }
    match args.next().as_deref() {
        Some("--all") => Ok(Some(BackupRequest::All)),
        Some("--db") => match args.next() {
            Some(name) => Ok(Some(BackupRequest::One(name))),
            None => anyhow::bail!("--db needs a database name"),
        },
        _ => anyhow::bail!("usage: cryptarch backup --all | cryptarch backup --db NAME"),
    }
}

/// Run backups to completion and exit non-zero if any of them failed, so cron
/// and systemd timers report honestly.
async fn run_cli_backup(state: web::AppState, request: BackupRequest) -> anyhow::Result<()> {
    if state.backup_dir.is_none() {
        anyhow::bail!("backups are not configured — set CRYPTARCH_BACKUP_DIR");
    }
    let names = match request {
        BackupRequest::One(name) => vec![name],
        BackupRequest::All => {
            let mut names: Vec<String> =
                sqlx::query_scalar(
                    // Live databases only — see backup::scheduled_targets.
                    sqlx::AssertSqlSafe(format!(
                        "SELECT name FROM databases WHERE {} ORDER BY name",
                        cryptarch::status::DbStatus::should_be_backed_up_sql()
                    )),
                )
                    .fetch_all(&state.db)
                    .await
                    .context("listing databases")?;
            names.push(cryptarch::backup::METADATA_DB.to_string());
            names
        }
    };

    let mut failed = 0;
    for name in &names {
        match cryptarch::backup::run_now(&state, "cli", name).await {
            Ok(cryptarch::backup::Outcome::Ok { size_bytes }) => {
                println!("ok      {name} ({size_bytes} bytes)");
            }
            // Counted as a failure on purpose (CRYPTARCH-85). The blob is on
            // disk and probably fine, but nothing in the metadata database
            // knows it exists, so it is not a backup anyone can find. Exiting
            // 0 here is how cron reports a good backup that was never
            // recorded — the whole bug this variant exists to make unsayable.
            Ok(cryptarch::backup::Outcome::Unrecorded { size_bytes, detail }) => {
                println!("UNRECORDED {name} ({size_bytes} bytes on disk): {detail}");
                failed += 1;
            }
            Ok(cryptarch::backup::Outcome::Failed { error }) => {
                println!("FAILED  {name}: {error}");
                failed += 1;
            }
            Err(e) => {
                println!("FAILED  {name}: {e}");
                failed += 1;
            }
        }
    }
    anyhow::ensure!(failed == 0, "{failed} of {} backup(s) failed", names.len());
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
