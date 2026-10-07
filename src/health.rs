//! Background health checks + transition notifications (CRYPTARCH-43).
//!
//! An in-process loop — no cron, no sidecar — probes every active server on
//! an interval: the edge listener (TCP to the advertised address, i.e. what
//! users actually dial), Postgres (DbEngine::ping over the admin connection),
//! and config drift (the same checksum checks the Edge health page runs on view,
//! but on a schedule, so drift is noticed before an admin happens to look).
//!
//! Alerting is TRANSITION-based: a check going red fires one notification,
//! recovery fires one — a flapping check can be noisy at most once per flap,
//! and steady states are silent. Every transition is also audited as
//! `system`, so the audit log doubles as an incident history.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use uuid::Uuid;

use crate::web::AppState;

/// One check's outcome: Ok, or why not.
pub type CheckResult = Result<(), String>;

/// A server's latest probe results.
#[derive(Debug, Clone)]
pub struct ServerHealth {
    pub edge: CheckResult,
    pub postgres: CheckResult,
    /// None = not checkable from here (no conf dir — manual placement).
    pub drift: Option<CheckResult>,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

impl ServerHealth {
    pub fn all_ok(&self) -> bool {
        self.edge.is_ok()
            && self.postgres.is_ok()
            && self.drift.as_ref().is_none_or(|d| d.is_ok())
    }
}

/// A state change worth telling someone about.
#[derive(Debug, Clone, PartialEq)]
pub struct Transition {
    pub server: String,
    pub check: &'static str,
    /// true = went red, false = recovered.
    pub failed: bool,
    pub detail: String,
}

/// Latest health per server, shared with the web layer.
#[derive(Clone, Default)]
pub struct HealthRegistry(Arc<Mutex<HashMap<Uuid, ServerHealth>>>);

impl HealthRegistry {
    pub fn get(&self, id: Uuid) -> Option<ServerHealth> {
        self.0.lock().unwrap().get(&id).cloned()
    }

    /// Store a fresh result and compute the transitions vs the previous one.
    /// First observation only reports FAILURES (a server that boots healthy
    /// should not fire a "recovered" volley).
    pub fn update(&self, id: Uuid, name: &str, fresh: ServerHealth) -> Vec<Transition> {
        let mut map = self.0.lock().unwrap();
        let prev = map.insert(id, fresh.clone());
        let mut out = Vec::new();
        let mut diff = |check: &'static str, old: Option<&CheckResult>, new: &CheckResult| {
            let was_ok = old.map(|r| r.is_ok());
            let is_ok = new.is_ok();
            let changed = match was_ok {
                None => !is_ok,          // first sighting: only report failures
                Some(w) => w != is_ok,   // afterwards: any flip
            };
            if changed {
                out.push(Transition {
                    server: name.to_string(),
                    check,
                    failed: !is_ok,
                    detail: new.as_ref().err().cloned().unwrap_or_else(|| "ok".into()),
                });
            }
        };
        diff("edge", prev.as_ref().map(|p| &p.edge), &fresh.edge);
        diff("postgres", prev.as_ref().map(|p| &p.postgres), &fresh.postgres);
        if let Some(new_drift) = &fresh.drift {
            diff("drift", prev.as_ref().and_then(|p| p.drift.as_ref()), new_drift);
        }
        out
    }

    /// Remove servers that no longer exist / are inactive, so a deleted
    /// server can't linger as a stale badge.
    pub fn retain(&self, live: &[Uuid]) {
        self.0.lock().unwrap().retain(|id, _| live.contains(id));
    }
}

/// Run every check for one server. Each probe carries its own timeout — a
/// wedged server must cost the loop seconds, not an interval.
pub async fn check_server(
    state: &AppState,
    id: Uuid,
    host: &str,
    port: u16,
    conf_dir: Option<&str>,
    tls_mode: &str,
) -> ServerHealth {
    let edge = crate::servers::tcp_check(host, port)
        .await
        .map_err(|e| format!("advertised address {host}:{port}: {e}"));

    let postgres = match state.servers.get(id) {
        Some(engine) => engine.ping().await.map_err(|e| e.to_string()),
        None => Err("engine not connected".into()),
    };

    let drift = match conf_dir.filter(|d| !d.is_empty()) {
        None => None,
        Some(dir) => Some(check_drift(state, id, dir, tls_mode).await),
    };

    ServerHealth { edge, postgres, drift, checked_at: chrono::Utc::now() }
}

/// The on-disk render vs desired state, condensed to one verdict. Mirrors
/// the richer per-file panel on the Edge health page; this one only answers
/// "does anything need attention".
async fn check_drift(state: &AppState, id: Uuid, dir: &str, tls_mode: &str) -> CheckResult {
    let dir = std::path::Path::new(dir);

    let desired_hba = match crate::acl::load_rules(&state.db, id).await {
        Ok(rules) => crate::acl::render_hba(&rules, tls_mode, crate::acl::console_cidr()),
        Err(e) => return Err(format!("loading ACL state: {e}")),
    };
    match std::fs::read_to_string(dir.join("pgbouncer_hba.conf")) {
        Err(_) => return Err("hba file missing".into()),
        Ok(content) => {
            match crate::acl::claimed_checksum(&content) {
                None => return Err("hba not cryptarch-managed".into()),
                Some(c) if c != crate::acl::body_checksum(&content) => {
                    return Err("hba hand-edited since last render".into())
                }
                Some(_) if content != desired_hba => {
                    return Err("hba stale vs current ACL state".into())
                }
                Some(_) => {}
            }
        }
    }

    let desired_knobs = match (
        crate::bouncer::load_server_knobs(&state.db, id).await,
        crate::bouncer::load_overrides(&state.db, id).await,
    ) {
        (Ok(k), Ok(o)) => crate::bouncer::render_knobs(&k, &o),
        _ => return Err("loading pool settings".into()),
    };
    match std::fs::read_to_string(dir.join(crate::bouncer::KNOBS_FILE)) {
        Err(_) => return Err("knobs file missing".into()),
        Ok(content) => {
            match crate::bouncer::claimed_checksum(&content) {
                None => return Err("knobs file not cryptarch-managed".into()),
                Some(c) if c != crate::bouncer::body_checksum(&content) => {
                    return Err("knobs hand-edited since last render".into())
                }
                Some(_) if content != desired_knobs => {
                    return Err("knobs stale vs current settings".into())
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

// ---- notifications ----------------------------------------------------------

/// Where and how transitions are delivered.
#[derive(Clone)]
pub enum Notifier {
    /// No URL configured — transitions still audit, nothing is sent.
    Disabled,
    /// ntfy-style: plain-text body, Title/Priority/Tags headers.
    Ntfy { url: String, client: reqwest::Client },
    /// Generic webhook: one JSON object per transition.
    Json { url: String, client: reqwest::Client },
}

impl Notifier {
    pub fn from_config(url: Option<&str>, format: &str) -> Self {
        let Some(url) = url.filter(|u| !u.is_empty()) else {
            return Self::Disabled;
        };
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("building http client");
        match format {
            "json" => Self::Json { url: url.to_string(), client },
            _ => Self::Ntfy { url: url.to_string(), client },
        }
    }

    /// Delivery is best-effort by design: the health loop must never wedge
    /// on a dead notification endpoint. Failures are logged, not retried.
    pub async fn send(&self, t: &Transition) {
        let res = match self {
            Self::Disabled => return,
            Self::Ntfy { url, client } => {
                let (title, priority, tags) = ntfy_meta(t);
                client
                    .post(url)
                    .header("Title", title)
                    .header("Priority", priority)
                    .header("Tags", tags)
                    .body(message(t))
                    .send()
                    .await
            }
            Self::Json { url, client } => {
                client
                    .post(url)
                    .json(&serde_json::json!({
                        "source": "cryptarch",
                        "server": t.server,
                        "check": t.check,
                        "status": if t.failed { "failed" } else { "recovered" },
                        "detail": t.detail,
                        "message": message(t),
                    }))
                    .send()
                    .await
            }
        };
        match res {
            Ok(r) if !r.status().is_success() => {
                tracing::warn!("notify for {}/{}: endpoint returned {}", t.server, t.check, r.status());
            }
            Err(e) => tracing::warn!("notify for {}/{}: {e}", t.server, t.check),
            Ok(_) => {}
        }
    }
}

/// Human message, shared by both formats and the audit log.
pub fn message(t: &Transition) -> String {
    // Backups are about a database, not a server, and "DOWN"/"recovered" reads
    // wrong for them — the incident is that data is unprotected.
    if t.check == "backup" {
        return if t.failed {
            format!("{}: BACKUP AT RISK — {}", t.server, t.detail)
        } else {
            format!("{}: backups healthy again", t.server)
        };
    }
    let what = match t.check {
        "edge" => "edge listener",
        "postgres" => "postgres",
        "drift" => "edge config",
        other => other,
    };
    if t.failed {
        format!("{}: {what} DOWN — {}", t.server, t.detail)
    } else {
        format!("{}: {what} recovered", t.server)
    }
}

fn ntfy_meta(t: &Transition) -> (String, &'static str, &'static str) {
    let title = format!("Cryptarch · {}", t.server);
    if t.failed {
        (title, "high", "rotating_light")
    } else {
        (title, "default", "white_check_mark")
    }
}

// ---- the loop ---------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct HealthTarget {
    id: Uuid,
    name: String,
    host: String,
    port: i32,
    bouncer_conf_dir: Option<String>,
    tls_mode: String,
}

/// One full sweep over active servers; returns fired transitions (tests use
/// this directly, the loop below wraps it).
pub async fn sweep(state: &AppState, registry: &HealthRegistry, notifier: &Notifier) {
    let targets = sqlx::query_as::<_, HealthTarget>(
        "SELECT id, name, host, port, bouncer_conf_dir, tls_mode \
         FROM managed_servers WHERE is_active",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    registry.retain(&targets.iter().map(|t| t.id).collect::<Vec<_>>());

    for t in targets {
        let health = check_server(
            state,
            t.id,
            &t.host,
            u16::try_from(t.port).unwrap_or(0),
            t.bouncer_conf_dir.as_deref(),
            &t.tls_mode,
        )
        .await;
        for tr in registry.update(t.id, &t.name, health) {
            let msg = message(&tr);
            tracing::info!("health transition: {msg}");
            crate::provision::audit(
                &state.db,
                "system",
                if tr.failed { "health_failed" } else { "health_recovered" },
                Some(&tr.server),
                Some(&msg),
            )
            .await;
            notifier.send(&tr).await;
        }
    }
}

/// The background loop. Interval 0 disables it (the caller just doesn't
/// spawn); first sweep runs one interval after boot, giving engines time to
/// connect instead of alerting on startup lag.
pub async fn run_loop(state: AppState, interval_secs: u64, notifier: Notifier) {
    let interval = std::time::Duration::from_secs(interval_secs);
    loop {
        tokio::time::sleep(interval).await;
        sweep(&state, &state.health, &notifier).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_health() -> ServerHealth {
        ServerHealth {
            edge: Ok(()),
            postgres: Ok(()),
            drift: Some(Ok(())),
            checked_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn first_sighting_reports_failures_but_not_health() {
        let reg = HealthRegistry::default();
        let id = Uuid::new_v4();
        assert!(reg.update(id, "srv", ok_health()).is_empty(), "healthy boot is silent");

        let reg = HealthRegistry::default();
        let mut h = ok_health();
        h.edge = Err("refused".into());
        let t = reg.update(id, "srv", h);
        assert_eq!(t.len(), 1);
        assert!(t[0].failed && t[0].check == "edge");
    }

    #[test]
    fn transitions_fire_on_flips_only() {
        let reg = HealthRegistry::default();
        let id = Uuid::new_v4();
        reg.update(id, "srv", ok_health());

        let mut down = ok_health();
        down.postgres = Err("connect timeout".into());
        let t = reg.update(id, "srv", down.clone());
        assert_eq!(t.len(), 1, "went red: one transition");
        assert!(t[0].failed);

        let t = reg.update(id, "srv", down);
        assert!(t.is_empty(), "still red: silent");

        let t = reg.update(id, "srv", ok_health());
        assert_eq!(t.len(), 1, "recovery: one transition");
        assert!(!t[0].failed);
    }

    #[test]
    fn drift_unknown_is_not_a_transition() {
        let reg = HealthRegistry::default();
        let id = Uuid::new_v4();
        let mut h = ok_health();
        h.drift = None; // manual placement — not checkable
        assert!(reg.update(id, "srv", h).is_empty());
    }

    #[test]
    fn messages_read_like_incidents() {
        let m = message(&Transition {
            server: "local".into(),
            check: "edge",
            failed: true,
            detail: "advertised address 10.0.0.5:6432: connection refused".into(),
        });
        assert_eq!(m, "local: edge listener DOWN — advertised address 10.0.0.5:6432: connection refused");
        let m = message(&Transition {
            server: "local".into(),
            check: "drift",
            failed: false,
            detail: "ok".into(),
        });
        assert_eq!(m, "local: edge config recovered");
    }

    #[test]
    fn retained_servers_only() {
        let reg = HealthRegistry::default();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        reg.update(a, "a", ok_health());
        reg.update(b, "b", ok_health());
        reg.retain(&[a]);
        assert!(reg.get(a).is_some());
        assert!(reg.get(b).is_none());
    }
}
