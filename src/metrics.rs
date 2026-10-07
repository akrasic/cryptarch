//! Prometheus exposition for the servers Cryptarch manages (CRYPTARCH-98).
//!
//! # Why this lives here and not in postgres_exporter
//!
//! `postgres_exporter` is one process per target, each with its own DSN in its
//! own config file. Cryptarch already holds every managed server's admin
//! credentials, encrypted, in a registry with a UI in front of it. Pointing a
//! second tool at the same servers means the same credentials in two places
//! kept in sync by hand — and a server added through the UI stays silently
//! unmonitored until somebody remembers to edit the exporter too. Exporting
//! from here means a server is scraped the moment it is registered.
//!
//! It is deliberately NOT a replacement for `postgres_exporter` on the metadata
//! database, or `pgbouncer_exporter` on the edge. Neither is reached through
//! the engine registry, so neither is ours to export; both are a compose stanza
//! away and should be.
//!
//! # The division of labour
//!
//! The panel says what is true now and what to do about it. This says what the
//! numbers were, so Prometheus can say what has been happening and wake someone
//! at three in the morning. Each answers the other's weakest question, which is
//! why the UI is not growing graphs.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::web::AppState;

/// How long the whole scrape may take, across every managed server.
///
/// A scrape runs the maintenance checks against each one, and a server being
/// slow to answer is a *reason to scrape it*, not a reason to hang. Prometheus
/// gives up on its own side anyway; this makes sure we do too.
const SCRAPE_BUDGET: std::time::Duration = std::time::Duration::from_secs(8);

/// Per-server budget inside the overall one.
const PER_SERVER: std::time::Duration = std::time::Duration::from_secs(3);

/// `GET /metrics`.
///
/// # Why this needs a token when most exporters do not
///
/// The compose stack publishes the app port on every interface, and this
/// endpoint carries tenant DATABASE NAMES. An open `/metrics` therefore hands
/// the full tenant inventory to anyone who can reach the panel — which is a
/// smaller leak than credentials and a leak all the same, and this project's
/// posture is default-deny.
///
/// Unset token means the endpoint does not exist: 404, not 403. A 403 confirms
/// there is something here to come back for.
pub async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(expected) = state.metrics_token.as_deref() else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    // Constant-time compare: a scrape token is a secret, and this endpoint is
    // reachable by anyone who can reach the panel.
    let ok = presented.is_some_and(|p| {
        use subtle::ConstantTimeEq;
        // The length check is not constant-time and cannot be: `ct_eq` requires
        // equal lengths. Token LENGTH leaking is not a weakness — the value is.
        p.len() == expected.len() && p.as_bytes().ct_eq(expected.as_bytes()).into()
    });
    if !ok {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }

    let body = tokio::time::timeout(SCRAPE_BUDGET, gather(&state))
        .await
        .unwrap_or_else(|_| "# scrape timed out gathering metrics\n".to_string());

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn gather(state: &AppState) -> String {
    let mut out = String::with_capacity(4096);

    // ---- inventory ------------------------------------------------------
    let dbs: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT s.name::text, d.status::text, count(*)::bigint \
         FROM databases d JOIN managed_servers s ON s.id = d.server_id \
         GROUP BY 1, 2",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    help(&mut out, "cryptarch_databases", "gauge", "Provisioned databases by server and status.");
    for (server, status, n) in &dbs {
        line(&mut out, "cryptarch_databases", &[("server", server), ("status", status)], *n as f64);
    }

    let users: i64 =
        sqlx::query_scalar("SELECT count(*)::bigint FROM users WHERE is_active")
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);
    help(&mut out, "cryptarch_users", "gauge", "Active user accounts.");
    line(&mut out, "cryptarch_users", &[], users as f64);

    // ---- backups --------------------------------------------------------
    // The series most worth alerting on: the panel can only ever show you a
    // badge for "this is stale", and staleness is a function of time, which is
    // exactly what a panel cannot watch while nobody is looking at it.
    let last: Vec<(String, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
        "SELECT db_name::text, max(finished_at) \
         FROM backups WHERE status = 'ok' GROUP BY 1",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    help(
        &mut out,
        "cryptarch_backup_last_success_timestamp_seconds",
        "gauge",
        "Unix time of the most recent successful backup of each database.",
    );
    for (db, at) in &last {
        if let Some(at) = at {
            line(
                &mut out,
                "cryptarch_backup_last_success_timestamp_seconds",
                &[("database", db)],
                at.timestamp() as f64,
            );
        }
    }

    let by_status: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status::text, count(*)::bigint FROM backups GROUP BY 1",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    help(&mut out, "cryptarch_backups", "gauge", "Backup rows by status.");
    for (status, n) in &by_status {
        line(&mut out, "cryptarch_backups", &[("status", status)], *n as f64);
    }

    // ---- per managed server ---------------------------------------------
    let servers: Vec<(uuid::Uuid, String)> =
        sqlx::query_as("SELECT id, name::text FROM managed_servers WHERE is_active")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    help(&mut out, "cryptarch_server_up", "gauge", "1 if the managed server answered its maintenance checks.");
    let mut findings_out = String::new();
    let mut metrics_out = String::new();

    // Concurrent, not serial (CRYPTARCH-115) — the same reasoning, and the
    // same primitive, as `admin::logins`: each survey is individually bounded
    // by PER_SERVER, but a serial loop makes the worst case N × that bound, so
    // three slow servers alone exceed SCRAPE_BUDGET and the outer timeout then
    // discards the WHOLE body. That threw away the local metadata series —
    // inventory, user counts, and `cryptarch_backup_last_success_timestamp_
    // seconds`, which this module's own docs call the series most worth
    // alerting on — because a REMOTE box was slow. Which is the exact opposite
    // of what the note on SCRAPE_BUDGET says this endpoint is for.
    let mut tasks = tokio::task::JoinSet::new();
    for (id, name) in &servers {
        let (id, name) = (*id, name.clone());
        let engine = state.servers.get(id);
        tasks.spawn(async move {
            let report = match engine {
                Some(engine) => tokio::time::timeout(PER_SERVER, engine.maintenance())
                    .await
                    .ok()
                    .and_then(Result::ok),
                None => None,
            };
            (name, report)
        });
    }
    let mut reports: Vec<(String, Option<crate::engine::MaintenanceReport>)> = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        // A panicked survey is one server's problem, not the scrape's.
        match joined {
            Ok(r) => reports.push(r),
            Err(e) => tracing::error!("a maintenance survey panicked during scrape: {e}"),
        }
    }
    // Sorted so the exposition is stable between scrapes; JoinSet completes in
    // whatever order the servers answer.
    reports.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, report) in &reports {
        let name = name.as_str();
        line(&mut out, "cryptarch_server_up", &[("server", name)], report.is_some() as u8 as f64);

        let Some(report) = report else { continue };
        for f in &report.findings {
            // Severity as a number so an alert can be written against any
            // check without the rule needing to know which checks exist.
            line(
                &mut findings_out,
                "cryptarch_server_check_severity",
                &[("server", name), ("check", &f.title)],
                match f.severity {
                    crate::engine::Severity::Ok => 0.0,
                    crate::engine::Severity::Watch => 1.0,
                    crate::engine::Severity::Urgent => 2.0,
                },
            );
            for (metric, value) in &f.metrics {
                line(
                    &mut metrics_out,
                    &format!("cryptarch_server_{metric}"),
                    &[("server", name)],
                    *value,
                );
            }
        }
    }
    help(
        &mut out,
        "cryptarch_server_check_severity",
        "gauge",
        "0 ok, 1 watch, 2 urgent, per maintenance check.",
    );
    out.push_str(&findings_out);
    // Engine-named series. No HELP/TYPE: the names come from the engine, and
    // inventing descriptions for numbers this module does not understand would
    // be writing documentation by guess.
    out.push_str(&metrics_out);
    out
}

fn help(out: &mut String, name: &str, kind: &str, text: &str) {
    out.push_str(&format!("# HELP {name} {text}\n# TYPE {name} {kind}\n"));
}

/// One sample. Label values are escaped because they include database and
/// server names, which are operator- and tenant-supplied text going into a
/// line-oriented format — an unescaped quote or newline would corrupt the rest
/// of the scrape, not just its own line.
fn line(out: &mut String, name: &str, labels: &[(&str, &str)], value: f64) {
    out.push_str(name);
    if !labels.is_empty() {
        out.push('{');
        for (i, (k, v)) in labels.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&escape(v));
            out.push('"');
        }
        out.push('}');
    }
    out.push_str(&format!(" {value}\n"));
}

/// Prometheus label-value escaping: backslash, double quote, newline.
fn escape(v: &str) -> String {
    let mut s = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            _ => s.push(c),
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_values_cannot_break_out_of_the_format() {
        // A database name cannot contain these — `valid_db_name` sees to that —
        // but SERVER names are admin-supplied and this is a line-oriented
        // format, so one unescaped newline would corrupt every sample after it
        // rather than just its own.
        let mut out = String::new();
        line(&mut out, "m", &[("server", "a\"b\\c\nd")], 1.0);
        assert_eq!(out, "m{server=\"a\\\"b\\\\c\\nd\"} 1\n");
        assert_eq!(out.lines().count(), 1, "the sample must stay on one line");
    }

    #[test]
    fn a_sample_without_labels_has_no_braces() {
        let mut out = String::new();
        line(&mut out, "cryptarch_users", &[], 4.0);
        assert_eq!(out, "cryptarch_users 4\n");
    }
}
