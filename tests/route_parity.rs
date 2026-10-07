//! Route parity between the maud UI and the JSON API (CRYPTARCH-130).
//!
//! The SvelteKit migration is only safe if no capability is lost on the way:
//! every maud route had to end up with an API equivalent, or be kept or dropped
//! for a stated reason. This test made that a ledger rather than a memory, and
//! after cutover (CRYPTARCH-137) it is the record of what happened to each one.
//! It reads both routers from SOURCE and checks [`LEDGER`] against them:
//!
//! * every API endpoint a `Done` entry names must exist in the API router;
//! * nothing is still `Pending`;
//! * a `Keep` route is still on the server, and a `Done`, `Spa` or `Gone` one
//!   is not — the page is the SPA's now;
//! * the server routes nothing that is not a `Keep` entry, so a page route
//!   added back (a second door, outside the API's guards) fails here.

use std::collections::BTreeSet;

/// Set by the cutover task, after which nothing may still be pending.
const CUTOVER: bool = true;

enum Status {
    /// Replaced by these API endpoints ("METHOD /api/v1/...").
    Done(&'static [&'static str]),
    /// Not yet migrated; the slice that owns it.
    Pending(&'static str),
    /// Stays a plain server route after cutover, for this reason.
    Keep(&'static str),
    /// Served by the SPA now — its shell, or a file in its build — with no
    /// server route of its own.
    Spa(&'static str),
    /// Deleted at cutover, for this reason.
    Gone(&'static str),
}
use Status::*;

const LEDGER: &[(&str, Status)] = &[
    ("GET /", Spa("the SPA's index route, which sends you to the dashboard or the login")),
    ("GET /login", Done(&["GET /api/v1/session"])),
    ("POST /login", Done(&["POST /api/v1/session"])),
    ("POST /logout", Done(&["DELETE /api/v1/session"])),
    ("GET /dashboard", Done(&["GET /api/v1/databases"])),
    ("GET /provision", Done(&["GET /api/v1/servers"])),
    ("POST /provision", Done(&["POST /api/v1/databases"])),
    // All five tabs: the header and Connect (S4a), then one endpoint per tab.
    ("GET /db/{name}", Done(&["GET /api/v1/databases/{name}", "GET /api/v1/databases/{name}/contents", "GET /api/v1/databases/{name}/acl", "GET /api/v1/databases/{name}/backups", "GET /api/v1/databases/{name}/restores"])),
    ("POST /db/{name}/acl", Done(&["POST /api/v1/databases/{name}/acl"])),
    ("POST /db/{name}/acl/{entry_id}/remove", Done(&["DELETE /api/v1/databases/{name}/acl/{entry_id}"])),
    ("POST /db/{name}/backup", Done(&["POST /api/v1/databases/{name}/backups"])),
    ("POST /db/{name}/restore/{backup_id}", Done(&["POST /api/v1/databases/{name}/restores"])),
    ("GET /db/{name}/restores/{id}", Done(&["GET /api/v1/databases/{name}/restores/{id}"])),
    ("POST /db/{name}/reset", Done(&["POST /api/v1/databases/{name}/reset"])),
    ("POST /db/{name}/delete", Done(&["POST /api/v1/databases/{name}/delete"])),
    ("GET /metrics", Keep("Prometheus scrape target; bearer-token gated, not a page")),
    ("GET /profile", Done(&["GET /api/v1/session", "GET /api/v1/me/sessions"])),
    ("POST /profile/password", Done(&["POST /api/v1/me/password"])),
    ("POST /profile/sessions/revoke-others", Done(&["POST /api/v1/me/sessions/revoke-others"])),
    ("GET /admin", Done(&["GET /api/v1/admin/overview"])),
    ("GET /admin/users", Done(&["GET /api/v1/admin/users"])),
    ("POST /admin/users", Done(&["POST /api/v1/admin/users"])),
    ("GET /admin/users/new", Done(&["POST /api/v1/admin/users"])),
    ("GET /admin/users/{id}", Done(&["GET /api/v1/admin/users/{id}"])),
    ("POST /admin/users/{id}/reset-password", Done(&["POST /api/v1/admin/users/{id}/reset-password"])),
    ("POST /admin/users/{id}/quota", Done(&["POST /api/v1/admin/users/{id}/quota"])),
    ("POST /admin/users/{id}/active", Done(&["POST /api/v1/admin/users/{id}/active"])),
    ("GET /admin/databases", Done(&["GET /api/v1/admin/databases"])),
    ("GET /admin/backups", Done(&["GET /api/v1/admin/backups", "GET /api/v1/admin/backups/left-behind", "GET /api/v1/admin/backups/unreferenced"])),
    ("POST /admin/backups/{id}/purge", Done(&["POST /api/v1/admin/backups/{id}/purge"])),
    ("POST /admin/backups/purge-file", Done(&["POST /api/v1/admin/backups/purge-file"])),
    ("GET /admin/logins", Done(&["GET /api/v1/admin/logins"])),
    ("POST /admin/logins/{name}/retry-delete", Done(&["POST /api/v1/admin/logins/{name}/retry-delete"])),
    ("GET /admin/servers", Done(&["GET /api/v1/admin/servers"])),
    ("POST /admin/servers", Done(&["POST /api/v1/admin/servers"])),
    ("GET /admin/servers/new", Done(&["POST /api/v1/admin/servers"])),
    ("GET /admin/servers/{id}", Done(&["GET /api/v1/admin/servers/{id}", "GET /api/v1/admin/servers/{id}/overview", "GET /api/v1/admin/servers/{id}/edge", "GET /api/v1/admin/servers/{id}/config"])),
    ("POST /admin/servers/{id}/active", Done(&["POST /api/v1/admin/servers/{id}/active"])),
    ("POST /admin/servers/{id}/test", Done(&["POST /api/v1/admin/servers/{id}/test"])),
    ("POST /admin/servers/{id}/init", Done(&["POST /api/v1/admin/servers/{id}/init"])),
    ("POST /admin/servers/{id}/sync", Done(&["POST /api/v1/admin/servers/{id}/sync"])),
    ("GET /admin/servers/{id}/settings", Done(&["GET /api/v1/admin/servers/{id}"])),
    ("POST /admin/servers/{id}/settings/address", Done(&["POST /api/v1/admin/servers/{id}/settings/address"])),
    ("POST /admin/servers/{id}/settings/pooling", Done(&["POST /api/v1/admin/servers/{id}/settings/pooling"])),
    ("POST /admin/servers/{id}/settings/edge", Done(&["POST /api/v1/admin/servers/{id}/settings/edge"])),
    ("POST /admin/servers/{id}/settings/credentials", Done(&["POST /api/v1/admin/servers/{id}/credentials"])),
    ("POST /admin/servers/{id}/db/{db_id}/knobs", Done(&["POST /api/v1/admin/servers/{id}/databases/{db_id}/pool"])),
    ("POST /admin/servers/{id}/sources", Done(&["POST /api/v1/admin/servers/{id}/sources"])),
    ("POST /admin/servers/{id}/sources/{source_id}/remove", Done(&["DELETE /api/v1/admin/servers/{id}/sources/{source_id}"])),
    ("POST /admin/servers/{id}/listeners", Done(&["POST /api/v1/admin/servers/{id}/listeners"])),
    ("POST /admin/servers/{id}/listeners/{listener_id}/remove", Done(&["DELETE /api/v1/admin/servers/{id}/listeners/{listener_id}"])),
    ("GET /admin/audit", Done(&["GET /api/v1/admin/audit"])),
    ("GET /static/app.css", Gone("the Keyring design replaced it with keyring.css and components.css, bundled into the build (CRYPTARCH-156)")),
    ("GET /static/app.js", Gone("its behaviours were ported page by page")),
    ("GET /static/htmx.min.js", Gone("deleted with htmx")),
    ("GET /static/favicon.svg", Spa("frontend/static/static/favicon.svg, at the same path")),
    ("GET /static/fonts/fraunces-var.woff2", Gone("replaced by Figtree in the Keyring design (CRYPTARCH-151)")),
    ("GET /static/fonts/manrope-var.woff2", Gone("replaced by Figtree in the Keyring design (CRYPTARCH-151)")),
    ("GET /healthz", Keep("liveness probe for orchestrators, not a page")),
    ("ANY /api", Keep("JSON 404 for unknown API paths, beside the versioned API")),
    ("ANY /api/", Keep("JSON 404 for unknown API paths, beside the versioned API")),
    ("ANY /api/{*rest}", Keep("JSON 404 for unknown API paths, beside the versioned API")),
];

/// The only ways the maud router may compose other routers. Anything else —
/// a new `.nest`, a `.merge`, `route_service`, `on(MethodFilter..)` — adds
/// routes this scanner cannot see into, so it fails the test instead of being
/// silently missed (CRYPTARCH-138).
/// In the scanner's whitespace-free form; see [`normalise`].
const KNOWN_COMPOSITION: &[&str] = &[".merge(spa::router())", ".nest(\"/api/v1\",crate::api::router())"];

/// `src` with `//` and `/* */` comments removed, so a commented-out route
/// neither counts as present nor hides one.
fn strip_comments(src: &str) -> String {
    let mut out = String::new();
    let mut rest = src;
    while let Some(i) = rest.find("/*") {
        out.push_str(&rest[..i]);
        rest = rest[i..].find("*/").map_or("", |j| &rest[i + j + 2..]);
    }
    out.push_str(rest);
    out.lines().map(|l| l.split("//").next().unwrap_or("")).collect::<Vec<_>>().join("\n")
}

/// Comments stripped and ALL whitespace removed (CRYPTARCH-138), so `. merge (`
/// and `post (h)` read the same as `.merge(` and `post(h)`. Route paths contain
/// no whitespace, so nothing the scanner matches on is lost.
fn normalise(src: &str) -> String {
    strip_comments(src).chars().filter(|c| !c.is_whitespace()).collect()
}

/// "METHOD /path" for every `.route("/path", get(..).post(..))` in `src`.
/// Panics on a `.route(` it can read no method from — a route handed a method
/// router built elsewhere is one this scanner would otherwise silently miss.
fn routes_in(src: &str, prefix: &str) -> BTreeSet<String> {
    let src = normalise(src);
    let mut out = BTreeSet::new();
    let mut rest = src.as_str();
    while let Some(i) = rest.find(".route(") {
        rest = &rest[i + ".route(".len()..];
        let Some(q1) = rest.find('"') else { break };
        let after = &rest[q1 + 1..];
        let Some(q2) = after.find('"') else { break };
        let path = &after[..q2];
        // The method list runs to the end of this .route( ... ) call.
        let mut depth = 1;
        let mut end = 0;
        for (k, c) in rest.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = k;
                        break;
                    }
                }
                _ => {}
            }
        }
        let call = &rest[..end];
        let mut methods = 0;
        for m in ["get", "post", "put", "patch", "delete", "any"] {
            let mut search = call;
            while let Some(p) = search.find(&format!("{m}(")) {
                let before = search[..p].chars().last();
                // `get(` but not `budget(`: a method is its own token.
                if !before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    out.insert(format!("{} {prefix}{path}", m.to_uppercase()));
                    methods += 1;
                }
                search = &search[p + 1..];
            }
        }
        assert!(methods > 0, "cannot read any method from the route `{path}` — this scanner would miss it");
    }
    out
}

fn maud_router_source() -> String {
    let src = std::fs::read_to_string("src/web/mod.rs").unwrap();
    let start = src.find("pub fn router(state: AppState) -> Router {").expect("the maud router");
    let body = &src[start..];
    normalise(&body[..body.find("\n}\n").unwrap()])
}

fn maud_routes() -> BTreeSet<String> {
    routes_in(&maud_router_source(), "")
}

/// Fail on any way of adding routes the scanner does not model.
fn assert_only_modelled_composition(src: &str, known: &[&str], what: &str) {
    let mut s = src.to_string();
    for k in known {
        s = s.replace(k, "");
    }
    for construct in [".nest(", ".merge(", "_service(", "on(MethodFilter", "routing::on("] {
        assert!(!s.contains(construct), "{what} uses `{construct}`, which this scanner cannot see into");
    }
}

fn api_sources() -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from("src/api")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(std::fs::read_to_string(&p).unwrap());
            }
        }
    }
    out
}

#[test]
fn both_routers_only_compose_in_ways_the_scanner_models() {
    assert_only_modelled_composition(&maud_router_source(), KNOWN_COMPOSITION, "the maud router");
    // API sub-routers would need their prefixes tracked; none exist yet.
    for src in api_sources() {
        assert_only_modelled_composition(&normalise(&src), &[], "src/api");
    }
}

fn api_routes() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut stack = vec![std::path::PathBuf::from("src/api")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.extend(routes_in(&std::fs::read_to_string(&p).unwrap(), "/api/v1"));
            }
        }
    }
    out
}

#[test]
fn every_maud_route_is_accounted_for_in_the_migration_ledger() {
    let server = maud_routes();
    // Premise: the scanner reads the router at all — a parse that found nothing
    // would make every check below pass for free.
    assert!(server.contains("GET /healthz") && server.contains("GET /metrics"), "scanner found {server:?}");

    let keep: BTreeSet<String> =
        LEDGER.iter().filter(|(_, s)| matches!(s, Keep(_))).map(|(r, _)| r.to_string()).collect();
    let unplanned: Vec<_> = server.difference(&keep).collect();
    assert!(unplanned.is_empty(), "server routes the ledger does not keep — a page belongs to the SPA: {unplanned:?}");
    let lost: Vec<_> = keep.difference(&server).collect();
    assert!(lost.is_empty(), "routes the ledger keeps that the server no longer has: {lost:?}");
    assert!(CUTOVER, "the ledger is the cutover's record");
    // And the routes that left took their handlers with them: no Done, Spa or
    // Gone route is still on the server.
    for (route, status) in LEDGER {
        if !matches!(status, Keep(_)) {
            assert!(!server.contains(*route), "{route} is still a server route after cutover");
        }
    }
}

#[test]
fn every_done_entry_names_endpoints_the_api_really_has() {
    let api = api_routes();
    assert!(api.contains("POST /api/v1/session"), "premise: the API scanner works: {api:?}");
    for (route, status) in LEDGER {
        if let Done(endpoints) = status {
            for e in *endpoints {
                assert!(api.contains(*e), "{route} is marked done via {e}, which the API does not have");
            }
        }
        match status {
            // A route kept, pending, moved or removed must say why, or the
            // ledger is a list of names rather than a set of decisions.
            Keep(why) | Pending(why) | Spa(why) | Gone(why) => assert!(!why.trim().is_empty(), "{route} gives no reason"),
            Done(_) => {}
        }
        if let (true, Pending(why)) = (CUTOVER, status) {
            panic!("{route} is still pending at cutover ({why})");
        }
    }
}

#[test]
fn the_scanner_ignores_comments_and_reads_any() {
    let src = r#"
        .route("/a", get(x).post(y))
        // .route("/commented", get(z))
        .route("/b", any(w))
    "#;
    let found = routes_in(src, "");
    assert!(found.contains("GET /a") && found.contains("POST /a") && found.contains("ANY /b"), "{found:?}");
    assert!(!found.iter().any(|r| r.contains("/commented")), "a commented route must not count: {found:?}");
}

#[test]
fn unmodelled_composition_fails_the_scanner() {
    for src in [
        r#".route_service("/x", svc)"#,
        r#". merge ( other() )"#,
        r#".fallback_service(svc)"#,
        r#".route("/x", get_service(svc))"#,
        r#".route("/x", axum::routing::on(axum::routing::MethodFilter::POST, h))"#,
        r#"/* fine */ .nest ("/y", r)"#,
    ] {
        let caught = std::panic::catch_unwind(|| {
            assert_only_modelled_composition(&normalise(src), &[], "synthetic")
        });
        assert!(caught.is_err(), "not caught: {src}");
    }
}

#[test]
fn spacing_and_block_comments_do_not_hide_or_invent_routes() {
    let found = routes_in(r#".route ("/a", post (h)) /* .route("/ghost", get(g)) */"#, "");
    assert!(found.contains("POST /a"), "{found:?}");
    assert!(!found.iter().any(|r| r.contains("ghost")), "{found:?}");
}

#[test]
#[should_panic(expected = "cannot read any method")]
fn a_route_with_no_readable_method_fails_the_scanner() {
    routes_in(r#".route("/x", handlers())"#, "");
}
