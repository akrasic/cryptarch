//! The embedded SvelteKit SPA (CRYPTARCH-129): how the binary serves it.
//!
//! No database needed — this is the static-file layer alone. The build
//! placeholder (build.rs, used when the frontend has not been built) carries a
//! real inline script and a real hashed asset on purpose, so every assertion
//! here exercises the serving machinery whether or not Node ever ran.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

async fn get(path: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let resp = cryptarch::web::spa::router::<()>()
        .fallback(cryptarch::web::spa::fallback)
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024).await.unwrap();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn header(h: &axum::http::HeaderMap, name: header::HeaderName) -> String {
    h.get(name).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
}

/// The inline `<script>` bodies in an HTML document, exactly as a browser
/// would hash them for CSP: the bytes between `>` and `</script>`.
fn inline_scripts(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(open) = rest.find("<script") {
        let after = &rest[open..];
        let tag_end = after.find('>').unwrap();
        let tag = &after[..tag_end];
        let body_start = open + tag_end + 1;
        let close = rest[body_start..].find("</script>").unwrap();
        if !tag.contains("src=") {
            out.push(rest[body_start..body_start + close].to_string());
        }
        rest = &rest[body_start + close..];
    }
    out
}

#[tokio::test]
async fn the_shell_is_served_for_the_root_and_any_deep_link() {
    for path in ["/", "/db/alice_app", "/admin/servers/x/settings", "/login"] {
        let (st, h, body) = get(path).await;
        assert_eq!(st, StatusCode::OK, "{path}");
        assert!(header(&h, header::CONTENT_TYPE).starts_with("text/html"), "{path}");
        assert!(body.contains("<script"), "{path}: not the SPA shell:\n{body}");
        // The shell names the current build's assets, so a cached one would
        // point at files a redeploy has removed.
        assert_eq!(header(&h, header::CACHE_CONTROL), "no-cache", "{path}");
    }
}

/// The CSP stays strict — no 'unsafe-inline' — and admits the shell's inline
/// bootstrap script by hash. Checked against the hash of the script the shell
/// ACTUALLY carries, computed here the way a browser computes it.
#[tokio::test]
async fn the_shell_csp_admits_exactly_its_own_inline_scripts() {
    let (_, h, body) = get("/").await;
    let csp = header(&h, header::CONTENT_SECURITY_POLICY);
    let scripts = inline_scripts(&body);
    assert!(!scripts.is_empty(), "premise: the shell has an inline script to admit");
    for s in &scripts {
        let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(s.as_bytes()));
        assert!(csp.contains(&format!("'sha256-{hash}'")), "CSP lacks the script's hash: {csp}");
    }
    assert!(!csp.contains("unsafe-inline"), "the CSP must stay strict: {csp}");
    assert!(csp.contains("default-src 'self'") && csp.contains("frame-ancestors 'none'"), "{csp}");
    assert!(!body.contains("style=\""), "an inline style attribute would be blocked by style-src 'self'");
}

#[tokio::test]
async fn hashed_assets_are_immutable_and_typed() {
    let (_, _, body) = get("/").await;
    let asset = body
        .split('"')
        .find(|s| s.starts_with("/_app/immutable/") && s.ends_with(".js"))
        .expect("premise: the shell references a hashed asset")
        .to_string();
    let (st, h, _) = get(&asset).await;
    assert_eq!(st, StatusCode::OK, "{asset}");
    assert!(header(&h, header::CACHE_CONTROL).contains("immutable"), "{asset}");
    assert!(header(&h, header::CONTENT_TYPE).contains("javascript"), "{asset}");
}

/// A missing asset is a 404, never the shell — otherwise a stale chunk after a
/// redeploy would "load" as HTML and fail with a baffling parse error.
#[tokio::test]
async fn a_missing_asset_is_not_answered_with_the_shell() {
    let (st, _, body) = get("/_app/immutable/chunks/does-not-exist.js").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert!(!body.contains("<script"), "a missing asset must not get the shell");
}

/// Nothing outside the embedded build is reachable, whatever the path says
/// (CRYPTARCH-138). In DEBUG — which is what this test runs in, and what
/// `cargo run` serves on 0.0.0.0 — rust-embed reads from disk at request time,
/// and follows a symlink out of the folder: before this guard,
/// `/app/\proc\self\exe` returned the running binary to anyone who asked.
#[tokio::test]
async fn no_path_reaches_outside_the_build() {
    let elf = b"\x7fELF";
    for path in [
        "/\\proc\\self\\exe",
        "/../../../../../../../../../proc/self/exe",
        "/_app/../../../../../../../../proc/self/exe",
        "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/proc/self/exe",
        "/..%2f..%2f..%2f..%2f..%2f..%2fproc%2fself%2fexe",
        "/_app/\\..\\..\\..\\..\\..\\..\\proc\\self\\exe",
        "//proc/self/exe",
        "/./200.html",
        "/_app/immutable/../../../Cargo.toml",
    ] {
        let resp = cryptarch::web::spa::router::<()>()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 64 * 1024 * 1024).await.unwrap();
        assert!(!body.starts_with(elf), "{path} served an executable");
        assert!(!String::from_utf8_lossy(&body).contains("[package]"), "{path} served Cargo.toml");
        // Either the shell (an unknown app route) or a 404 (an unknown asset) —
        // never anything else.
        assert!(
            status == StatusCode::NOT_FOUND
                || (status == StatusCode::OK && String::from_utf8_lossy(&body).contains("<script")),
            "{path}: {status}"
        );
    }
}

/// Only content-hashed files are immutable; anything else the build ships
/// (robots.txt) can change between deploys under the same name.
#[tokio::test]
async fn only_hashed_assets_are_immutable() {
    let (st, h, _) = get("/robots.txt").await;
    assert_eq!(st, StatusCode::OK, "premise: the build ships an unhashed file");
    assert_eq!(header(&h, header::CACHE_CONTROL), "no-cache");
}

/// `_app/version.json` sits under `_app/` but not `_app/immutable/`: SvelteKit
/// polls it to notice a new deploy, so caching it would hide every one.
#[tokio::test]
async fn the_version_file_is_not_cached_despite_living_under_app() {
    let (st, h, _) = get("/_app/version.json").await;
    if st == StatusCode::NOT_FOUND {
        // build.rs's placeholder has none; a real build always does (CI).
        assert!(cryptarch::web::spa::is_placeholder(), "a real build must ship _app/version.json");
        return;
    }
    assert_eq!(header(&h, header::CACHE_CONTROL), "no-cache");
}

/// The boot-time check accepts the shell that is actually embedded — so its
/// error path means something when it fires.
#[test]
fn the_embedded_shell_is_hashable() {
    let n = cryptarch::web::spa::check_shell().expect("the embedded shell must be hashable");
    assert!(n >= 1, "the shell boots from an inline script");
}
