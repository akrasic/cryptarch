//! The SvelteKit single-page app, compiled into the binary (CRYPTARCH-129;
//! dec-cryptarch-sveltekit-architecture).
//!
//! `frontend/` builds to static files with one fallback shell, `200.html`.
//! It is the whole UI (CRYPTARCH-137): every GET the server does not route
//! itself — the API, `/healthz`, `/metrics` — is a built file or that shell,
//! and the client-side router takes it from there. Three rules carry the
//! behaviour:
//!
//! * Hashed assets under `_app/immutable/` are cached for a year — their names
//!   change whenever their content does.
//! * The shell is `no-cache`: it names the current build's assets, and a cached
//!   one would point at files a redeploy has removed.
//! * A missing file under `_app/` is a 404, never the shell. Otherwise a stale
//!   chunk requested after a redeploy would "load" as HTML and fail with a
//!   parse error nobody could trace.
//!
//! The CSP stays strict — `script-src 'self'`, no `'unsafe-inline'`. SvelteKit
//! boots from one inline `<script>` in the shell, which is admitted by its
//! sha256 hash, computed here from the shell itself. The hash therefore always
//! matches whatever build is embedded; nothing has to be kept in sync by hand.

use axum::body::Body;
use axum::http::{header, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine as _;
use rust_embed::RustEmbed;
use sha2::{Digest, Sha256};

#[derive(RustEmbed)]
#[folder = "frontend/build"]
struct Build;

/// Where the SPA was mounted before cutover (CRYPTARCH-137). Its links
/// redirect to the same page at the root.
const OLD_BASE: &str = "/app";

const SHELL: &str = "200.html";

/// Written by build.rs into a placeholder build, never present in a real one.
const PLACEHOLDER_SENTINEL: &str = ".cryptarch-placeholder";

/// Whether this binary embeds build.rs's placeholder instead of a real
/// frontend — a portal with no UI. Logged at boot.
pub fn is_placeholder() -> bool {
    Build::get(PLACEHOLDER_SENTINEL).is_some()
}

/// Every directive but `script-src`. One definition for the whole app
/// (CRYPTARCH-138): the shell adds its hashes to `script-src`, every other
/// route is served [`PLAIN_CSP`].
macro_rules! csp_rest {
    () => {
        "default-src 'self'; style-src 'self'; img-src 'self'; \
         frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    };
}
const CSP_REST: &str = csp_rest!();

/// The policy for every route but the SPA shell: no inline script at all.
pub const PLAIN_CSP: &str = concat!("script-src 'self'; ", csp_rest!());

pub fn router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new()
        .route(OLD_BASE, get(moved))
        .route(&format!("{OLD_BASE}/"), get(moved))
        .route(&format!("{OLD_BASE}/{{*rest}}"), get(moved))
}

/// The router's fallback: a GET or HEAD for anything the server does not
/// route itself is the SPA's. Any other method there is a 404.
pub async fn fallback(method: Method, uri: Uri) -> Response {
    if method == Method::GET || method == Method::HEAD {
        serve(uri).await
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// `/app/...` → the same page at the root, query and all. The rest of the
/// path is stripped of leading slashes first: `/app//evil.example` must land
/// on `/evil.example` on this host, not on `//evil.example` — a
/// protocol-relative URL, which is another host.
async fn moved(uri: Uri) -> Redirect {
    let rest = uri.path().strip_prefix(OLD_BASE).unwrap_or("");
    let rest = rest.trim_start_matches(['/', '\\']);
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    Redirect::permanent(&format!("/{rest}{query}"))
}

/// A built file `rel` may name, if any (CRYPTARCH-138).
///
/// Two independent guards, because in DEBUG rust-embed reads from disk at
/// request time and follows a symlink whose canonical path is outside the
/// build folder: `/app/\proc\self\exe` once returned the running binary.
///
/// * The path must be plain segments — no `..`, `.`, empty segments,
///   backslashes, percent-escapes or colons. Nothing the build produces looks
///   like any of those.
/// * It must be a name the build's own listing contains. Lookup by listing
///   rather than by path means no input is ever resolved against a filesystem.
fn built_file(rel: &str) -> Option<rust_embed::EmbeddedFile> {
    let plain = !rel.is_empty()
        && !rel.contains(['\\', '%', ':', '\0'])
        && rel.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..");
    if !plain || !Build::iter().any(|name| name == rel) {
        return None;
    }
    Build::get(rel)
}

async fn serve(uri: Uri) -> Response {
    let rel = uri.path().trim_start_matches('/');
    if !rel.is_empty() && rel != SHELL {
        if let Some(file) = built_file(rel) {
            let cache = if rel.starts_with("_app/immutable/") {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            };
            return (
                [
                    (header::CONTENT_TYPE, file.metadata.mimetype().to_string()),
                    (header::CACHE_CONTROL, cache.to_string()),
                ],
                file.data.into_owned(),
            )
                .into_response();
        }
        if rel.starts_with("_app/") {
            return StatusCode::NOT_FOUND.into_response();
        }
    }
    shell()
}

/// The shell and the CSP that admits its inline scripts.
struct Shell {
    html: Vec<u8>,
    csp: HeaderValue,
    /// Set when the shell could not be hashed reliably; see [`script_hashes`].
    problem: Option<String>,
}

fn load_shell() -> Shell {
    let html = Build::get(SHELL).map(|f| f.data.into_owned()).unwrap_or_default();
    let (hashes, problem) = match script_hashes(&String::from_utf8_lossy(&html)) {
        Ok(h) => (h, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    let sources: String = hashes.iter().map(|h| format!(" '{h}'")).collect();
    let csp = format!("script-src 'self'{sources}; {CSP_REST}");
    Shell {
        html,
        csp: HeaderValue::from_str(&csp).expect("a CSP built from base64 hashes is a valid header"),
        problem,
    }
}

static RELEASE_SHELL: std::sync::LazyLock<Shell> = std::sync::LazyLock::new(load_shell);

/// Hash the shell now rather than on the first request, and report a shell
/// that cannot be hashed reliably. Called at boot. A wrong hash fails closed —
/// the browser refuses the bootstrap script and the page is blank — so the
/// failure must at least be loud somewhere a human looks.
pub fn check_shell() -> Result<usize, String> {
    let shell: &Shell = &RELEASE_SHELL;
    match &shell.problem {
        Some(p) => Err(p.clone()),
        None => Ok(script_hashes(&String::from_utf8_lossy(&shell.html)).map(|h| h.len()).unwrap_or(0)),
    }
}

fn shell() -> Response {
    // Cached in release, where the shell is compiled in and cannot change. In
    // debug rust-embed reads from disk, so a frontend rebuild is picked up
    // without restarting the backend — and the hash must follow it.
    let fresh;
    let s: &Shell = if cfg!(debug_assertions) {
        fresh = load_shell();
        &fresh
    } else {
        &RELEASE_SHELL
    };
    let mut resp = Body::from(s.html.clone()).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(header::CONTENT_SECURITY_POLICY, s.csp.clone());
    resp
}

/// The CSP source expressions (`sha256-…`) for a document's inline scripts,
/// computed the way a browser computes them (CRYPTARCH-138), or an error when
/// the document has a shape this cannot be sure about.
///
/// Browser semantics, pinned in the tests against hashes Chrome itself reported:
/// * line endings are normalised first (CRLF and lone CR become LF — the HTML
///   input-stream preprocessing step), so a CRLF build hashes like an LF one;
/// * tags are matched case-insensitively, and `</script` may be followed by
///   whitespace before its `>`;
/// * a script with a `src` attribute is external and needs no hash, while one
///   with `data-src` is still inline.
///
/// And refusals, because a WRONG hash is the dangerous direction — it fails
/// closed as a blank page while the boot log reports success. Anything this
/// small parser cannot be sure a browser reads the same way is an error
/// (CRYPTARCH-138, each case checked against Chrome by the re-audit):
/// * a `<script` anywhere that is not a script element — inside a comment, or
///   inside another script's text;
/// * a quote in a script tag's attributes (a quoted `>` or `src=` would be
///   misread) — SvelteKit's shell has no attributes on its script at all;
/// * an end tag that is not one: `</scripts`, `</script-x` are text to a
///   browser;
/// * a NUL byte, which browsers replace before hashing;
/// * `<svg` or `<math`, inside which scripts are parsed as foreign content.
///
/// A real HTML5 tokenizer would replace all of this; the refusals keep a
/// hand-rolled one honest until then.
fn script_hashes(html: &str) -> Result<Vec<String>, String> {
    let doc = html.replace("\r\n", "\n").replace('\r', "\n");
    let lower = doc.to_ascii_lowercase(); // same byte offsets as `doc`
    if lower.contains('\0') {
        return Err("the shell contains a NUL byte".into());
    }
    if lower.contains("<svg") || lower.contains("<math") {
        return Err("the shell contains <svg or <math (foreign content)".into());
    }
    let mut cpos = 0;
    while let Some(c) = lower[cpos..].find("<!--") {
        let start = cpos + c;
        let end = lower[start..].find("-->").map_or(lower.len(), |e| start + e);
        if lower[start..end].contains("<script") {
            return Err("a <script appears inside a comment".into());
        }
        cpos = end.max(start + 4);
    }
    let mut hashes = Vec::new();
    let mut elements = 0;
    let mut pos = 0;
    while let Some(found) = lower[pos..].find("<script") {
        let open = pos + found;
        let tag_len = lower[open..].find('>').ok_or("a <script tag is never closed")?;
        let tag = &lower[open + "<script".len()..open + tag_len];
        if tag.contains(['"', '\'']) {
            return Err("a <script tag has quoted attributes, which this parser does not read".into());
        }
        let body_start = open + tag_len + 1;
        let body_len = lower[body_start..].find("</script").ok_or("a <script> has no </script>")?;
        let after = lower[body_start + body_len + "</script".len()..].chars().next();
        if !after.is_some_and(|c| c == '>' || c == '/' || c.is_ascii_whitespace()) {
            return Err("a script contains </script followed by something other than an end tag".into());
        }
        let body = &doc[body_start..body_start + body_len];
        let external = tag
            .split(|c: char| c.is_ascii_whitespace())
            .any(|attr| attr == "src" || attr.starts_with("src="));
        if !external {
            let digest = Sha256::digest(body.as_bytes());
            hashes.push(format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(digest)));
        }
        elements += 1;
        let close = body_start + body_len;
        pos = close + lower[close..].find('>').ok_or("a </script is never closed")? + 1;
    }
    let mentions = lower.matches("<script").count();
    if mentions != elements {
        return Err(format!(
            "the shell mentions <script {mentions} times but has {elements} script elements — \
             cannot be sure which bytes a browser would hash"
        ));
    }
    Ok(hashes)
}

#[cfg(test)]
mod tests {
    use super::script_hashes;

    /// What Chrome reported it required, for `console.log("x");` on its own
    /// line inside a script — measured, not derived (CRYPTARCH-138). The same
    /// value for LF, CRLF and uppercase tags, which is the point.
    const CHROME: &str = "sha256-mMw+3s7YinkV7+SIeua/KVai7sPWvatCim7PoMxbLL0=";

    #[test]
    fn hashes_match_what_chrome_requires() {
        for doc in [
            "<body><script>\n\tconsole.log(\"x\");\n</script></body>",
            "<body><script>\r\n\tconsole.log(\"x\");\r\n</script></body>",
            "<body><SCRIPT>\n\tconsole.log(\"x\");\n</SCRIPT ></body>",
        ] {
            assert_eq!(script_hashes(doc).unwrap(), vec![CHROME.to_string()], "{doc:?}");
        }
    }

    #[test]
    fn external_scripts_need_no_hash_but_data_src_is_inline() {
        let doc = "<script src=/a.js></script><script data-src=x>\n\tconsole.log(\"x\");\n</script>";
        assert_eq!(script_hashes(doc).unwrap(), vec![CHROME.to_string()], "one inline, one external");
    }

    /// Each of these made the old parser return a WRONG hash, or drop one,
    /// while Chrome required something else (CRYPTARCH-138 re-audit).
    #[test]
    fn shapes_a_browser_reads_differently_are_refused() {
        for doc in [
            "<script data-x=\"a>b\">1</script>",
            "<script data-x='a>b'>1</script>",
            "<script data-n=\"a src=b\">1</script>",
            "<script>let s = '</scripts>';</script>",
            "<script>a</script-x>b</script>",
            "<script>a\0b</script>",
            "<svg><script>1</script></svg>",
            "<math><script>1</script></math>",
            "<!-- <script>old()</script> --><script>1</script>",
        ] {
            assert!(script_hashes(doc).is_err(), "must refuse: {doc:?}");
        }
        // Premise: an ordinary comment beside a script is fine — the shell has
        // two (app.html), and refusing all comments would refuse every build.
        assert_eq!(script_hashes("<!-- note --><script>1</script>").unwrap().len(), 1);
    }

    #[test]
    fn an_uncertain_document_is_refused_not_guessed() {
        assert!(script_hashes("<!-- <script --><script>1</script>").is_err());
        assert!(script_hashes("<script>let s = \"<script>\";</script>").is_err());
        assert!(script_hashes("<script>never closed").is_err());
    }
}
