//! Make sure the embedded frontend directory exists (CRYPTARCH-129).
//!
//! `rust-embed` needs `frontend/build` at compile time. A real build comes from
//! `npm run build` in `frontend/` (the Dockerfile's node stage, and CI). Without
//! one — a fresh clone, a backend-only change — this writes a small placeholder
//! so `cargo build` and `cargo test` work with no Node installed.
//!
//! The placeholder is shaped like a real build ON PURPOSE: an inline bootstrap
//! script and a hashed asset under `_app/immutable/`. The serving tests assert
//! against those, so they exercise the real machinery either way rather than
//! passing vacuously against an empty directory.

use std::path::Path;

/// Present only in a placeholder build. `npm run build` replaces the whole
/// directory, so a real build never carries it. The binary checks for it too
/// (`web::spa::is_placeholder`) and says so at boot.
const SENTINEL: &str = ".cryptarch-placeholder";

fn main() {
    let build = Path::new("frontend/build");
    println!("cargo:rerun-if-changed=frontend/build");
    let placeholder = !build.join("200.html").exists() || build.join(SENTINEL).exists();
    // Loud in release, and keyed on the SENTINEL rather than on the directory
    // being missing (CRYPTARCH-138): a placeholder written by an earlier debug
    // build persists, and a release binary embedding it is a portal with no UI.
    // The Docker build always embeds a real one; this catches a hand-built one.
    if placeholder && std::env::var("PROFILE").as_deref() == Ok("release") {
        println!(
            "cargo:warning=embedding a PLACEHOLDER UI — frontend/build is not a real build. \
             Run `npm ci && npm run build` in frontend/ before a release build."
        );
    }
    if build.join("200.html").exists() {
        refuse_symlinks(build);
        return;
    }
    let immutable = build.join("_app/immutable/entry");
    std::fs::create_dir_all(&immutable).expect("creating the frontend placeholder");
    std::fs::write(
        build.join("200.html"),
        r#"<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8" />
		<title>Cryptarch</title>
		<link href="/_app/immutable/entry/placeholder.js" rel="modulepreload">
	</head>
	<body>
		<div class="sk-root">
			<script>
				import("/_app/immutable/entry/placeholder.js");
			</script>
			<p>The frontend has not been built. Run <code>npm ci &amp;&amp; npm run build</code> in <code>frontend/</code>.</p>
		</div>
	</body>
</html>
"#,
    )
    .expect("writing the frontend placeholder shell");
    std::fs::write(build.join(SENTINEL), "written by build.rs; deleted by npm run build\n")
        .expect("writing the placeholder sentinel");
    std::fs::write(build.join("robots.txt"), "User-agent: *\nDisallow: /\n")
        .expect("writing the placeholder robots.txt");
    std::fs::write(
        immutable.join("placeholder.js"),
        "console.warn('cryptarch: frontend placeholder — run npm run build in frontend/');\n",
    )
    .expect("writing the frontend placeholder asset");
}

/// rust-embed follows symlinks — at compile time in release, at request time in
/// debug — so a link inside the build would be served as if it were part of it
/// (CRYPTARCH-138). SvelteKit never emits one; finding one is an error.
fn refuse_symlinks(dir: &Path) {
    for entry in std::fs::read_dir(dir).expect("reading frontend/build") {
        let path = entry.expect("reading frontend/build").path();
        let meta = std::fs::symlink_metadata(&path).expect("reading frontend/build");
        if meta.file_type().is_symlink() {
            panic!("{} is a symlink — refusing to embed it (see build.rs)", path.display());
        }
        if meta.is_dir() {
            refuse_symlinks(&path);
        }
    }
}
