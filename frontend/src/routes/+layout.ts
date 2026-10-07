// A single-page app: nothing is rendered on a server and nothing is
// prerendered. The Rust binary serves one shell (200.html) for every route.
export const ssr = false;
export const prerender = false;
