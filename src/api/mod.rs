//! The JSON API the SvelteKit SPA talks to (CRYPTARCH-130;
//! dec-cryptarch-sveltekit-architecture D4–D6), mounted at `/api/v1`.
//!
//! The only door since cutover (CRYPTARCH-137): the server-rendered UI it
//! replaced is gone, and the SPA is the whole interface. Handlers are thin;
//! the domain functions they call (`crate::web`, `admin`, `admin_servers`,
//! `backup`, `restore`, `profile`) hold the security properties, in one place.
//!
//! Three rules apply to every route, enforced here rather than per handler:
//!
//! * **Errors are JSON** — `{"error": {"code", "message"}}` — and an
//!   unauthenticated request is a 401, never a redirect. A fetch would follow a
//!   redirect to the login page and then try to read HTML as data.
//! * **Nothing is cacheable.** Every response is `Cache-Control: no-store`: the
//!   API carries account data and show-once credentials.
//! * **Mutations must be JSON.** Any method but GET/HEAD/OPTIONS needs
//!   `Content-Type: application/json`, or it is a 415 before a handler runs. A
//!   cross-site HTML form, or a "simple" cross-site fetch, cannot send that
//!   without a CORS preflight — which this server never grants. That is the
//!   second CSRF lock; the first is `web::origin_guard`, in front of all of it.
//! * **Only the app itself.** A browser marks every request with
//!   `Sec-Fetch-Site`; `same-site` and `cross-site` are refused on every method
//!   (CRYPTARCH-138). SameSite cookies are not a lock here: on a homelab,
//!   another port on the same host is "same-site", and its pages get the Lax
//!   cookie attached. Clients that send no such header are not browsers, and
//!   are not riding anyone's cookie.
//!
//! The session cookie is HttpOnly and SameSite=Lax. No token ever reaches
//! JavaScript.

use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, FromRequest, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};

use crate::auth::Session;

mod acl;
mod admin;
mod admin_backups;
mod admin_servers;
mod backups;
mod databases;
mod me;
mod restores;
use crate::web::{AppState, LoginFailure};

/// An API error: an HTTP status, a stable machine-readable `code` the SPA can
/// branch on, and a human-readable `message` it can show as-is.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }
    pub fn unauthenticated() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthenticated", "Sign in to continue.")
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "Something went wrong.")
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorDetail<'a>,
}

#[derive(Serialize)]
struct ErrorDetail<'a> {
    code: &'a str,
    message: &'a str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody { error: ErrorDetail { code: self.code, message: &self.message } };
        // no-store here as well as in `guard`: some errors are produced outside
        // the API router (web::origin_guard, the /api catch-all), and an error
        // must never be the thing a cache keeps.
        let mut resp = (self.status, Json(body)).into_response();
        resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }
}

/// `axum::Json`, with its rejections — malformed JSON, a wrong shape, an
/// oversized body — answered in the API's own error shape rather than as the
/// plain text axum produces (CRYPTARCH-138). Every API handler takes its body
/// through this.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(ApiJson(v)),
            Err(rej) => Err(ApiError::new(rej.status(), "bad_request", rej.body_text())),
        }
    }
}

/// `axum::extract::Path`, with its rejection — a segment that is not valid
/// UTF-8, say — answered in the API's error shape like every other failure.
pub struct ApiPath<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    T: serde::de::DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(v)) => Ok(ApiPath(v)),
            Err(rej) => Err(ApiError::new(rej.status(), "bad_path", rej.body_text())),
        }
    }
}

/// The largest request body the API accepts. Nothing it takes is anywhere near
/// this; the point is that a 2 MB login is refused before it is parsed.
const BODY_LIMIT: usize = 64 * 1024;

/// Answers any path under `/api` the API does not have — mounted by
/// `web::router` beside the versioned API, so `/api`, `/api/` and `/api/v2/...`
/// get the API's JSON 404 rather than the SPA shell.
pub async fn unknown_endpoint() -> ApiError {
    ApiError::not_found("No such API endpoint.")
}

pub type ApiResult<T> = Result<T, ApiError>;

/// Any signed-in session, including one whose admin-set password must be
/// replaced first (CRYPTARCH-146) — for `GET /session` (so the SPA can learn
/// that it must) and the three `/me` endpoints (where it does). Everything
/// else takes [`ApiUser`].
pub struct ApiSignedIn(pub Session);

impl FromRequestParts<AppState> for ApiSignedIn {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = crate::web::session_token(state, &jar);
        match token {
            Some(t) => state.sessions.get(&t).await.map(ApiSignedIn).ok_or_else(ApiError::unauthenticated),
            None => Err(ApiError::unauthenticated()),
        }
    }
}

/// The signed-in user, for API routes: 401 without a session, and 403
/// `password_change_required` while the account's password is one an admin
/// set (CRYPTARCH-146).
pub struct ApiUser(pub Session);

impl FromRequestParts<AppState> for ApiUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let ApiSignedIn(session) = ApiSignedIn::from_request_parts(parts, state).await?;
        if session.must_change_password {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "password_change_required",
                "Your password was set by an administrator. Set your own before doing anything else.",
            ));
        }
        Ok(ApiUser(session))
    }
}

/// A signed-in admin. 401 when signed out, 403 when signed in without admin.
pub struct ApiAdmin(pub Session);

impl FromRequestParts<AppState> for ApiAdmin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let ApiUser(session) = ApiUser::from_request_parts(parts, state).await?;
        if session.is_admin {
            Ok(ApiAdmin(session))
        } else {
            Err(ApiError::forbidden("This needs admin rights, which your account doesn't have."))
        }
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/session", get(session_get).post(session_create).delete(session_delete))
        .route("/databases", get(databases::list).post(databases::create))
        .route("/databases/{name}", get(databases::detail))
        .route("/databases/{name}/reset", axum::routing::post(databases::reset))
        .route("/databases/{name}/delete", axum::routing::post(databases::delete))
        .route("/databases/{name}/backups", get(backups::list).post(backups::start))
        .route("/databases/{name}/restores", get(restores::list).post(restores::start))
        .route("/databases/{name}/restores/{id}", get(restores::job))
        .route("/databases/{name}/contents", get(databases::contents))
        .route("/databases/{name}/acl", get(acl::list).post(acl::add))
        .route("/databases/{name}/acl/{entry_id}", axum::routing::delete(acl::remove))
        .route("/servers", get(databases::servers))
        .route("/admin/overview", get(admin::overview))
        .route("/admin/users", get(admin::users).post(admin::create_user))
        .route("/admin/users/{id}", get(admin::user))
        .route("/admin/users/{id}/reset-password", axum::routing::post(admin::reset_password))
        .route("/admin/users/{id}/quota", axum::routing::post(admin::set_quota))
        .route("/admin/users/{id}/active", axum::routing::post(admin::set_active))
        .route("/admin/databases", get(admin::databases))
        .route("/admin/backups", get(admin_backups::jobs))
        .route("/admin/backups/left-behind", get(admin_backups::left_behind))
        .route("/admin/backups/unreferenced", get(admin_backups::unreferenced))
        .route("/admin/backups/{id}/purge", axum::routing::post(admin_backups::purge))
        .route("/admin/backups/purge-file", axum::routing::post(admin_backups::purge_file))
        .route("/admin/servers", get(admin_servers::list).post(admin_servers::create))
        .route("/admin/servers/{id}", get(admin_servers::detail))
        .route("/admin/servers/{id}/overview", get(admin_servers::overview))
        .route("/admin/servers/{id}/edge", get(admin_servers::edge))
        .route("/admin/servers/{id}/active", axum::routing::post(admin_servers::set_active))
        .route("/admin/servers/{id}/test", axum::routing::post(admin_servers::test))
        .route("/admin/servers/{id}/init", axum::routing::post(admin_servers::init))
        .route("/admin/servers/{id}/credentials", axum::routing::post(admin_servers::credentials))
        .route("/admin/servers/{id}/config", get(admin_servers::config))
        .route("/admin/servers/{id}/settings/address", axum::routing::post(admin_servers::set_address))
        .route("/admin/servers/{id}/settings/pooling", axum::routing::post(admin_servers::set_pooling))
        .route("/admin/servers/{id}/settings/edge", axum::routing::post(admin_servers::set_edge))
        .route("/admin/servers/{id}/sources", axum::routing::post(admin_servers::add_source))
        .route("/admin/servers/{id}/sources/{source_id}", axum::routing::delete(admin_servers::remove_source))
        .route("/admin/servers/{id}/listeners", axum::routing::post(admin_servers::add_listener))
        .route("/admin/servers/{id}/listeners/{listener_id}", axum::routing::delete(admin_servers::remove_listener))
        .route("/admin/servers/{id}/databases/{db_id}/pool", axum::routing::post(admin_servers::set_db_pool))
        .route("/admin/servers/{id}/sync", axum::routing::post(admin_servers::sync))
        .route("/admin/audit", get(admin::audit))
        .route("/admin/logins", get(admin::logins))
        .route("/admin/logins/{name}/retry-delete", axum::routing::post(admin::retry_delete))
        .route("/me/sessions", get(me::sessions))
        .route("/me/sessions/revoke-others", axum::routing::post(me::revoke_others))
        .route("/me/password", axum::routing::post(me::change_password))
        .fallback(unknown_endpoint)
        .method_not_allowed_fallback(|| async {
            ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", "That method is not allowed here.")
        })
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(axum::middleware::from_fn(guard))
}

/// The per-request rules every API route shares; see the module docs.
async fn guard(req: Request, next: Next) -> Response {
    // An allowlist over EVERY value of EVERY such header: anything but
    // same-origin or none (direct navigation) is foreign, including values a
    // browser would never send.
    let foreign = req.headers().get_all("sec-fetch-site").iter().any(|v| {
        v.to_str().map_or(true, |v| {
            v.split(',').any(|part| {
                let part = part.trim();
                !(part.eq_ignore_ascii_case("same-origin") || part.eq_ignore_ascii_case("none"))
            })
        })
    });
    if foreign {
        return ApiError::new(StatusCode::FORBIDDEN, "cross_site", "Cross-site request refused.")
            .into_response();
    }
    let mutating = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let is_json = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"));
    let mut resp = if mutating && !is_json {
        ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "json_required",
            "Requests that change anything must be sent as JSON.",
        )
        .into_response()
    } else {
        next.run(req).await
    };
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Who is signed in.
#[derive(Serialize)]
pub struct Me {
    pub username: String,
    pub is_admin: bool,
    /// Every other endpoint refuses until the password is replaced.
    pub must_change_password: bool,
}

impl From<&Session> for Me {
    fn from(s: &Session) -> Self {
        Me { username: s.username.clone(), is_admin: s.is_admin, must_change_password: s.must_change_password }
    }
}

async fn session_get(ApiSignedIn(session): ApiSignedIn) -> Json<Me> {
    Json(Me::from(&session))
}

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

async fn session_create(
    State(state): State<AppState>,
    jar: CookieJar,
    ApiJson(body): ApiJson<LoginBody>,
) -> ApiResult<(CookieJar, Json<Me>)> {
    let token = crate::web::authenticate(&state, &body.username, body.password)
        .await
        .map_err(|f| match f {
            LoginFailure::Throttled => ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "throttled",
                "Too many failed attempts — wait a few minutes and try again.",
            ),
            LoginFailure::Invalid => {
                ApiError::new(StatusCode::UNAUTHORIZED, "invalid_credentials", "Invalid credentials.")
            }
            LoginFailure::Internal => ApiError::internal(),
        })?;
    // Read back through the session store, so what this reports is exactly what
    // every later request will see — not a second opinion assembled here.
    let session = state.sessions.get(&token).await.ok_or_else(ApiError::internal)?;
    Ok((jar.add(crate::web::session_cookie(&state, token)), Json(Me::from(&session))))
}

async fn session_delete(State(state): State<AppState>, jar: CookieJar) -> ApiResult<(StatusCode, CookieJar)> {
    if let Some(token) = crate::web::session_token(&state, &jar) {
        // Refused, not reported as done, when the row could not be deleted:
        // the SPA only leaves the page once this succeeds.
        state.sessions.remove(&token).await.map_err(|_| ApiError::internal())?;
    }
    // Path "/" explicitly: without it the browser scopes the removal to the
    // request's directory, /api/v1, and the site-wide cookie survives.
    Ok((StatusCode::NO_CONTENT, jar.remove(crate::web::session_cookie_removal(&state))))
}
