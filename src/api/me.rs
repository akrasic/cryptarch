//! The signed-in user's own account: their sessions, changing their password,
//! signing out everywhere else (CRYPTARCH-133).
//!
//! All three take `ApiSignedIn`, not `ApiUser`: they are exactly what a
//! session with an admin-set password is allowed to do (CRYPTARCH-146), and
//! the change is how it lifts its own gate. Everything is scoped to the
//! caller's id; nothing here can name another user.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Serialize;

use super::{ApiError, ApiJson, ApiResult, ApiSignedIn};
use crate::profile::{self, PasswordError, PasswordInput};
use crate::web::AppState;

#[derive(Serialize)]
pub struct MySession {
    created_at: chrono::DateTime<chrono::Utc>,
    last_seen: chrono::DateTime<chrono::Utc>,
    /// The session this request came from.
    current: bool,
}

#[derive(Serialize)]
pub struct Sessions {
    sessions: Vec<MySession>,
}

fn current_token(state: &AppState, jar: &CookieJar) -> ApiResult<String> {
    crate::web::session_token(state, jar).ok_or_else(ApiError::unauthenticated)
}

/// `GET /api/v1/me/sessions` — the caller's live sessions, this one first.
pub async fn sessions(
    State(state): State<AppState>,
    ApiSignedIn(session): ApiSignedIn,
    jar: CookieJar,
) -> ApiResult<Json<Sessions>> {
    let token = current_token(&state, &jar)?;
    let sessions = state
        .sessions
        .list_for_user(session.user_id, &token)
        .await
        .into_iter()
        .map(|s| MySession { created_at: s.created_at, last_seen: s.last_seen, current: s.is_current })
        .collect();
    Ok(Json(Sessions { sessions }))
}

#[derive(Serialize)]
pub struct Changed {
    other_sessions_signed_out: u64,
}

/// `POST /api/v1/me/password` — the current password, and the new one twice.
/// On success the acting session is re-issued (a new cookie) and every other
/// one is gone; on failure nothing changed.
pub async fn change_password(
    State(state): State<AppState>,
    ApiSignedIn(session): ApiSignedIn,
    jar: CookieJar,
    ApiJson(input): ApiJson<PasswordInput>,
) -> ApiResult<(CookieJar, Json<Changed>)> {
    let token = current_token(&state, &jar)?;
    let done = profile::change_password_for(&state, &session, &token, input).await.map_err(|e| {
        let message = e.to_string();
        match e {
            PasswordError::Mismatch => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "mismatch", message),
            PasswordError::TooShort => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "too_short", message),
            PasswordError::TooLong => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "too_long", message),
            PasswordError::WrongCurrent => ApiError::new(StatusCode::FORBIDDEN, "wrong_password", message),
            PasswordError::Throttled => ApiError::new(StatusCode::TOO_MANY_REQUESTS, "throttled", message),
            PasswordError::ChangedElsewhere => ApiError::new(StatusCode::CONFLICT, "changed_elsewhere", message),
            PasswordError::Internal => {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "password_change_failed", message)
            }
        }
    })?;
    Ok((
        // A login cookie, by construction: the same function login uses.
        jar.add(crate::web::session_cookie(&state, done.token)),
        Json(Changed { other_sessions_signed_out: done.other_sessions_signed_out }),
    ))
}

#[derive(Serialize)]
pub struct SignedOut {
    signed_out: u64,
}

/// `POST /api/v1/me/sessions/revoke-others` — every session but this one.
pub async fn revoke_others(
    State(state): State<AppState>,
    ApiSignedIn(session): ApiSignedIn,
    jar: CookieJar,
) -> ApiResult<Json<SignedOut>> {
    let token = current_token(&state, &jar)?;
    let signed_out = profile::revoke_others_for(&state, &session, &token).await.map_err(|()| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "revoke_failed",
            "Signing out the other sessions failed — they may still be live.",
        )
    })?;
    Ok(Json(SignedOut { signed_out }))
}
