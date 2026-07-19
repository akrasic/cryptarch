//! Self-service profile (CRYPTARCH-16): change own password, see own
//! sessions, sign out everywhere else. Owner-only by construction — every
//! query is scoped to the CurrentUser's id, and the password change demands
//! the current password even with a live session (a walked-up-to-an-open-
//! laptop attacker must not be able to rotate the password quietly).

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Form;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use maud::html;
use serde::Deserialize;

use crate::auth::{self, CurrentUser, SESSION_COOKIE};
use crate::provision::audit;
use crate::web::{shell, AppState};

const MIN_PASSWORD_LEN: usize = 8;

pub async fn page(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    jar: CookieJar,
) -> Response {
    render(&state, &session, &jar, None, None).await
}

#[derive(Deserialize)]
pub struct PasswordInput {
    current_password: String,
    new_password: String,
    confirm_password: String,
}

pub async fn change_password(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    jar: CookieJar,
    Form(input): Form<PasswordInput>,
) -> Response {
    if input.new_password != input.confirm_password {
        return render(&state, &session, &jar, Some("New passwords don't match."), None).await;
    }
    if input.new_password.len() < MIN_PASSWORD_LEN {
        return render(&state, &session, &jar,
            Some("New password must be at least 8 characters."), None).await;
    }
    let stored: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(session.user_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let Some(stored) = stored else {
        return crate::web::error_page(&session, axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong", "Loading your account failed — your password was not changed.");
    };
    if !auth::verify_password(&input.current_password, &stored) {
        // Failed attempts are audit-worthy: a stolen-cookie attacker gets
        // Argon2-speed guesses here, and silence would hide the probing.
        audit(&state.db, &session.username, "change_password_failed",
              Some(&session.username), None)
            .await;
        return render(&state, &session, &jar, Some("Current password is wrong."), None).await;
    }
    let new_hash = match auth::hash_password(&input.new_password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("hashing new password for {}: {e}", session.username);
            return crate::web::error_page(&session, axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong", "Hashing the new password failed — your password was not changed.");
        }
    };
    if let Err(e) = sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&new_hash)
        .bind(session.user_id)
        .execute(&state.db)
        .await
    {
        tracing::error!("updating password for {}: {e}", session.username);
        return crate::web::error_page(&session, axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong", "Saving the new password failed — your old password still works.");
    }

    // A password change revokes every OTHER session AND rotates the current
    // token — a cookie stolen before the change must not survive it.
    let revoked = match jar.get(SESSION_COOKIE) {
        Some(c) => {
            let n = state.sessions.remove_others(session.user_id, c.value()).await;
            state.sessions.remove(c.value()).await;
            n
        }
        None => 0,
    };
    let new_token = match state.sessions.insert(session.user_id).await {
        Ok(t) => t,
        Err(e) => {
            // Password IS changed; the user just needs to log in again.
            tracing::error!("rotating session after password change: {e}");
            return axum::response::Redirect::to("/login").into_response();
        }
    };
    let jar = jar.add(
        Cookie::build((SESSION_COOKIE, new_token))
            .path("/")
            .http_only(true)
            .secure(state.secure_cookies)
            .same_site(SameSite::Lax)
            .build(),
    );
    audit(&state.db, &session.username, "change_password", Some(&session.username),
          Some(&format!("other_sessions_revoked={revoked}, current rotated")))
        .await;
    let page = render(&state, &session, &jar, None,
           Some("Password changed. All other sessions were signed out.")).await;
    (jar, page).into_response()
}

pub async fn revoke_others(
    State(state): State<AppState>,
    CurrentUser(session): CurrentUser,
    jar: CookieJar,
) -> Response {
    let revoked = match jar.get(SESSION_COOKIE) {
        Some(c) => state.sessions.remove_others(session.user_id, c.value()).await,
        None => 0,
    };
    audit(&state.db, &session.username, "revoke_sessions", Some(&session.username),
          Some(&format!("revoked={revoked}")))
        .await;
    render(&state, &session, &jar, None,
           Some(&format!("Signed out {revoked} other session(s)."))).await
}

async fn render(
    state: &AppState,
    session: &crate::auth::Session,
    jar: &CookieJar,
    error: Option<&str>,
    notice: Option<&str>,
) -> Response {
    let sessions = match jar.get(SESSION_COOKIE) {
        Some(c) => state.sessions.list_for_user(session.user_id, c.value()).await,
        None => Vec::new(),
    };
    shell(
        "Profile",
        session,
        html! {
            h1 { "Profile" }
            @if let Some(msg) = error { p.error role="alert" { (msg) } }
            @if let Some(msg) = notice { p.notice role="status" { (msg) } }
            dl.creds {
                dt { "Username" } dd { code { (session.username) } }
                dt { "Role" } dd { @if session.is_admin { "admin" } @else { "user" } }
            }
            h2 { "Change password" }
            form method="post" action="/profile/password" .scard {
                (crate::web::srow("Current password",
                    "Required even while signed in — proof it's really you at the keyboard.",
                    html! { input type="password" name="current_password" autocomplete="current-password" required; }))
                (crate::web::srow("New password",
                    "At least 8 characters.",
                    html! { input type="password" name="new_password" autocomplete="new-password" required; }))
                (crate::web::srow("Confirm new password",
                    "Typed twice so a typo can't lock you out.",
                    html! { input type="password" name="confirm_password" autocomplete="new-password" required; }))
                (crate::web::sfoot(Some("Signs out every other session automatically."), "Change password"))
            }
            h2 { "Active sessions" }
            div.table-scroll {
                table.dbs {
                    thead { tr { th { "Started" } th { "Last seen" } th { "" } } }
                    tbody {
                        @for s in &sessions {
                            tr {
                                td.tnum { (s.created_at.format("%Y-%m-%d %H:%M UTC").to_string()) }
                                td.tnum { (s.last_seen.format("%Y-%m-%d %H:%M UTC").to_string()) }
                                td { @if s.is_current { span.st.st-active { span.dot {} "this session" } } }
                            }
                        }
                    }
                }
            }
            @if sessions.len() > 1 {
                form method="post" action="/profile/sessions/revoke-others" .inline {
                    button type="submit" { "Sign out everywhere else" }
                }
            }
        },
    )
    .into_response()
}

#[cfg(test)]
mod tests {
    #[test]
    fn username_policy() {
        use crate::auth::valid_username;
        for ok in ["alice", "bob_2", "dev-ops"] {
            assert!(valid_username(ok), "{ok}");
        }
        for bad in ["ab", "Alice", "1abc", "a b", "naïve", &"x".repeat(33)] {
            assert!(!valid_username(bad), "{bad:?}");
        }
    }
}
