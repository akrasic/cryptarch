//! Self-service profile (CRYPTARCH-16): change own password, see own
//! sessions, sign out everywhere else. Owner-only by construction — every
//! query is scoped to the CurrentUser's id, and the password change demands
//! the current password even with a live session (a walked-up-to-an-open-
//! laptop attacker must not be able to rotate the password quietly).

use serde::Deserialize;

use crate::auth::{self};
use crate::provision::audit;
use crate::web::AppState;

pub const MIN_PASSWORD_LEN: usize = 8;

#[derive(Deserialize)]
pub struct PasswordInput {
    current_password: String,
    new_password: String,
    confirm_password: String,
}

/// Why a password change was refused. Nothing changed in any of them.
#[derive(Debug)]
pub enum PasswordError {
    Mismatch,
    TooShort,
    TooLong,
    /// The current password was wrong. Audited: a stolen-cookie attacker gets
    /// Argon2-speed guesses here, and silence would hide the probing.
    WrongCurrent,
    /// Too many wrong guesses for this account — counted with login's, so
    /// neither door is a way around the other (S5 audit P2).
    Throttled,
    /// The password, the account or this session changed while the request
    /// was being checked — an admin reset, a suspension. Nothing changed here.
    ChangedElsewhere,
    Internal,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PasswordError::Mismatch => "New passwords don't match.",
            PasswordError::TooShort => "New password must be at least 8 characters.",
            PasswordError::TooLong => "New password is too long.",
            PasswordError::WrongCurrent => "Current password is wrong.",
            PasswordError::Throttled => "Too many failed attempts — wait a few minutes and try again.",
            PasswordError::ChangedElsewhere => {
                "Your password or this session changed while this was being checked — nothing was \
                 changed here. Sign in again."
            }
            PasswordError::Internal => "Something went wrong — your password was not changed.",
        })
    }
}

/// What a change did.
pub struct PasswordChanged {
    /// The acting session's new token; every old one, its own included, is gone.
    pub token: String,
    pub other_sessions_signed_out: u64,
}

/// Change the signed-in user's own password.
/// The current password is demanded even with a live session (a walked-up-to
/// open laptop must not rotate it quietly), and the change is whole or not at
/// all — see `SessionStore::change_password_rotating`.
pub async fn change_password_for(
    state: &AppState,
    session: &crate::auth::Session,
    current_token: &str,
    input: PasswordInput,
) -> Result<PasswordChanged, PasswordError> {
    if input.new_password != input.confirm_password {
        return Err(PasswordError::Mismatch);
    }
    if input.new_password.len() < MIN_PASSWORD_LEN {
        return Err(PasswordError::TooShort);
    }
    // A validation message, not the internal error the hasher's own refusal
    // would surface as (CRYPTARCH-128).
    if input.new_password.len() > auth::MAX_PASSWORD_LEN {
        return Err(PasswordError::TooLong);
    }
    let stored: Option<String> = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let Some(stored) = stored else { return Err(PasswordError::Internal) };
    // The login throttle, keyed the same way: a guess here and a guess at the
    // login form spend one budget.
    let Some(_attempt) = state.login_throttle.begin(&session.username) else {
        return Err(PasswordError::Throttled);
    };
    // On the blocking pool for the reason given at the login site
    // (CRYPTARCH-115): this path hands a stolen-cookie attacker Argon2-speed
    // guesses, so it is a second place an attacker chooses how much CPU to spend.
    if !auth::verify_account_password(input.current_password, stored.clone()).await {
        state.login_throttle.record_failure(&session.username);
        audit(&state.db, &session.actor(), "change_password_failed", Some(&session.username), None).await;
        return Err(PasswordError::WrongCurrent);
    }
    state.login_throttle.clear(&session.username);
    let new_hash = auth::hash_password_capped(input.new_password).await.map_err(|e| {
        tracing::error!("hashing new password for {}: {e}", session.username);
        PasswordError::Internal
    })?;
    // The rotated session keeps this one's lineage: whoever set the password
    // it signed in with may be who just changed it (CRYPTARCH-146).
    let (token, other_sessions_signed_out) = state
        .sessions
        .change_password_rotating(
            session.user_id,
            &stored,
            &new_hash,
            current_token,
            session.began_on_password_set_by.as_deref(),
        )
        .await
        .map_err(|e| match e {
            auth::RotateError::Stale => PasswordError::ChangedElsewhere,
            auth::RotateError::Db(e) => {
                tracing::error!("changing password for {}: {e}", session.username);
                PasswordError::Internal
            }
        })?;
    audit(&state.db, &session.actor(), "change_password", Some(&session.username),
          Some(&format!("other_sessions_revoked={other_sessions_signed_out}, current rotated")))
        .await;
    Ok(PasswordChanged { token, other_sessions_signed_out })
}

/// "Sign out everywhere else". `Err` when the revocation failed — never a
/// count of zero that reads like "there were none".
pub async fn revoke_others_for(
    state: &AppState,
    session: &crate::auth::Session,
    current_token: &str,
) -> Result<u64, ()> {
    let revoked = state.sessions.remove_others_checked(session.user_id, current_token).await.map_err(|e| {
        tracing::error!("revoking other sessions for {}: {e}", session.username);
    })?;
    audit(&state.db, &session.actor(), "revoke_sessions", Some(&session.username),
          Some(&format!("revoked={revoked}")))
        .await;
    Ok(revoked)
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
