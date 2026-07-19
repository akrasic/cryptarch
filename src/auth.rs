//! Authentication: password hashing, session store, the current-user extractor,
//! and first-run admin bootstrap.
//!
//! Local accounts with Argon2-hashed passwords; sessions live in the metadata
//! DB (CRYPTARCH-15) keyed by the SHA-256 of an opaque cookie token — they
//! survive restarts, die instantly when a user is disabled (lookup JOINs
//! users.is_active), and expire on a sliding 7-day window. LDAP slots in as
//! an alternate credential check without touching sessions.

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use rand::Rng;
use uuid::Uuid;

use crate::web::AppState;

/// Cookie that carries the opaque session token.
pub const SESSION_COOKIE: &str = "cryptarch_session";

/// Hash a plaintext password with Argon2 (default params).
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))?
        .to_string();
    Ok(hash)
}

/// Verify a plaintext password against a stored Argon2 hash. Never panics;
/// a malformed stored hash is treated as a non-match.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// The authenticated identity attached to a session.
#[derive(Clone, Debug)]
pub struct Session {
    pub user_id: Uuid,
    pub username: String,
    pub is_admin: bool,
}

/// Session lifetime: sliding 7-day window, but never past 30 days from
/// creation — a stolen cookie kept warm by a bot must still die.
/// (When a password-change or role-demote route lands, it must also
/// DELETE FROM sessions for that user.)
const SESSION_TTL_DAYS: i64 = 7;
const SESSION_MAX_DAYS: i64 = 30;
const TOUCH_INTERVAL_MINUTES: i64 = 10;

/// DB-backed session store over the metadata pool. Only the token's SHA-256
/// is persisted; the raw token exists in the cookie and nowhere else.
#[derive(Clone)]
pub struct SessionStore {
    db: sqlx::PgPool,
}

impl SessionStore {
    pub fn new(db: sqlx::PgPool) -> Self {
        Self { db }
    }

    /// Create a session, returning its opaque token. Opportunistically sweeps
    /// expired rows — logins are rare enough to carry the cleanup.
    pub async fn insert(&self, user_id: Uuid) -> anyhow::Result<String> {
        let _ = sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
            .execute(&self.db)
            .await;
        let token = new_token();
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at) \
             VALUES ($1, $2, now() + make_interval(days => $3))",
        )
        .bind(token_hash(&token))
        .bind(user_id)
        .bind(SESSION_TTL_DAYS as i32)
        .execute(&self.db)
        .await?;
        Ok(token)
    }

    /// Resolve a token to a live session. The JOIN enforces expiry AND user
    /// active status — disabling a user kills their sessions immediately.
    /// Refreshes the sliding window at most every TOUCH_INTERVAL_MINUTES.
    pub async fn get(&self, token: &str) -> Option<Session> {
        let hash = token_hash(token);
        let row: Option<(Uuid, String, bool, bool)> = sqlx::query_as(
            "SELECT s.user_id, u.username, u.is_admin, \
                    s.last_seen < now() - make_interval(mins => $2) AS stale \
             FROM sessions s JOIN users u ON u.id = s.user_id \
             WHERE s.token_hash = $1 AND s.expires_at > now() AND u.is_active \
               AND s.created_at > now() - make_interval(days => $3)",
        )
        .bind(&hash)
        .bind(TOUCH_INTERVAL_MINUTES as i32)
        .bind(SESSION_MAX_DAYS as i32)
        .fetch_optional(&self.db)
        .await
        // Fail closed on DB errors, but never silently — an outage must not
        // be indistinguishable from token churn in the logs.
        .inspect_err(|e| tracing::error!("session lookup failed: {e}"))
        .ok()
        .flatten();
        let (user_id, username, is_admin, stale) = row?;
        if stale {
            if let Err(e) = sqlx::query(
                "UPDATE sessions SET last_seen = now(), \
                 expires_at = LEAST(now() + make_interval(days => $2), \
                                    created_at + make_interval(days => $3)) \
                 WHERE token_hash = $1",
            )
            .bind(&hash)
            .bind(SESSION_TTL_DAYS as i32)
            .bind(SESSION_MAX_DAYS as i32)
            .execute(&self.db)
            .await
            {
                tracing::warn!("session refresh failed: {e}");
            }
        }
        Some(Session { user_id, username, is_admin })
    }

    pub async fn remove(&self, token: &str) {
        if let Err(e) = sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(token_hash(token))
            .execute(&self.db)
            .await
        {
            // The cookie is cleared client-side regardless, but the DB row
            // would stay live — that's worth an operator's attention.
            tracing::error!("logout session delete failed: {e}");
        }
    }
}

/// One of a user's sessions, for the profile page. No token material.
#[derive(sqlx::FromRow)]
pub struct SessionListRow {
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub is_current: bool,
}

impl SessionStore {
    /// The user's live sessions, current-first.
    pub async fn list_for_user(&self, user_id: Uuid, current_token: &str) -> Vec<SessionListRow> {
        sqlx::query_as::<_, SessionListRow>(
            "SELECT created_at, last_seen, token_hash = $2 AS is_current \
             FROM sessions WHERE user_id = $1 AND expires_at > now() \
             ORDER BY is_current DESC, last_seen DESC",
        )
        .bind(user_id)
        .bind(token_hash(current_token))
        .fetch_all(&self.db)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("listing sessions for {user_id}: {e}");
            Vec::new()
        })
    }

    /// Kill every session of the user except the current one — the hook for
    /// password change and "sign out everywhere else".
    pub async fn remove_others(&self, user_id: Uuid, current_token: &str) -> u64 {
        match sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
            .bind(user_id)
            .bind(token_hash(current_token))
            .execute(&self.db)
            .await
        {
            Ok(r) => r.rows_affected(),
            Err(e) => {
                tracing::error!("revoking other sessions for {user_id}: {e}");
                0
            }
        }
    }

    /// Kill ALL sessions of a user (admin password reset).
    pub async fn remove_all_for_user(&self, user_id: Uuid) {
        if let Err(e) = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.db)
            .await
        {
            tracing::error!("revoking sessions for {user_id}: {e}");
        }
    }
}

/// Username policy: lowercase letter first, then lowercase/digits/_/-, 3-32.
pub fn valid_username(s: &str) -> bool {
    s.len() >= 3
        && s.len() <= 32
        && s.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// SHA-256 hex of a raw token — the only form that touches the database.
fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// 48-char opaque session token from a CSPRNG.
fn new_token() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..48)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

/// Extractor that yields the current [`Session`] or rejects with a redirect to
/// the login page. Use it as a handler argument to require authentication.
pub struct CurrentUser(pub Session);

#[async_trait]
impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get(SESSION_COOKIE)
            .map(|c| c.value().to_owned())
            .ok_or_else(|| Redirect::to("/login").into_response())?;

        state
            .sessions
            .get(&token)
            .await
            .map(CurrentUser)
            .ok_or_else(|| Redirect::to("/login").into_response())
    }
}

/// Extractor variant that requires admin. Rejects non-admins with 403.
pub struct AdminUser(pub Session);

#[async_trait]
impl FromRequestParts<AppState> for AdminUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let CurrentUser(session) = CurrentUser::from_request_parts(parts, state).await?;
        if session.is_admin {
            Ok(AdminUser(session))
        } else {
            Err(crate::web::error_page(
                &session,
                StatusCode::FORBIDDEN,
                "Admins only",
                "This page needs admin rights, which your account doesn't have.",
            ))
        }
    }
}

/// On first run (empty users table), create the bootstrap admin from config.
pub async fn bootstrap_admin(
    db: &sqlx::PgPool,
    username: &str,
    password: &str,
    default_quota: i32,
) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await?;
    if count > 0 {
        return Ok(());
    }
    let hash = hash_password(password)?;
    sqlx::query(
        "INSERT INTO users (username, password_hash, is_admin, db_quota) \
         VALUES ($1, $2, TRUE, $3)",
    )
    .bind(username)
    .bind(hash)
    .bind(default_quota)
    .execute(db)
    .await?;
    tracing::info!("bootstrapped admin user '{username}'");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_roundtrips() {
        let h = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &h));
        assert!(!verify_password("wrong password", &h));
    }

    #[test]
    fn malformed_hash_is_non_match() {
        assert!(!verify_password("anything", "not-a-real-hash"));
    }

    #[test]
    fn tokens_are_unique_and_long() {
        let a = new_token();
        let b = new_token();
        assert_eq!(a.len(), 48);
        assert_ne!(a, b);
    }
}
