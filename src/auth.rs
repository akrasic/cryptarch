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
use rand::RngExt;
use uuid::Uuid;


/// The session cookie's name when cookies are not Secure (dev, plain http).
pub const SESSION_COOKIE: &str = "cryptarch_session";

/// Its name when they are — the default (CRYPTARCH-150).
///
/// A browser accepts a `__Host-` cookie only from a secure origin, only
/// without a Domain and only with `Path=/`. So it cannot be planted by a
/// plain-http service on the same host (which can otherwise set a fresh,
/// non-Secure cookie of the plain name whenever the victim has none, and the
/// browser sends that to https too), nor by a sibling subdomain. It does NOT
/// stop another https service on the same host: cookies do not separate by
/// port. Only this name is read in secure mode; reading the plain one as well
/// would let exactly the planted cookie back in.
pub const SECURE_SESSION_COOKIE: &str = "__Host-cryptarch_session";

/// The session cookie's name for a deployment.
pub fn session_cookie_name(secure: bool) -> &'static str {
    if secure { SECURE_SESSION_COOKIE } else { SESSION_COOKIE }
}

/// Hash a plaintext password with Argon2 (default params).
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))?
        .to_string();
    Ok(hash)
}

/// A fixed, valid Argon2 hash computed once with our own params. The login
/// path verifies against this when the username is unknown or suspended, so a
/// missing account costs the same Argon2 work as a real one — response latency
/// can't be used to enumerate usernames. No real password produces it.
pub static DUMMY_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    hash_password("cryptarch-login-timing-equalizer").expect("computing dummy login hash")
});

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

/// How many Argon2 operations may run at once on the LOGIN path (CRYPTARCH-124).
///
/// Each one holds ~19 MiB. Moving them to `spawn_blocking` (CRYPTARCH-115)
/// stopped them starving the async workers, but the blocking pool grows to 512
/// threads on demand — so a spray of distinct usernames, which the per-username
/// throttle never sees, could ask for ~10 GB at once. A homelab box OOMs well
/// before that. Excess attempts queue for a permit instead: the attacker's
/// requests get slower, nobody else's memory goes anywhere.
pub const LOGIN_ARGON2_CONCURRENCY: usize = 4;

/// The same cap for AUTHENTICATED Argon2 work — provisioning, password resets,
/// password changes, admin user management (CRYPTARCH-128). A separate pool, so
/// an anonymous login spray queues only against itself and cannot stall a
/// signed-in user's provision behind it.
pub const ACCOUNT_ARGON2_CONCURRENCY: usize = 2;

static LOGIN_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(LOGIN_ARGON2_CONCURRENCY);
static ACCOUNT_PERMITS: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(ACCOUNT_ARGON2_CONCURRENCY);

/// The longest password any path will hash or verify. Far beyond anything
/// legitimate; the point is that a 2 MB form body is not held in the permit
/// queue and then fed to Argon2.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Run Argon2 work off the async workers, at most `pool`'s size at a time.
/// Generic so the cap can be tested without paying for real hashes.
///
/// The permit moves INTO the blocking closure (CRYPTARCH-128). Held by the
/// awaiting future instead, it was released the moment the request was
/// cancelled — a client closing its socket does that — while the blocking work,
/// which cannot be cancelled, ran on regardless. A disconnect-spray then had no
/// cap at all.
async fn with_permit<T, F>(pool: &'static tokio::sync::Semaphore, work: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    // The semaphores are static and never closed, so acquire cannot fail.
    let permit = pool.acquire().await.ok()?;
    // A panic in the hasher surfaces as None, which every caller treats as
    // "not verified" — a crash must never authenticate anybody.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .ok()
}

/// [`verify_password`] for the unauthenticated login path.
pub async fn verify_login_password(password: String, stored_hash: String) -> bool {
    if password.len() > MAX_PASSWORD_LEN {
        return false;
    }
    with_permit(&LOGIN_PERMITS, move || verify_password(&password, &stored_hash))
        .await
        .unwrap_or(false)
}

/// [`verify_password`] for signed-in paths (re-entering the current password).
pub async fn verify_account_password(password: String, stored_hash: String) -> bool {
    if password.len() > MAX_PASSWORD_LEN {
        return false;
    }
    with_permit(&ACCOUNT_PERMITS, move || verify_password(&password, &stored_hash))
        .await
        .unwrap_or(false)
}

/// [`hash_password`] for every request path.
pub async fn hash_password_capped(password: String) -> anyhow::Result<String> {
    anyhow::ensure!(password.len() <= MAX_PASSWORD_LEN, "password longer than {MAX_PASSWORD_LEN} bytes");
    with_permit(&ACCOUNT_PERMITS, move || hash_password(&password))
        .await
        .unwrap_or_else(|| Err(anyhow::anyhow!("password hashing panicked")))
}

/// The authenticated identity attached to a session.
#[derive(Clone, Debug)]
pub struct Session {
    pub user_id: Uuid,
    pub username: String,
    pub is_admin: bool,
    /// The account's password was set by an admin and not yet replaced: the
    /// session may only see who it is, change the password and sign out
    /// (CRYPTARCH-146). Enforced by the CurrentUser/ApiUser extractors.
    pub must_change_password: bool,
    /// The admin who set the password this session SIGNED IN with, kept for
    /// the session's life. See [`Session::actor`].
    ///
    /// What this does NOT do, so nobody mistakes it for more: accounts created
    /// or reset before migration 0023 are not gated; and a session that signs
    /// in FRESH on a password whoever held the issued one chose is recorded
    /// plainly — the trail shows the change of hands (one tagged
    /// change_password row) but cannot tell the admin from the user. Closing
    /// that needs a secret the admin never sees (an out-of-band reset link, or
    /// LDAP/OIDC).
    pub began_on_password_set_by: Option<String>,
}

impl Session {
    /// Who to record as having acted. Plainly the username — unless the
    /// session began on a password an admin set, in which case the admin
    /// could have been the one acting, and the trail says so rather than
    /// blaming the user (CRYPTARCH-146). Display and comparisons use
    /// `username`; anything that records an actor uses this.
    pub fn actor(&self) -> String {
        match &self.began_on_password_set_by {
            Some(admin) => format!("{} [on a password set by {admin}]", self.username),
            None => self.username.clone(),
        }
    }
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
    /// A session for a user who just signed in with the password whose hash is
    /// `verified_hash` — created only if that is STILL the account's hash, and
    /// inheriting, in the same statement, whoever set it (NULL: the user did).
    /// `None` when the password changed between the verify and now: a login
    /// checked against an admin-issued password must not land after the user
    /// replaced it, ungated and untagged (CRYPTARCH-146 audit P1). The row is
    /// read FOR SHARE: a login landing inside an admin's reset or suspension
    /// waits for it, then sees it and is refused — instead of reading the
    /// account as it was and slipping a session in after the sign-out (S6a
    /// audit P2).
    pub async fn insert_for_login(&self, user_id: Uuid, verified_hash: &str) -> anyhow::Result<Option<String>> {
        let _ = sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
            .execute(&self.db)
            .await;
        let token = new_token();
        let created = sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, began_on_password_set_by) \
             SELECT $1, u.id, now() + make_interval(days => $3), u.password_set_by \
             FROM users u WHERE u.id = $2 AND u.password_hash = $4 AND u.is_active \
             FOR SHARE OF u",
        )
        .bind(token_hash(&token))
        .bind(user_id)
        .bind(SESSION_TTL_DAYS as i32)
        .bind(verified_hash)
        .execute(&self.db)
        .await?
        .rows_affected();
        Ok((created == 1).then_some(token))
    }

    /// A session with an explicit lineage — the rotation after a password
    /// change carries the old session's, which the users row no longer has.
    pub async fn insert_carrying(&self, user_id: Uuid, began_on_password_set_by: Option<&str>) -> anyhow::Result<String> {
        let _ = sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
            .execute(&self.db)
            .await;
        let token = new_token();
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, began_on_password_set_by) \
             VALUES ($1, $2, now() + make_interval(days => $3), $4)",
        )
        .bind(token_hash(&token))
        .bind(user_id)
        .bind(SESSION_TTL_DAYS as i32)
        .bind(began_on_password_set_by)
        .execute(&self.db)
        .await?;
        Ok(token)
    }

    /// Resolve a token to a live session. The JOIN enforces expiry AND user
    /// active status — disabling a user kills their sessions immediately.
    /// Refreshes the sliding window at most every TOUCH_INTERVAL_MINUTES.
    pub async fn get(&self, token: &str) -> Option<Session> {
        let hash = token_hash(token);
        let row: Option<(Uuid, String, bool, bool, bool, Option<String>)> = sqlx::query_as(
            "SELECT s.user_id, u.username, u.is_admin, \
                    s.last_seen < now() - make_interval(mins => $2) AS stale, \
                    u.password_set_by IS NOT NULL AS must_change, s.began_on_password_set_by \
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
        let (user_id, username, is_admin, stale, must_change_password, began_on_password_set_by) = row?;
        if stale
            && let Err(e) = sqlx::query(
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
        Some(Session { user_id, username, is_admin, must_change_password, began_on_password_set_by })
    }

    /// End one session. Returns the failure rather than swallowing it
    /// (CRYPTARCH-138): a caller that reports "signed out" while the row is
    /// still live has told the user the opposite of the truth.
    pub async fn remove(&self, token: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(token_hash(token))
            .execute(&self.db)
            .await
            .map(|_| ())
            .inspect_err(|e| tracing::error!("session delete failed: {e}"))
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

    /// A password change, whole or not at all (CRYPTARCH-133): the new hash
    /// (the user's own now, so `password_set_by` clears), EVERY session of the
    /// user deleted, and one new session issued carrying `lineage` — in one
    /// transaction. Returns the new token and how many sessions went (the
    /// acting one included). A failure anywhere leaves the old password and
    /// every old session exactly as they were: a stolen pre-change cookie must
    /// not survive a change that is reported as done.
    ///
    /// Only if nothing moved since the current password was verified (S5 audit
    /// P1): the hash is still `verified_hash`, the account still active, and
    /// the acting session (`acting_token`) still alive. An admin reset or a
    /// suspension that lands mid-change wins; this returns `Stale` and changes
    /// nothing, rather than undoing it.
    pub async fn change_password_rotating(
        &self,
        user_id: Uuid,
        verified_hash: &str,
        new_hash: &str,
        acting_token: &str,
        lineage: Option<&str>,
    ) -> Result<(String, u64), RotateError> {
        let mut tx = self.db.begin().await?;
        let updated = sqlx::query(
            "UPDATE users SET password_hash = $1, password_set_by = NULL \
             WHERE id = $2 AND password_hash = $3 AND is_active",
        )
        .bind(new_hash)
        .bind(user_id)
        .bind(verified_hash)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if updated != 1 {
            return Err(RotateError::Stale);
        }
        let acting = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash = $2")
            .bind(user_id)
            .bind(token_hash(acting_token))
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if acting != 1 {
            return Err(RotateError::Stale);
        }
        let removed = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        let token = new_token();
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, began_on_password_set_by) \
             VALUES ($1, $2, now() + make_interval(days => $3), $4)",
        )
        .bind(token_hash(&token))
        .bind(user_id)
        .bind(SESSION_TTL_DAYS as i32)
        .bind(lineage)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        // `removed` counts the OTHER sessions: the acting one went first.
        Ok((token, removed))
    }

    /// "Sign out everywhere else", reporting failure rather than a count of
    /// zero that reads like "there were none".
    pub async fn remove_others_checked(&self, user_id: Uuid, current_token: &str) -> Result<u64, sqlx::Error> {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
            .bind(user_id)
            .bind(token_hash(current_token))
            .execute(&self.db)
            .await
            .map(|r| r.rows_affected())
    }

}

/// Why a password-and-session rotation did not happen. Nothing changed in either.
#[derive(Debug)]
pub enum RotateError {
    /// The hash, the account or the acting session moved since the verify.
    Stale,
    Db(sqlx::Error),
}

impl From<sqlx::Error> for RotateError {
    fn from(e: sqlx::Error) -> Self {
        RotateError::Db(e)
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
    let mut rng = rand::rng();
    (0..48)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
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
    static TEST_PERMITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(3);

    /// Spawn `n` permit-gated jobs of `work_ms` each and return the peak number
    /// running at once. With `stream_cancel_ms`, callers arrive one at a time
    /// and each is cancelled that long after it arrives — the shape of a client
    /// that sends a login and drops the socket — rather than all at once, which
    /// would leave no caller alive to pick up a wrongly freed permit.
    async fn peak_concurrency(n: usize, work_ms: u64, stream_cancel_ms: Option<u64>) -> usize {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let now = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let job = |now: Arc<AtomicUsize>, peak: Arc<AtomicUsize>| {
            with_permit(&TEST_PERMITS, move || {
                let k = now.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(k, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(work_ms));
                now.fetch_sub(1, Ordering::SeqCst);
            })
        };
        match stream_cancel_ms {
            None => {
                let tasks: Vec<_> =
                    (0..n).map(|_| tokio::spawn(job(now.clone(), peak.clone()))).collect();
                for t in tasks {
                    assert!(t.await.unwrap().is_some(), "every queued job must eventually run");
                }
            }
            Some(ms) => {
                for _ in 0..n {
                    let t = tokio::spawn(job(now.clone(), peak.clone()));
                    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                    t.abort();
                }
                // Let every job that did start run to completion.
                while now.load(Ordering::SeqCst) > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
        }
        peak.load(Ordering::SeqCst)
    }

    /// The cap holds, and the work really does run in parallel up to it —
    /// without the second assertion a helper that serialised everything (cap
    /// of 1, or a mutex) would pass, and so would one that never ran at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn argon2_work_is_capped_but_concurrent() {
        let peak = peak_concurrency(12, 30, None).await;
        assert!(peak <= 3, "{peak} ran at once, cap is 3");
        assert!(peak >= 2, "premise: the work runs concurrently up to the cap (peak {peak})");
    }

    /// A cancelled caller must not free its permit while its blocking work runs
    /// on (CRYPTARCH-128). A client that closes its socket cancels the handler;
    /// before the permit moved into the closure, that was a way round the cap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelling_callers_does_not_lift_the_cap() {
        // 12 callers, 25ms apart, each gone 25ms after arriving; work 400ms.
        let peak = peak_concurrency(12, 400, Some(25)).await;
        assert!(peak <= 3, "{peak} ran at once after their callers were cancelled, cap is 3");
        assert!(peak >= 2, "premise: work was really running when the callers went away (peak {peak})");
    }

    #[tokio::test]
    async fn a_panicking_verify_authenticates_nobody() {
        let out: Option<bool> = with_permit(&TEST_PERMITS, || panic!("hasher blew up")).await;
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn an_oversized_password_is_refused_before_it_queues() {
        let huge = "x".repeat(MAX_PASSWORD_LEN + 1);
        assert!(!verify_login_password(huge.clone(), DUMMY_HASH.clone()).await);
        assert!(hash_password_capped(huge).await.is_err());
        // Premise: the limit itself is not what fails ordinary passwords.
        let ok = hash_password_capped("x".repeat(MAX_PASSWORD_LEN)).await.expect("at the limit");
        assert!(verify_login_password("x".repeat(MAX_PASSWORD_LEN), ok).await);
    }

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
