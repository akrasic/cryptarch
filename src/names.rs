//! Identifier validation and credential generation.
//!
//! The first line of defence against injection-via-identifier: every database
//! name a user supplies must match a strict allowlist before it is ever
//! interpolated into DDL. The engine layer additionally quotes identifiers,
//! but validation happens here, early, where a rejection is a clean 400.

use rand::RngExt;

/// Allowed database/role name: lowercase letter first, then lowercase
/// alphanumerics and underscores, 3–63 chars. No quotes, no spaces, no dashes.
pub fn valid_db_name(name: &str) -> bool {
    let len = name.len();
    if !(3..=63).contains(&len) {
        return false;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Generate a 32-character CSPRNG password from an unambiguous alphabet.
pub fn generate_password() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    let mut rng = rand::rng();
    (0..32)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_injection_shapes() {
        assert!(!valid_db_name("ab"));                 // too short
        assert!(!valid_db_name("1abc"));               // leading digit
        assert!(!valid_db_name("Alice"));              // uppercase
        assert!(!valid_db_name("robert'; DROP"));      // quote + space
        assert!(!valid_db_name("has-dash"));           // dash
        assert!(!valid_db_name(&"x".repeat(64)));      // too long
    }

    #[test]
    fn accepts_sane_names() {
        assert!(valid_db_name("alice"));
        assert!(valid_db_name("alice_db"));
        assert!(valid_db_name("project_42"));
    }

    #[test]
    fn password_is_32_chars() {
        assert_eq!(generate_password().len(), 32);
    }

    /// The alphabet deliberately omits `I O l o 0 1` so a password can be read
    /// off a screen and typed without ambiguity. A generator that indexed
    /// outside it would still produce 32 characters, so length alone does not
    /// check this.
    #[test]
    fn password_uses_only_the_unambiguous_alphabet() {
        const ALPHABET: &str = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
        let pw = generate_password();
        assert!(!pw.is_empty(), "nothing to check if the password is empty");
        for c in pw.chars() {
            assert!(ALPHABET.contains(c), "password contains {c:?}, which is outside the alphabet");
        }
    }

    /// `password_is_32_chars` passes for a generator that returns the same
    /// character 32 times, and that is exactly what a degenerate RNG produces
    /// — a fixed seed, a stuck source, a range collapsed to one value. This is
    /// the function that mints every credential the system issues, so the
    /// property worth asserting is that it actually varies.
    ///
    /// Sampling rather than eyeballing two values: across 100 passwords (3200
    /// characters) the chance that any given alphabet character never appears
    /// is about e^-57, so requiring full coverage is not flaky. It also catches
    /// an off-by-one that silently excluded the last character of the alphabet.
    #[test]
    fn password_draws_from_the_whole_alphabet_and_varies() {
        const ALPHABET: &str = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";

        let first = generate_password();
        assert_ne!(first, generate_password(), "two passwords in a row were identical");

        let seen: std::collections::HashSet<char> =
            (0..100).flat_map(|_| generate_password().chars().collect::<Vec<_>>()).collect();

        // Positive precondition: without this, an empty `seen` would sail
        // through a subset check and prove nothing.
        assert_eq!(seen.len(), ALPHABET.chars().count(), "generator does not cover the alphabet");
        for c in ALPHABET.chars() {
            assert!(seen.contains(&c), "{c:?} never appeared in 3200 generated characters");
        }
    }
}
