//! Identifier validation and credential generation.
//!
//! The first line of defence against injection-via-identifier: every database
//! name a user supplies must match a strict allowlist before it is ever
//! interpolated into DDL. The engine layer additionally quotes identifiers,
//! but validation happens here, early, where a rejection is a clean 400.

use rand::Rng;

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
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
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
}
