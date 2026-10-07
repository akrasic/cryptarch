//! Cryptarch library surface — everything the binary (and the integration
//! tests in `tests/`) build on. The binary in `main.rs` stays a thin boot
//! sequence; tests construct [`web::AppState`] and drive [`web::router`]
//! directly against a throwaway database.

pub mod acl;
pub mod api;
pub mod admin;
pub mod admin_servers;
pub mod auth;
pub mod backup;
pub mod bouncer;
pub mod config;
pub mod crypto;
pub mod edge;
pub mod health;
pub mod engine;
pub mod manifest;
pub mod metrics;
pub mod names;
pub mod profile;
pub mod provision;
pub mod repair;
pub mod restore;
pub mod servers;
pub mod status;
pub mod web;

/// The embedded metadata migrations, shared by the binary and the test
/// harness so both always run the identical schema.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
