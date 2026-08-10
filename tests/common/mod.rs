//! Scaffolding shared by the fixture-based integration tests.
//!
//! The tests shell out to `db_dump`, which `build.rs` only vendors on
//! non-Windows platforms (elsewhere it must be on `PATH`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use zewif_zcashd::{BDBDump, BdbDumpError, ZcashdDump};

/// The once-per-binary outcome of `db_dump`ing a fixture.
pub enum FixtureDump {
    /// `db_dump` ran and its records were collected.
    Loaded(ZcashdDump),
    /// `db_dump` could not be used: the binary is missing (not vendored and
    /// not on `PATH` — notably Windows CI) or it ran and failed (e.g. an
    /// incompatible Berkeley DB build). Tests skip rather than fail.
    DbDumpUnavailable(String),
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Dump and collect a fixture, caching the outcome so each fixture is
/// `db_dump`ed at most once per test binary no matter how many tests use it.
pub fn fixture_dump(name: &'static str) -> &'static FixtureDump {
    static CACHE: OnceLock<Mutex<HashMap<&'static str, &'static FixtureDump>>> = OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap();
    cache.entry(name).or_insert_with(|| {
        let outcome = match BDBDump::from_file(&fixture_path(name)) {
            Ok(bdb) => FixtureDump::Loaded(
                ZcashdDump::from_bdb_dump(&bdb, false).expect("collect records"),
            ),
            Err(e @ (BdbDumpError::DbDumpExec { .. } | BdbDumpError::DbDumpFailed { .. })) => {
                FixtureDump::DbDumpUnavailable(e.to_string())
            }
            // `db_dump` itself succeeded but produced output we cannot read:
            // a corrupt fixture or a real bug, never a reason to skip.
            Err(e) => panic!("reading fixture {name}: {e}"),
        };
        Box::leak(Box::new(outcome))
    })
}

/// Fetch the cached [`ZcashdDump`] for a fixture, or skip the current test
/// (returning as a pass) when `db_dump` is unavailable on this platform.
macro_rules! require_fixture_dump {
    ($name:expr) => {
        match crate::common::fixture_dump($name) {
            crate::common::FixtureDump::Loaded(dump) => dump,
            crate::common::FixtureDump::DbDumpUnavailable(reason) => {
                eprintln!("skipping: db_dump is unavailable: {reason}");
                return;
            }
        }
    };
}
pub(crate) use require_fixture_dump;
