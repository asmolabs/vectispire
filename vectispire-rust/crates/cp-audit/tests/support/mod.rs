//! A database of its own on each engine, migrated by `vectispire-migrate` — the runner held to the real Flyway by
//! its own oracle — and, for the oracle suite, the real Java audit log on the same database.
//!
//! The database is `vectispire_cp_db::testing`'s: one of its own for each test, in a throwaway container or on
//! the shared server `VECTISPIRE_TEST_MYSQL_URL` / `VECTISPIRE_TEST_POSTGRES_URL` names (see that module).

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use time::OffsetDateTime;
use vectispire_cp_audit::{AuditLog, Clock, Mirror, MirrorEntry, NoMirror, SystemClock};
use vectispire_cp_db::Db;

#[allow(unused_imports)] // not every suite of the crate reaches a database
pub use vectispire_cp_db::testing::TestDatabase as Migrated;

/// The real Java audit log on a test's database (`oracle/oracle.sh`).
pub trait Oracle {
    /// In a JVM on UTC, as the images run.
    fn oracle(&self, args: &[&str]) -> Result<String, String> {
        self.oracle_in_zone("UTC", args)
    }

    /// In a JVM whose default time zone is `zone`.
    fn oracle_in_zone(&self, zone: &str, args: &[&str]) -> Result<String, String>;
}

impl Oracle for Migrated {
    fn oracle_in_zone(&self, zone: &str, args: &[&str]) -> Result<String, String> {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("oracle/oracle.sh");
        let mut all = vec![args[0].to_owned(), self.jdbc_url(), self.username().to_owned(), self.password().to_owned()];
        all.extend(args[1..].iter().map(|arg| (*arg).to_owned()));
        let output = Command::new(&script)
            .args(&all)
            .env("ORACLE_TIMEZONE", zone)
            .output()
            .expect("oracle/oracle.sh runs (it needs a JDK 25)");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        if output.status.success() {
            Ok(stdout)
        } else {
            Err(format!("{stdout}\n{}", String::from_utf8_lossy(&output.stderr)))
        }
    }
}

/// A log with no mirror and no listener, on the system clock.
pub fn plain_log(db: &Db) -> AuditLog {
    AuditLog::new(db.clone(), Arc::new(NoMirror), Arc::new(SystemClock), Vec::new())
}

/// A clock a test moves by hand.
#[derive(Debug)]
pub struct FixedClock(pub Mutex<OffsetDateTime>);

impl FixedClock {
    pub fn at(instant: OffsetDateTime) -> Arc<FixedClock> {
        Arc::new(FixedClock(Mutex::new(instant)))
    }

    pub fn set(&self, instant: OffsetDateTime) {
        *self.0.lock().unwrap() = instant;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

/// A mirror held in memory, which can be told to refuse.
#[derive(Debug, Default)]
pub struct MemoryMirror {
    pub lines: Mutex<Vec<MirrorEntry>>,
    pub refuse: std::sync::atomic::AtomicBool,
}

impl Mirror for MemoryMirror {
    fn append(&self, entry: &MirrorEntry) -> bool {
        if self.refuse.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        self.lines.lock().unwrap().push(entry.clone());
        true
    }

    fn configured(&self) -> bool {
        true
    }

    fn entry_hashes(&self) -> Result<Vec<String>, String> {
        Ok(self.lines.lock().unwrap().iter().map(|line| line.entry_hash.clone()).collect())
    }
}
