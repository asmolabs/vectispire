//! `RetentionPolicy` and `EvidenceRetention`: which raw scanner payloads are purged, and how long the
//! registers that prove a control ran are kept.
//!
//! **What is purged is the whole subject.** A scan's raw SBOM and CVE blobs go; its summary, findings and
//! issues stay — the normalized projection is the durable record. A scan is purgeable only when it is
//! *both* outside its target's last-N window *and* older than the age limit: a target scanned twice a year
//! keeps its payloads while one scanned hourly stays bounded, which neither rule alone does.

use std::collections::HashMap;
use std::time::Duration;

use crate::instant::Instant;
use crate::{ScanTarget, java};

/// Zero on an axis means "no limit on that axis"; zero on both disables purging.
pub const UNLIMITED: u32 = 0;

/// The raw-payload policy: the last `keep_per_target` scans of each target, and anything younger than
/// `max_age`, keep their payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub keep_per_target: u32,
    pub max_age: Duration,
}

/// A scan whose payload might be purged; `created_at` is both its age and its rank's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub scan_id: i64,
    pub target: ScanTarget,
    pub created_at: Instant,
}

impl RetentionPolicy {
    /// Each target's last ten scans, and anything under ninety days: generous on purpose — the goal is to
    /// bound growth, and an operator chasing a regression looks at recent scans.
    pub const DEFAULT: RetentionPolicy =
        RetentionPolicy { keep_per_target: 10, max_age: Duration::from_secs(90 * 86_400) };

    /// A disabled policy purges nothing at all.
    pub fn is_enabled(&self) -> bool {
        self.keep_per_target != UNLIMITED || !self.max_age.is_zero()
    }

    /// The instant before which a scan is old enough to purge; `None` when age is unlimited.
    pub fn cutoff(&self, now: Instant) -> Option<Instant> {
        if self.max_age.is_zero() { None } else { now.minus(self.max_age) }
    }

    /// `RetentionPolicy.prunable`: the scans whose raw payloads may be dropped.
    ///
    /// Candidates must arrive **newest first, target by target** — the caller's query owns that order, and
    /// another one would purge the most recent scans, the very ones payloads exist for. Nothing here can
    /// check it.
    pub fn prunable(&self, candidates: &[Candidate], now: Instant) -> Vec<i64> {
        if !self.is_enabled() {
            return Vec::new();
        }
        let cutoff = self.cutoff(now);
        let mut seen: HashMap<ScanTarget, u32> = HashMap::new();
        let mut purgeable = Vec::new();
        for candidate in candidates {
            let count = seen.entry(candidate.target).or_insert(0);
            let rank = *count;
            *count = count.saturating_add(1);
            let within_keep_window = self.keep_per_target != UNLIMITED && rank < self.keep_per_target;
            // `false` with no age limit, and the inversion is not obvious: with no limit the age protects
            // nothing, so the keep window decides alone. Reading an absent cutoff as "everything is recent"
            // would make an unlimited age disable purging entirely.
            let recent_enough = cutoff.is_some_and(|cutoff| candidate.created_at > cutoff);
            if !within_keep_window && !recent_enough {
                purgeable.push(candidate.scan_id);
            }
        }
        purgeable
    }
}

/// `RetentionPolicy.intSetting`: an integer setting, or its fallback — **never zero by accident**, since
/// zero means "no limit" and a typo would quietly disable retention. Blank as `String.isBlank` reads it,
/// trimmed as `String.trim` trims, read by `Integer.parseInt` (a sign, any Unicode decimal digit), and a
/// negative value is the fallback too.
pub fn int_setting(raw: Option<&str>, fallback: i32) -> i32 {
    match raw {
        Some(raw) if !java::is_blank(raw) => match java::read_int(java::trim(raw)) {
            Ok(value) if value >= 0 => value,
            _ => fallback,
        },
        _ => fallback,
    }
}

/// `EvidenceRetention`: how long gate verdicts — the proof a control ran, which nothing can recreate — are
/// kept. Twelve months plus the weeks between a period's end and the assessor reading it.
pub mod evidence {
    use crate::instant::Instant;

    /// Four hundred days.
    pub const DEFAULT_DAYS: i32 = 400;

    /// The instant before which a verdict may be purged; `None` when `days` is zero or negative, which
    /// keeps evidence for ever — the safe direction for this table.
    pub fn cutoff(days: i32, now: Instant) -> Option<Instant> {
        if days <= 0 { None } else { now.minus_days(i64::from(days)) }
    }
}
