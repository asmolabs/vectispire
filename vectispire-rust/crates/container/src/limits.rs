//! What a scanner may consume — `ScannerLimits`.

use std::time::Duration;

/// A scanner's ceilings: a container that exceeds one dies, the host does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannerLimits {
    /// Bytes of memory, scratch space included: a tmpfs counts against it.
    pub memory: i64,
    /// What turns a fork bomb into a dead container.
    pub pids: i64,
    /// How long a run may last before it is stopped and reported as a failure.
    pub timeout: Duration,
    /// CPU quota in billionths of a CPU, clamped to what the daemon can grant.
    pub nano_cpus: i64,
    /// How much of the standard output is kept; more fails the run rather than truncating it.
    pub output_bytes: usize,
}

/// `ScannerLimits.DEFAULT_OUTPUT_BYTES`.
pub const DEFAULT_OUTPUT_BYTES: usize = 256 * 1024 * 1024;

impl ScannerLimits {
    /// `ScannerLimits.DEFAULT`: 2 GiB, 512 processes, fifteen minutes, all cores but one.
    pub fn default_for_this_host() -> ScannerLimits {
        let cores = std::thread::available_parallelism().map_or(1, |cores| cores.get() as i64);
        ScannerLimits {
            memory: 2048 * 1024 * 1024,
            pids: 512,
            timeout: Duration::from_secs(15 * 60),
            nano_cpus: all_but_one(cores),
            output_bytes: DEFAULT_OUTPUT_BYTES,
        }
    }

    /// The quota clamped to what a daemon with `cores` CPUs accepts: it refuses a create asking for
    /// more ("Range of CPUs is from 0.01 to 4.00"), and Docker Desktop's VM usually has fewer cores
    /// than the host this process counts.
    pub fn clamped_to(self, cores: i64) -> ScannerLimits {
        if cores <= 0 {
            return self;
        }
        ScannerLimits { nano_cpus: self.nano_cpus.min(all_but_one(cores)), ..self }
    }
}

/// All cores but one, in nano-CPUs — one left for the control plane to answer a gate call on.
pub fn all_but_one(cores: i64) -> i64 {
    (cores - 1).max(1) * 1_000_000_000
}
