//! How many password derivations run at once, and how long one waits for its turn — `DerivationGate`,
//! `DerivationsSaturated` and `PasswordDerivationBound`.
//!
//! **Each Argon2id derivation holds 19 MiB for its length, and nothing bounded how many ran together.** The sign-in
//! throttles count per address and per account: they bound what one client may try, not what every client together
//! costs. An anonymous sign-in is admitted, and a name nobody holds is verified against the stand-in hash all the same
//! (that is what keeps the answer's timing silent on whether the account exists) — so enough addresses, each within its
//! own ceiling, ran enough derivations at once to exhaust the memory of a pod sized for normal use. A derivation past
//! the bound waits a short while for a permit, then is refused as [`DerivationsSaturated`]: an answer the caller can
//! retry — `503` with `Retry-After`, code `unavailable` ([`DerivationsSaturated::problem`]) — rather than a process
//! that dies for everybody. A Rust allocation failure ends the process, where Java's `OutOfMemoryError` ended a
//! request: the bound matters more here, not less.
//!
//! **The wait is fair**: permits go in the order they were asked for (tokio's semaphore is first-in, first-out, as
//! Java's `new Semaphore(n, true)`), so a stream of new attempts does not starve one that has been waiting. And the
//! wait is **asynchronous**: a derivation waiting for its turn holds no worker thread, which a blocking wait on the
//! runtime's few threads would — every other request would then queue behind the sign-ins.
//!
//! **One bound for the process, installed at start** ([`bound`], [`gate`]): Java puts it on `PasswordHasher`, called
//! statically from every place that derives — a sign-in, an API key, a password change, an account created — and so
//! does this, through [`crate::passwords`] and the API keys' hash. A bound each caller had to be handed would be the
//! one somebody forgot.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::Semaphore;

/// `DerivationGate.DEFAULT_WAIT`: two seconds. At the shipped cost a derivation takes a few tens of milliseconds, so a
/// burst of people signing in at nine o'clock clears well inside it, and a refusal still comes back before a browser's
/// patience does.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(2);

/// `DerivationGate.HEAP_SHARE_DIVISOR`: no more than this share of the memory goes to derivations in flight, whatever
/// the processor count says — a container without a CPU limit reports the host's, and 64 permits at 19 MiB is more than
/// the shipped chart's memory.
const MEMORY_SHARE_DIVISOR: u64 = 4;

/// `DerivationsSaturated`'s sentence, which says nothing about the password or the account: the permit is asked for
/// before anything is compared, for a name nobody holds exactly as for an account's.
pub const SATURATED: &str = "Too many passwords are being verified at once. Try again in a few seconds.";

/// Every derivation permit is taken and none came free in time. Transient by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}", SATURATED)]
pub struct DerivationsSaturated {
    retry_after: Duration,
}

impl DerivationsSaturated {
    /// What the caller is told to wait.
    pub fn retry_after(&self) -> Duration {
        self.retry_after
    }

    /// `Math.max(1, retryAfter.toSeconds())`: the whole seconds `Retry-After` and `retryAfterSeconds` carry.
    pub fn retry_after_seconds(&self) -> u64 {
        self.retry_after.as_secs().max(1)
    }

    /// The answer `ApiExceptionHandler.derivationsSaturated` gives: 503, the sentence, code `unavailable`, the wait in
    /// the member `retryAfterSeconds` and in `Retry-After`. The routes that verify a password answer this when the
    /// service raises it (no access route is served yet; this is what they will answer).
    pub fn problem(&self) -> vectispire_cp_http::problem::Problem {
        let seconds = self.retry_after_seconds();
        vectispire_cp_http::problem::Problem::handler(http::StatusCode::SERVICE_UNAVAILABLE, SATURATED)
            .code("unavailable")
            .with("retryAfterSeconds", seconds)
            .header("Retry-After", seconds.to_string())
    }
}

/// The bound: how many derivations at once, and how long one waits for its turn.
#[derive(Debug)]
pub struct DerivationGate {
    permits: Arc<Semaphore>,
    size: u32,
    wait: Duration,
}

impl DerivationGate {
    /// `permits` derivations at once — zero reads as [`DerivationGate::default_permits`], as every ceiling here reads
    /// an unset value as the shipped one rather than as "nobody signs in"; `wait` for a permit — zero reads as
    /// [`DEFAULT_WAIT`]. `vectispire.sign-in.derivations.concurrent` and `.queue-wait`, already read that way by the
    /// runtime's settings.
    pub fn new(permits: u32, wait: Duration) -> DerivationGate {
        let size = if permits > 0 { permits } else { DerivationGate::default_permits() };
        let wait = if wait.is_zero() { DEFAULT_WAIT } else { wait };
        DerivationGate { permits: Arc::new(Semaphore::new(usize::try_from(size).unwrap_or(1))), size, wait }
    }

    /// The shipped bound: one per processor, at least two, and no more than a quarter of the memory holds.
    ///
    /// **The memory read is the container's limit** (cgroup v2's `memory.max`), where Java reads its heap's maximum:
    /// a Rust process has no heap ceiling of its own, and the container's is what an allocation failure runs into.
    /// Without one — a machine with no limit, a platform without cgroups — the processors alone decide.
    pub fn default_permits() -> u32 {
        let processors = std::thread::available_parallelism().map_or(1, |count| count.get());
        DerivationGate::default_permits_for(u32::try_from(processors).unwrap_or(u32::MAX), container_memory_limit())
    }

    /// The rule of [`DerivationGate::default_permits`], given the processors and the memory.
    pub fn default_permits_for(processors: u32, memory_bytes: Option<u64>) -> u32 {
        // Argon2 at parallelism 1 keeps one processor busy; more permits than processors only queue inside the
        // scheduler instead of at the gate, holding their memory while they do.
        let by_processors = processors.max(2);
        let Some(memory) = memory_bytes else {
            return by_processors;
        };
        let by_memory = memory
            .checked_div(MEMORY_SHARE_DIVISOR)
            .and_then(|share| share.checked_div(derivation_bytes()))
            .unwrap_or(0)
            .max(1);
        u32::try_from(by_memory).map_or(by_processors, |by_memory| by_processors.min(by_memory))
    }

    /// How many derivations may run at once.
    pub fn permits(&self) -> u32 {
        self.size
    }

    /// How long a derivation waits for its turn before it is refused.
    pub fn wait(&self) -> Duration {
        self.wait
    }

    /// What a refused caller is told to wait: the gate's own wait, at least a second. Saturation is measured in
    /// derivations, which last milliseconds, so the condition clears in about that time.
    pub fn retry_after(&self) -> Duration {
        self.wait.max(Duration::from_secs(1))
    }

    /// Permits free right now — for a test to see that a refused or failed derivation gave its back.
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }

    /// Runs one derivation under a permit, released however it ends — a panic included, the permit being dropped
    /// with the stack it lives on.
    pub async fn run<T>(&self, derivation: impl FnOnce() -> T) -> Result<T, DerivationsSaturated> {
        let refused = DerivationsSaturated { retry_after: self.retry_after() };
        let permit = match tokio::time::timeout(self.wait, self.permits.acquire()).await {
            Ok(Ok(permit)) => permit,
            // Elapsed, or a closed semaphore — which nothing closes: either way no permit, and nothing compared.
            Ok(Err(_)) | Err(_) => return Err(refused),
        };
        let derived = derivation();
        drop(permit);
        Ok(derived)
    }
}

/// What one derivation at the current cost holds while it runs, for sizing the bound.
pub fn derivation_bytes() -> u64 {
    u64::from(crate::passwords::MEMORY_KIB).saturating_mul(1024)
}

/// The bound in force for the process: the one [`bound`] installed, or the shipped one until then — in code that runs
/// without the deployment's settings, a test or a tool.
static GATE: RwLock<Option<Arc<DerivationGate>>> = RwLock::new(None);

/// Puts a bound in force for every derivation of the process — `PasswordHasher.bound`, which
/// `PasswordDerivationBound` calls once at start, before the first request is served. No database: the start stays
/// free of one.
pub fn bound(gate: DerivationGate) {
    tracing::info!(
        "Password derivations: at most {} at once, waiting up to {} ms for a turn.",
        gate.permits(),
        gate.wait().as_millis()
    );
    let gate = Arc::new(gate);
    match GATE.write() {
        Ok(mut slot) => *slot = Some(gate),
        Err(poisoned) => *poisoned.into_inner() = Some(gate),
    }
}

/// The bound in force — `PasswordHasher.gate()`.
pub fn gate() -> Arc<DerivationGate> {
    let installed = match GATE.read() {
        Ok(slot) => slot.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    if let Some(gate) = installed {
        return gate;
    }
    let mut slot = match GATE.write() {
        Ok(slot) => slot,
        Err(poisoned) => poisoned.into_inner(),
    };
    slot.get_or_insert_with(|| Arc::new(DerivationGate::new(0, Duration::ZERO))).clone()
}

/// cgroup v2's memory limit, when the process runs under one: `max` is no limit.
fn container_memory_limit() -> Option<u64> {
    let text = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()?;
    text.trim().parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    /// `DerivationGateTest.shippedBound`.
    #[test]
    fn the_shipped_bound_is_one_per_processor_at_least_two_and_never_more_than_a_quarter_of_the_memory() {
        assert_eq!(DerivationGate::default_permits_for(1, Some(4096 * MIB)), 2);
        assert_eq!(DerivationGate::default_permits_for(8, Some(4096 * MIB)), 8);
        // The shipped Helm chart's heap, on a node reporting 64 processors.
        assert_eq!(DerivationGate::default_permits_for(64, Some(1536 * MIB)), 20);
        assert!(
            u64::from(DerivationGate::default_permits_for(64, Some(1536 * MIB))) * derivation_bytes() <= 1536 * MIB / 4
        );
        assert_eq!(DerivationGate::default_permits_for(4, Some(32 * MIB)), 1);
        assert_eq!(DerivationGate::default_permits_for(3, None), 3);
    }

    /// `DerivationGateTest.unsetReadsAsShipped`.
    #[test]
    fn an_unset_bound_reads_as_the_shipped_one_never_as_zero() {
        assert_eq!(DerivationGate::new(0, Duration::ZERO).permits(), DerivationGate::default_permits());
        assert_eq!(DerivationGate::new(0, Duration::ZERO).wait(), DEFAULT_WAIT);
        assert_eq!(DerivationGate::new(5, Duration::from_millis(300)).permits(), 5);
        assert_eq!(DerivationGate::new(5, Duration::from_millis(300)).retry_after(), Duration::from_secs(1));
        assert_eq!(DerivationGate::new(5, Duration::from_secs(3)).retry_after(), Duration::from_secs(3));
    }
}
