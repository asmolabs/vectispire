//! What a worker can run scans with, as it last said — `WorkerExecutors` (decision 0045).
//!
//! **Why the claim asks.** A worker whose Docker daemon is down used to claim scans all the same, and every step
//! that needed the daemon failed on the scan — an attempt spent per claim, three claims and the scan failed for good,
//! for a fault that was the worker's and not the target's. A worker that says none of its executors can run a kind is
//! not handed a scan of that kind; the scan waits for one that can.
//!
//! **Absent is unknown, never "nothing available".** An agent older than the announcement says nothing and claims as
//! it always did (decision 0043 §2). An agent that announced an empty list said it has no executor at all — a
//! different statement, which claims nothing. Every function here keeps the two apart: `Option<WorkerExecutors>` is
//! the announcement, and only `None` reads as "every kind".
//!
//! Shared by both sides: the agent announces through it, the control plane bounds, stores and reads it.

use crate::coerce::{self, Members};
use crate::failure_reason;
use crate::jackson::Refused;
use serde::Serialize;
use serde_json::value::RawValue;
use std::collections::BTreeSet;
use vectispire_domain::{bounded_text, java};

/// More than any worker has: a list past it is cut, not refused — see [`WorkerExecutors::bounded`].
pub const MAX_EXECUTORS: usize = 8;

/// The longest kind kept, in UTF-16 units.
pub const MAX_KIND_LENGTH: usize = 20;

/// The longest reason kept, in UTF-16 units. It is shown on a screen, and an executor's error can be a stack's worth.
pub const MAX_DETAIL_LENGTH: usize = 500;

/// The kinds of target a scan examines, by the names the wire and the screens use — `WorkerExecutors.Target`. The
/// order is the enum's, which `EnumSet` iterates in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutorTarget {
    /// A Git repository, cloned.
    Repository,
    /// A container image, exported from its registry.
    Container,
}

impl ExecutorTarget {
    pub const ALL: [ExecutorTarget; 2] = [ExecutorTarget::Repository, ExecutorTarget::Container];

    pub fn wire_name(self) -> &'static str {
        match self {
            ExecutorTarget::Repository => "repository",
            ExecutorTarget::Container => "container",
        }
    }

    /// Exactly the wire name: a name this version does not know is ignored, not guessed.
    pub fn by_wire_name(value: &str) -> Option<ExecutorTarget> {
        ExecutorTarget::ALL.into_iter().find(|target| target.wire_name() == value)
    }

    /// Every kind: what a worker that never said may be handed.
    pub fn every() -> BTreeSet<ExecutorTarget> {
        ExecutorTarget::ALL.into_iter().collect()
    }
}

/// One executor — `WorkerExecutors.Executor`, its components in their order, as Jackson writes the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Executor {
    /// `docker` or `kubernetes` today; any other name is kept and shown — what it runs is `targets`, not the name.
    pub kind: Option<String>,
    /// Whether it could run a scanner when the worker last asked it.
    pub available: bool,
    /// The kinds of target it scans, by wire name; a name this version does not know is ignored by the claim.
    pub targets: Vec<String>,
    /// Why it is unavailable, in the executor's words; `None` when it is available.
    pub detail: Option<String>,
}

impl Executor {
    /// The targets this version knows, in their order, each once.
    pub fn known_targets(&self) -> Vec<ExecutorTarget> {
        let mut known = Vec::new();
        for target in self.targets.iter().filter_map(|name| ExecutorTarget::by_wire_name(name)) {
            if !known.contains(&target) {
                known.push(target);
            }
        }
        known
    }
}

/// What a worker can run scans with: its executors, in the order it gave them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkerExecutors {
    pub executors: Vec<Executor>,
}

impl WorkerExecutors {
    pub fn new(executors: Vec<Executor>) -> WorkerExecutors {
        WorkerExecutors { executors }
    }

    /// What the worker may be handed: the targets of the executors that are available now. Empty when none is — or
    /// when the worker has none — and the claim then takes nothing.
    pub fn claimable(&self) -> BTreeSet<ExecutorTarget> {
        self.executors.iter().filter(|executor| executor.available).flat_map(Executor::known_targets).collect()
    }

    /// `WorkerExecutors.claimable(announced)`: [`claimable`](Self::claimable) when the worker said, every kind when
    /// it did not — the claim of an agent older than the announcement.
    pub fn claimable_of(announced: Option<&WorkerExecutors>) -> BTreeSet<ExecutorTarget> {
        announced.map_or_else(ExecutorTarget::every, WorkerExecutors::claimable)
    }

    /// Clipped to the bounds, never refused, as every other field an agent says about itself is: a refusal would drop
    /// the announcement and the agent would claim as an unknown — the opposite of what it said. The kind stripped, the
    /// targets reduced to the ones this version knows, **the detail scrubbed as a failure's reason is** (an API
    /// server's message can quote a URL with its credentials) and blank read as none.
    ///
    /// Lengths in UTF-16 units, cut on a character boundary: Java's `substring` can split a surrogate pair and leave a
    /// lone half, which no Rust string holds — an astral character straddling the limit is dropped whole here.
    pub fn bounded(&self) -> WorkerExecutors {
        let executors = self
            .executors
            .iter()
            .take(MAX_EXECUTORS)
            .map(|executor| {
                let kind = java::strip(executor.kind.as_deref().unwrap_or(""));
                let detail = failure_reason::scrub(executor.detail.as_deref().unwrap_or(""), []);
                Executor {
                    kind: bounded_text::clip(Some(kind), MAX_KIND_LENGTH).map(str::to_owned),
                    available: executor.available,
                    targets: executor.known_targets().into_iter().map(|target| target.wire_name().to_owned()).collect(),
                    detail: if detail.is_empty() {
                        None
                    } else {
                        bounded_text::clip(Some(&detail), MAX_DETAIL_LENGTH).map(str::to_owned)
                    },
                }
            })
            .collect();
        WorkerExecutors { executors }
    }

    /// The stored form: the JSON the wire carries, so the column reads as what the agent said — written as Jackson
    /// writes the list of records (`null` for an absent detail, upper-case hex in `\u` escapes).
    pub fn write(&self) -> String {
        // A list of plain records: serialization cannot fail.
        crate::server::write(&self.executors).unwrap_or_else(|_| "[]".to_owned())
    }

    /// The stored form read back, `None` when there is none. **Unreadable reads as none too**, and the worker then
    /// claims as before: only the control plane writes the column, from a list it has already read, so an unreadable
    /// value is a row edited by hand — and keeping a worker from every scan over it would be the worse failure.
    pub fn read(stored: Option<&str>) -> Option<WorkerExecutors> {
        let stored = stored.filter(|text| !java::is_blank(text))?;
        let raw: &RawValue = serde_json::from_str(stored).ok()?;
        read_list(raw).ok().flatten().map(WorkerExecutors::new)
    }
}

/// A JSON list of executors as Jackson binds `List<WorkerExecutors.Executor>`: `None` for `null`, null elements
/// dropped as the record's constructor drops them, unknown members read past (`ignoreUnknown`).
pub(crate) fn read_list(raw: &RawValue) -> Result<Option<Vec<Executor>>, Refused> {
    let Some(elements) = coerce::list(raw, "java.util.List")? else { return Ok(None) };
    let mut executors = Vec::with_capacity(elements.len());
    for element in elements {
        if let Some(members) = coerce::members(element, "WorkerExecutors$Executor")? {
            executors.push(executor(&members)?);
        }
    }
    Ok(Some(executors))
}

fn executor(members: &Members<'_>) -> Result<Executor, Refused> {
    let targets = match coerce::last(members, "targets", |raw| coerce::list(raw, "java.util.List"))?.flatten() {
        None => Vec::new(),
        Some(elements) => {
            let mut names = Vec::with_capacity(elements.len());
            for element in elements {
                if let Some(name) = coerce::text(element)? {
                    names.push(name);
                }
            }
            names
        }
    };
    Ok(Executor {
        kind: coerce::last(members, "kind", coerce::text)?.flatten(),
        available: coerce::last(members, "available", coerce::boolean)?.unwrap_or(false),
        targets,
        detail: coerce::last(members, "detail", coerce::text)?.flatten(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn docker(available: bool, targets: &[&str], detail: Option<&str>) -> Executor {
        Executor {
            kind: Some("docker".into()),
            available,
            targets: targets.iter().map(|t| (*t).to_owned()).collect(),
            detail: detail.map(str::to_owned),
        }
    }

    #[test]
    fn absent_is_every_kind_and_empty_is_none() {
        assert_eq!(WorkerExecutors::claimable_of(None), ExecutorTarget::every());
        assert!(WorkerExecutors::claimable_of(Some(&WorkerExecutors::default())).is_empty());
        let down = WorkerExecutors::new(vec![docker(false, &["repository", "container"], Some("down"))]);
        assert!(WorkerExecutors::claimable_of(Some(&down)).is_empty());
        let repositories = WorkerExecutors::new(vec![docker(true, &["repository", "later"], None)]);
        assert_eq!(repositories.claimable(), BTreeSet::from([ExecutorTarget::Repository]));
    }

    #[test]
    fn the_stored_form_is_jackson_s() {
        let stored = WorkerExecutors::new(vec![docker(
            false,
            &["repository", "container"],
            Some("The Docker daemon did not answer a ping: connection refused"),
        )])
        .write();
        assert_eq!(
            stored,
            r#"[{"kind":"docker","available":false,"targets":["repository","container"],"detail":"The Docker daemon did not answer a ping: connection refused"}]"#
        );
        assert_eq!(WorkerExecutors::read(Some(&stored)).map(|read| read.write()), Some(stored));
        assert_eq!(WorkerExecutors::read(Some("not json")), None);
        assert_eq!(WorkerExecutors::read(Some(" ")), None);
        assert_eq!(WorkerExecutors::read(Some("[]")), Some(WorkerExecutors::default()));
    }

    #[test]
    fn bounded_clips_scrubs_and_forgets_unknown_targets() {
        let long = "k".repeat(30);
        let many: Vec<Executor> = (0..10).map(|_| docker(true, &["repository"], None)).collect();
        assert_eq!(WorkerExecutors::new(many).bounded().executors.len(), MAX_EXECUTORS);
        let one = WorkerExecutors::new(vec![Executor {
            kind: Some(format!("  {long}  ")),
            available: false,
            targets: vec!["container".into(), "later".into(), "container".into()],
            detail: Some("token=abcdefgh\n  ".into()),
        }])
        .bounded();
        let executor = &one.executors[0];
        assert_eq!(executor.kind.as_deref(), Some(&long[..MAX_KIND_LENGTH]));
        assert_eq!(executor.targets, ["container"]);
        assert_eq!(executor.detail.as_deref(), Some("token=***"));
        let blank = WorkerExecutors::new(vec![docker(true, &[], Some("  "))]).bounded();
        assert_eq!(blank.executors[0].detail, None);
    }
}
