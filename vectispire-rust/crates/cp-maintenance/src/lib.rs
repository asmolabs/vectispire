//! The control plane's maintenance module — the Rust of `core.maintenance` (plan, Phase 2 task 2.1): the periodic
//! jobs' port and the jobs that run once per database. A shared module, as Java declares it on
//! `VectispireApplication`: every module may use it without a line in its list, and it uses none.
//!
//! - [`MaintenanceTask`] is the port a module implements, beside the service it calls; [`Sequence`] is the one global
//!   order of every module's tasks, every slot reserved, and each slot says its [`Cadence`].
//! - [`Turns`] runs the three turns: thirty seconds before the first run, a fixed delay after each, a guard per
//!   cadence, and a task that fails ends its own run, not the turn — `MaintenanceJobs`.
//! - [`composition`] holds the binary's composition to Java's: every slot filled, or deferred in a list that only
//!   shrinks — `MaintenanceCompositionTest`, for a port that lands one module at a time.
//! - [`OneShotJobs`] claims a job by the primary key of `t_one_shot_job`, in the transaction that does its work.
//!
//! **No leader election here, deliberately.** Every instance runs every turn; a task that must run once elects inside
//! the service it calls. The scan scheduler's lease row is scanning's (task 2.7), not this crate's.

#![forbid(unsafe_code)]

pub mod composition;
mod one_shot;
mod persistence;
mod task;
mod turns;

pub use one_shot::{Clock, OneShotError, OneShotJobs, SystemClock};
pub use task::{Cadence, MaintenanceTask, Sequence, TaskError, TaskRun};
pub use turns::{CompositionError, Intervals, Turn, Turns};
