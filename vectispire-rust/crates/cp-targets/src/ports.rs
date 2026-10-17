//! What `targets` asks of the modules above it — the scan queue and the backlog — as ports it declares, so that the
//! dependency points from them to `targets` and nowhere else (decision 0029): `TargetScans`, implemented by
//! `scanning` (task 2.7), and `TargetBacklog`, by `issues` (Phase 3). Each has a stand-in here, named after the module
//! that will replace it, which the binary composes until then.

use std::collections::{BTreeMap, BTreeSet};

use time::OffsetDateTime;
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_domain::Severity;

use crate::views::{ContainerView, RepositoryView};

/// A port's failure — never read as an empty answer (decision 0007).
pub type PortError = Box<dyn std::error::Error + Send + Sync>;

/// The open backlog per target and severity.
pub type OpenBySeverity = BTreeMap<ScanTarget, BTreeMap<Severity, i64>>;

/// A target's most recent scan, as the listings show it beside the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestScan {
    pub id: i64,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub error: Option<String>,
}

/// A scan just queued: what the "scan now" route answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    pub id: i64,
    pub status: String,
}

/// Why a scan was not queued.
#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    /// `ScanTriggerService.AlreadyQueuedException`: one is already waiting — a 409.
    #[error("{0}")]
    AlreadyQueued(String),
    #[error(transparent)]
    Failed(PortError),
}

/// `TargetScans`: each target's latest scan, the languages a repository was found written in, and a scan queued on
/// request. `scanning` → `targets` is the direction kept: a scan is of a target.
pub trait TargetScans: Send + Sync {
    /// The latest scan of every repository that has one, keyed by repository.
    fn latest_per_repository(&self) -> BoxFuture<'_, Result<BTreeMap<i64, LatestScan>, PortError>>;
    /// The latest scan of every image that has one, keyed by image.
    fn latest_per_container(&self) -> BoxFuture<'_, Result<BTreeMap<i64, LatestScan>, PortError>>;
    /// The languages each of these repositories' newest completed scan found, as wire names (`Language`'s, whose
    /// declaration order is their alphabetical one). **A repository missing from the answer is unknown**, which a
    /// screen must never show as "no language"; an empty set is "counted, and none" (decision 0007).
    fn detected_languages<'a>(
        &'a self,
        repositories: &'a [i64],
    ) -> BoxFuture<'a, Result<BTreeMap<i64, BTreeSet<String>>, PortError>>;
    /// Queues a scan of the repository as it stands — branch, sub-path and required label copied onto the scan —
    /// claimed by no executor before `not_before` when one is given; refuses when one is already waiting.
    fn queue_repository<'a>(
        &'a self,
        repository: &'a RepositoryView,
        not_before: Option<OffsetDateTime>,
    ) -> BoxFuture<'a, Result<Queued, QueueError>>;
    /// The same for an image.
    fn queue_container<'a>(&'a self, container: &'a ContainerView) -> BoxFuture<'a, Result<Queued, QueueError>>;
}

/// `TargetBacklog`: the open-issue figures the target screens show beside each row and in the solutions tree.
pub trait TargetBacklog: Send + Sync {
    /// Open issues per repository, settled triage included — the count the repository list shows.
    fn open_per_repository(&self) -> BoxFuture<'_, Result<BTreeMap<i64, i64>, PortError>>;
    /// The same per image.
    fn open_per_container(&self) -> BoxFuture<'_, Result<BTreeMap<i64, i64>, PortError>>;
    /// The open backlog per target and severity, **settled triage left out**, for the targets `narrowed` permits —
    /// the solutions tree's figures.
    fn open_by_severity_per_target<'a>(
        &'a self,
        narrowed: &'a Visibility,
    ) -> BoxFuture<'a, Result<OpenBySeverity, PortError>>;
}

/// `issues`' stand-in until Phase 3: **zero figures** (plan §7, the stand-ins table). The listings' goldens recorded
/// with open issues wait for Phase 3 (`golden/deferred.txt`).
#[derive(Debug, Clone, Copy, Default)]
pub struct IssuesStandIn;

impl TargetBacklog for IssuesStandIn {
    fn open_per_repository(&self) -> BoxFuture<'_, Result<BTreeMap<i64, i64>, PortError>> {
        Box::pin(async { Ok(BTreeMap::new()) })
    }

    fn open_per_container(&self) -> BoxFuture<'_, Result<BTreeMap<i64, i64>, PortError>> {
        Box::pin(async { Ok(BTreeMap::new()) })
    }

    fn open_by_severity_per_target<'a>(
        &'a self,
        _narrowed: &'a Visibility,
    ) -> BoxFuture<'a, Result<OpenBySeverity, PortError>> {
        Box::pin(async { Ok(BTreeMap::new()) })
    }
}

/// `scanning`'s stand-in until task 2.7: no scan yet for any target, every repository's languages unknown, and a
/// scan request refused as a failure — never queued nowhere and reported as queued.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanningStandIn;

#[derive(Debug, thiserror::Error)]
#[error("the scan queue is not composed in this binary yet (task 2.7)")]
struct NoQueue;

impl TargetScans for ScanningStandIn {
    fn latest_per_repository(&self) -> BoxFuture<'_, Result<BTreeMap<i64, LatestScan>, PortError>> {
        Box::pin(async { Ok(BTreeMap::new()) })
    }

    fn latest_per_container(&self) -> BoxFuture<'_, Result<BTreeMap<i64, LatestScan>, PortError>> {
        Box::pin(async { Ok(BTreeMap::new()) })
    }

    fn detected_languages<'a>(
        &'a self,
        _repositories: &'a [i64],
    ) -> BoxFuture<'a, Result<BTreeMap<i64, BTreeSet<String>>, PortError>> {
        Box::pin(async { Ok(BTreeMap::new()) })
    }

    fn queue_repository<'a>(
        &'a self,
        _repository: &'a RepositoryView,
        _not_before: Option<OffsetDateTime>,
    ) -> BoxFuture<'a, Result<Queued, QueueError>> {
        Box::pin(async { Err(QueueError::Failed(Box::new(NoQueue))) })
    }

    fn queue_container<'a>(&'a self, _container: &'a ContainerView) -> BoxFuture<'a, Result<Queued, QueueError>> {
        Box::pin(async { Err(QueueError::Failed(Box::new(NoQueue))) })
    }
}
