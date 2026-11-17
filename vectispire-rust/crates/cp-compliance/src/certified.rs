//! The certified scope — Java's `CertifiedScopeService`: which targets the ISMS certification covers, how many assets
//! its statement declares, and how many of those carry current evidence.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;
use time::{Duration, OffsetDateTime};
use vectispire_cp_access::rows::require_visible;
use vectispire_cp_audit::{AuditLog, AuditOperation, RequestActor};
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_scanning::ScanCatalog;
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_targets::catalog::ScopeChange;
use vectispire_cp_targets::{Clock, Targets};

use crate::decisions::ScopeCoverage;
use crate::error::ComplianceError;

/// What a freshness window of zero or less falls back to.
const DEFAULT_FRESHNESS_DAYS: i32 = 30;
const TARGET_NOT_FOUND: &str = "Target not found.";

/// `ScopeView`: the statement, its coverage and the targets marked in scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeView {
    pub statement: String,
    pub coverage: ScopeCoverage,
    pub targets: Vec<TargetRef>,
}

/// Which kind of target a membership route names: the repository's route or the image's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Repository,
    Container,
}

/// `TargetRef`: `REPOSITORY` or `CONTAINER`, and its identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetRef {
    pub kind: &'static str,
    pub id: i64,
}

#[derive(Clone)]
pub struct CertifiedScopeService {
    targets: Arc<Targets>,
    scans: Arc<ScanCatalog>,
    settings: Settings,
    clock: Arc<dyn Clock>,
    audit: Arc<AuditLog>,
}

impl std::fmt::Debug for CertifiedScopeService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("CertifiedScopeService").finish_non_exhaustive()
    }
}

impl CertifiedScopeService {
    pub fn new(
        targets: Arc<Targets>,
        scans: Arc<ScanCatalog>,
        settings: Settings,
        clock: Arc<dyn Clock>,
        audit: Arc<AuditLog>,
    ) -> CertifiedScopeService {
        CertifiedScopeService { targets, scans, settings, clock, audit }
    }

    /// The controller's `scope`: the statement, the coverage and the targets, each over the caller's view.
    pub async fn view(&self, allowed: &Visibility) -> Result<ScopeView, ComplianceError> {
        let statement = self.settings.get(Setting::IsmsScopeStatement).await.map_err(ComplianceError::unexpected)?;
        let in_scope = self.in_scope(allowed).await?;
        let coverage = self.coverage_of(&in_scope).await?;
        let targets = in_scope
            .iter()
            .map(|target| match *target {
                ScanTarget::Repository(id) => TargetRef { kind: "REPOSITORY", id },
                ScanTarget::Container(id) => TargetRef { kind: "CONTAINER", id },
            })
            .collect();
        Ok(ScopeView { statement, coverage, targets })
    }

    /// `inScope`: repositories then images, in the catalogue's order, those marked in scope that the caller sees.
    pub async fn in_scope(&self, allowed: &Visibility) -> Result<Vec<ScanTarget>, ComplianceError> {
        let repositories = self.targets.catalog_repositories().await.map_err(ComplianceError::unexpected)?;
        let containers = self.targets.catalog_containers().await.map_err(ComplianceError::unexpected)?;
        Ok(repositories
            .iter()
            .filter(|row| row.in_certified_scope)
            .map(|row| ScanTarget::Repository(row.id))
            .chain(containers.iter().filter(|row| row.in_certified_scope).map(|row| ScanTarget::Container(row.id)))
            .filter(|target| allowed.permits(*target))
            .collect())
    }

    /// `coverage`: each target in scope never scanned, scanned before the freshness cutoff, or since — the latest scan
    /// of any status. `declaredAssets` is the statement's own count, never narrowed.
    async fn coverage_of(&self, in_scope: &[ScanTarget]) -> Result<ScopeCoverage, ComplianceError> {
        let mut last: BTreeMap<ScanTarget, OffsetDateTime> = BTreeMap::new();
        for row in self.scans.latest_per_repository().await.map_err(ComplianceError::unexpected)? {
            keep_newest(&mut last, ScanTarget::Repository(row.target_id), row.created_at);
        }
        for row in self.scans.latest_per_container().await.map_err(ComplianceError::unexpected)? {
            keep_newest(&mut last, ScanTarget::Container(row.target_id), row.created_at);
        }
        let configured =
            self.settings.as_int(Setting::ComplianceFreshnessDays).await.map_err(ComplianceError::unexpected)?;
        let days = if configured > 0 { configured } else { DEFAULT_FRESHNESS_DAYS };
        let cutoff = self.clock.now().checked_sub(Duration::days(i64::from(days)));

        let (mut fresh, mut stale, mut never) = (0i32, 0i32, 0i32);
        for target in in_scope {
            match last.get(target) {
                None => never = never.saturating_add(1),
                Some(at) if cutoff.is_some_and(|cutoff| *at < cutoff) => stale = stale.saturating_add(1),
                Some(_) => fresh = fresh.saturating_add(1),
            }
        }
        let declared = self.settings.as_int(Setting::IsmsScopeAssets).await.map_err(ComplianceError::unexpected)?;
        Ok(ScopeCoverage {
            declared_assets: declared.max(0),
            in_scope: i32::try_from(in_scope.len()).unwrap_or(i32::MAX),
            scanned_recently: fresh,
            stale,
            never_scanned: never,
        })
    }

    /// `setInScope`: refused as absent before anything is read when the caller cannot see the target, and as absent
    /// when it does not exist. **An unchanged membership writes no audit entry**, by design.
    pub async fn set_in_scope(
        &self,
        kind: TargetKind,
        id: i64,
        allowed: &Visibility,
        in_scope: bool,
        actor: &RequestActor,
    ) -> Result<bool, ComplianceError> {
        let target = match kind {
            TargetKind::Repository => ScanTarget::Repository(id),
            TargetKind::Container => ScanTarget::Container(id),
        };
        require_visible(target, allowed).map_err(|_| ComplianceError::NotFound(TARGET_NOT_FOUND.to_owned()))?;
        let outcome =
            self.targets.set_in_certified_scope(target, in_scope).await.map_err(ComplianceError::unexpected)?;
        match outcome {
            ScopeChange::Absent => Err(ComplianceError::NotFound(TARGET_NOT_FOUND.to_owned())),
            ScopeChange::Unchanged => Ok(false),
            ScopeChange::Changed => {
                let (id, named) = match target {
                    ScanTarget::Repository(id) => (id, format!("Repository {id}")),
                    ScanTarget::Container(id) => (id, format!("Image {id}")),
                };
                let change = if in_scope { " put in the certified scope" } else { " taken out of the certified scope" };
                self.audit
                    .record(actor.entry(AuditOperation::CertifiedScopeChanged, &id.to_string(), &(named + change)))
                    .await;
                Ok(true)
            }
        }
    }
}

/// Two rows of one target keep the later — Java's `merge` with `isAfter`.
fn keep_newest(into: &mut BTreeMap<ScanTarget, OffsetDateTime>, target: ScanTarget, at: OffsetDateTime) {
    into.entry(target).and_modify(|kept| *kept = (*kept).max(at)).or_insert(at);
}
