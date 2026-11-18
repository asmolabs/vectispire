//! `ScanCatalog`: scans as the other modules read them — views, never rows — and the one place, besides the
//! scheduler, that queues a scan (`trigger.rs`, `ScanTriggerService`).
//!
//! **What Phase 2 reads of it is here**: a scan by identifier, the latest scan per target and the newest languages
//! (`targets`' listings, through `TargetScans`), and what `agents` (2.9) reads of the queue — the waiting scans and
//! their attempts, the counts per claimant and per label. The readings of later phases (inventory's SBOMs, compliance's
//! examinations, checklists' plugin runs, exports' labels and outlines) come with them; `labels_of` is here already,
//! held to `ScanLabelsIntegrationTest`. It needs nothing but the database, so `targets` can be composed over it
//! before the rest of the module exists.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_targets::Clock;
use vectispire_domain::FindingType;
use vectispire_domain::language::Language;

use crate::persistence::{self, LOOKUP_BATCH, LatestRow, StoreError};
use crate::views::{
    BUILT_IN, FindingOnScan, NewestCompletedScanRow, PackageImpact, PluginOutcome, ScanFindingView, ScanSbom, ScanView,
    detected_languages,
};

/// The catalogue, over the database and the clock that stamps a queued scan.
#[derive(Clone)]
pub struct ScanCatalog {
    pub(crate) db: Db,
    pub(crate) clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ScanCatalog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ScanCatalog").field("db", &self.db).finish_non_exhaustive()
    }
}

/// `ScanLabel`: a scan's branch, and the project version its manifest gave — `None` where it read none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanLabel {
    pub branch: String,
    pub version: Option<String>,
}

/// `ScanCatalog.ScanOutline`: a scan as a document describes it. `examined_types` is `None` where the scan did not
/// record it, which is not the empty set; `failures` the failed steps as recorded, `None` when none failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutline {
    pub id: i64,
    pub created_at: OffsetDateTime,
    pub duration_ms: Option<i64>,
    pub examined_types: Option<Vec<vectispire_domain::FindingType>>,
    pub failures: Option<String>,
    pub plugins: Vec<crate::views::PluginOutcome>,
}

/// `ScanCatalog.ScanOfTarget`: a scan as identifier and target columns only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOfTarget {
    pub id: i64,
    pub repo_id: Option<i64>,
    pub container_id: Option<i64>,
}

/// `AttemptedScan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptedScan {
    pub id: i64,
    pub repo_id: i64,
}

/// `WaitingScans`: waiting scans of one repository requiring one label — `None` when they require none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitingScans {
    pub required_label: Option<String>,
    pub repo_id: i64,
    pub scans: i64,
}

/// `ExaminingScanRow`: a repository's newest completed scan in which one built-in step produced — what a checklist's
/// measurement cites as its evidence (decision 0032 §6). Only a scan that **recorded** the type as examined is one: a
/// scan from before `examined_types` never is, whatever it found, because nothing says whether its step ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExaminingScanRow {
    pub repository_id: i64,
    pub scan_id: i64,
    /// When the scan was queued, the instant every other screen dates a scan by.
    pub created_at: OffsetDateTime,
    /// Whether the scan still holds its SBOM — retention may have purged it, and a dependency rule asks.
    pub sbom_stored: bool,
}

/// `ScansWithin`: a repository's completed scans within an age, and how many of them are from before `examined_types`
/// — what tells "every step absent" from "nobody recorded it" when no scan within the age examined a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScansWithin {
    pub repository_id: i64,
    pub completed: i64,
    pub unrecorded: i64,
}

/// `PluginRun`: one plugin's outcome in one completed scan of a repository — `produced`, `not_applicable`, `absent` or
/// `refused`, decision 0017's states kept apart, as [`PluginOutcome::read`] reads them back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginRun {
    pub repository_id: i64,
    pub scan_id: i64,
    pub created_at: OffsetDateTime,
    pub outcome: PluginOutcome,
}

/// `ScanLanguages`: what one scan recorded of languages — those its census found in the tree, and those the Semgrep
/// rules of its task read. **`None` is "the scan recorded none", never the empty set** (decision 0007): reading it as
/// empty would tell a checklist that a Java tree holds no Java, or that its static analysis read nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedLanguages {
    pub detected: Option<BTreeSet<Language>>,
    pub sast_rules: Option<BTreeSet<Language>>,
}

/// A request no caller should make — Java's `UnsupportedOperationException`: a type no built-in step examines, or a
/// plugin id a `like` pattern would read as a wildcard. A defect of the code, never of a user's input.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Unsupported(pub String);

impl ScanCatalog {
    pub fn new(db: Db, clock: Arc<dyn Clock>) -> ScanCatalog {
        ScanCatalog { db, clock }
    }

    async fn read<T>(
        &self,
        statement: impl AsyncFnOnce(&mut vectispire_cp_db::Tx) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut tx = persistence::read(&self.db).await?;
        let answer = statement(&mut tx).await;
        tx.commit().await?;
        answer
    }

    pub async fn scan(&self, id: i64) -> Result<Option<ScanView>, StoreError> {
        Ok(self.read(async |tx| persistence::scan(tx, id).await).await?.map(ScanView::from))
    }

    /// Each repository's newest scan, by the highest identifier.
    pub async fn latest_per_repository(&self) -> Result<Vec<LatestRow>, StoreError> {
        self.read(async |tx| persistence::latest_per_repository(tx).await).await
    }

    pub async fn latest_per_container(&self) -> Result<Vec<LatestRow>, StoreError> {
        self.read(async |tx| persistence::latest_per_container(tx).await).await
    }

    /// Each repository's newest scan that is no longer in flight; a repository with none is absent.
    pub async fn latest_finished_per_repository(&self) -> Result<Vec<LatestRow>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::latest_finished_per_repository(tx).await).await
    }

    /// The container half of `latest_finished_per_repository`.
    pub async fn latest_finished_per_container(&self) -> Result<Vec<LatestRow>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::latest_finished_per_container(tx).await).await
    }

    /// One target's newest scan that is no longer in flight — completed or failed — or None when none
    /// has finished: never scanned, or every scan still pending or running.
    pub async fn latest_finished(&self, target: ScanTarget) -> Result<Option<LatestRow>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::latest_finished_of_target(tx, target).await).await
    }

    /// `newestDetectedLanguages`: the languages each of these repositories' newest **completed** scan found. **A
    /// repository missing from the answer is unknown** — no completed scan, or one that recorded no whole census —
    /// never an older scan's languages in its place: the newest completed scan is what the repository is now.
    pub async fn newest_detected_languages(
        &self,
        repositories: &[i64],
    ) -> Result<BTreeMap<i64, Vec<&'static str>>, StoreError> {
        let mut detected = BTreeMap::new();
        for batch in repositories.chunks(LOOKUP_BATCH) {
            let rows =
                self.read(async |tx| persistence::newest_detected_languages(tx, batch, "completed").await).await?;
            for (repository, column) in rows {
                if let Some(languages) = detected_languages::read(column.as_deref()) {
                    detected.insert(repository, languages);
                }
            }
        }
        Ok(detected)
    }

    /// `labelsOf`: each existing scan's label, a thousand identifiers per statement — a list sized by the data.
    pub async fn labels_of(&self, ids: &[i64]) -> Result<BTreeMap<i64, ScanLabel>, StoreError> {
        let rows = self.read(async |tx| persistence::labels_of(tx, ids).await).await?;
        Ok(rows.into_iter().map(|(id, branch, version)| (id, ScanLabel { branch, version })).collect())
    }

    /// `outlinesOf`: each of these scans' outline, by id; a scan that does not exist is absent. A thousand
    /// identifiers per statement. **A `null` plugin outcome fails the read**, as Java's `List.copyOf` does past
    /// `PluginOutcome.read`'s catch.
    pub async fn outlines_of(&self, ids: &[i64]) -> Result<BTreeMap<i64, ScanOutline>, StoreError> {
        let mut outlines = BTreeMap::new();
        for batch in distinct(ids).chunks(LOOKUP_BATCH) {
            let rows = self.read(async |tx| persistence::catalog_queries::outlines_of(tx, batch).await).await?;
            for row in rows {
                let plugins = crate::views::PluginOutcome::read(row.plugin_steps.as_deref())
                    .map_err(|refused| StoreError(Box::new(refused)))?;
                outlines.insert(
                    row.id,
                    ScanOutline {
                        id: row.id,
                        created_at: row.created_at,
                        duration_ms: row.duration_ms,
                        examined_types: crate::views::examined_types::read(row.examined_types.as_deref()),
                        failures: row.error,
                        plugins,
                    },
                );
            }
        }
        Ok(outlines)
    }

    /// `withStatusNewestFirst`: scans with this status, newest first, as identifier and target only.
    pub async fn with_status_newest_first(&self, status: &str) -> Result<Vec<ScanOfTarget>, StoreError> {
        let rows =
            self.read(async |tx| persistence::catalog_queries::ids_and_targets_newest_first(tx, status).await).await?;
        Ok(rows
            .into_iter()
            .map(|row| ScanOfTarget { id: row.id, repo_id: row.repo_id, container_id: row.container_id })
            .collect())
    }

    /// `waitingWithAttempts`: the waiting scans of repositories that were counted at least one attempt.
    pub async fn waiting_with_attempts(&self) -> Result<Vec<AttemptedScan>, StoreError> {
        Ok(self
            .read(async |tx| persistence::attempted_repository_scans(tx, "pending").await)
            .await?
            .into_iter()
            .map(|(id, repo_id)| AttemptedScan { id, repo_id })
            .collect())
    }

    /// `refundAttempts`: these waiting scans given their attempts back — **the catalogue's one write**, on `agents`'
    /// behalf (the withheld claims' repair, 2.9). A scan claimed since it was read is left as it is.
    pub async fn refund_attempts(&self, ids: &[i64]) -> Result<u64, StoreError> {
        let distinct: Vec<i64> = ids.iter().copied().collect::<BTreeSet<i64>>().into_iter().collect();
        let mut tx = persistence::write(&self.db).await?;
        let mut changed: u64 = 0;
        for batch in distinct.chunks(LOOKUP_BATCH) {
            match persistence::reset_attempts(&mut tx, batch, "pending").await {
                Ok(rows) => changed = changed.saturating_add(rows),
                Err(failure) => {
                    let _ = tx.rollback().await;
                    return Err(failure);
                }
            }
        }
        tx.commit().await?;
        Ok(changed)
    }

    /// `waitingRepositories`: the waiting scans of repositories, per required label and repository.
    pub async fn waiting_repositories(&self) -> Result<Vec<WaitingScans>, StoreError> {
        Ok(self
            .read(async |tx| persistence::waiting_by_label_and_repository(tx, "pending").await)
            .await?
            .into_iter()
            .map(|(required_label, repo_id, scans)| WaitingScans { required_label, repo_id, scans })
            .collect())
    }

    /// `countByClaimant`: running scans per claimant.
    pub async fn count_by_claimant(&self, status: &str) -> Result<BTreeMap<String, i64>, StoreError> {
        Ok(self.read(async |tx| persistence::count_by_claimant(tx, status).await).await?.into_iter().collect())
    }

    /// `countByRequiredLabel`.
    pub async fn count_by_required_label(&self, status: &str) -> Result<BTreeMap<String, i64>, StoreError> {
        Ok(self.read(async |tx| persistence::count_by_required_label(tx, status).await).await?.into_iter().collect())
    }

    /// `countWithStatusClaimedBy`: a lapsed lease counted too.
    pub async fn count_claimed_by(&self, status: &str, claimant: &str) -> Result<i64, StoreError> {
        self.read(async |tx| persistence::count_claimed_by(tx, status, claimant).await).await
    }

    /// `withStatusOldestFirst`, for the two statuses the agents' screen lists.
    pub async fn with_status_oldest_first(&self, statuses: [&str; 2]) -> Result<Vec<ScanView>, StoreError> {
        Ok(self
            .read(async |tx| persistence::with_status_oldest_first(tx, statuses).await)
            .await?
            .into_iter()
            .map(ScanView::from)
            .collect())
    }

    /// `countWithStatusSince`: created strictly after `after`.
    pub async fn count_since(&self, status: &str, after: OffsetDateTime) -> Result<i64, StoreError> {
        self.read(async |tx| persistence::count_since(tx, status, after).await).await
    }

    /// `averageDurationMsSince`: `None` when no such scan recorded a duration.
    pub async fn average_duration_since(&self, status: &str, after: OffsetDateTime) -> Result<Option<f64>, StoreError> {
        self.read(async |tx| persistence::average_duration_since(tx, status, after).await).await
    }

    /// Every scan's `ScanSbom`, in no order.
    pub async fn sboms(&self) -> Result<Vec<ScanSbom>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::sboms_of_all(tx).await).await
    }

    /// The `ScanSbom` of every scan attached to no target.
    pub async fn sboms_of_untargeted(&self) -> Result<Vec<ScanSbom>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::sboms_of_untargeted(tx).await).await
    }

    /// The `ScanSbom` of every scan naming one of these targets.
    pub async fn sboms_of_targets(&self, targets: &[ScanTarget]) -> Result<Vec<ScanSbom>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::sboms_of_targets(tx, targets).await).await
    }

    /// Each of these targets' newest completed scan, and whether it still holds its SBOM.
    pub async fn newest_completed(
        &self,
        targets: &[ScanTarget],
    ) -> Result<BTreeMap<ScanTarget, NewestCompletedScanRow>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::newest_completed(tx, targets).await).await
    }

    /// The identifiers of a target's most recent scans, newest first.
    pub async fn recent_ids(&self, target: ScanTarget, limit: usize) -> Result<Vec<i64>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::recent_ids(tx, target, limit).await).await
    }

    /// The findings of one scan.
    pub async fn findings(&self, scan_id: i64) -> Result<Vec<ScanFindingView>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::findings(tx, scan_id).await).await
    }

    /// The license findings of these scans.
    pub async fn license_findings(&self, scan_ids: &[i64]) -> Result<Vec<ScanFindingView>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::license_findings(tx, scan_ids).await).await
    }

    /// Aggregated package impacts across targets the caller may see.
    pub async fn package_impacts(&self, allowed: &Visibility) -> Result<Vec<PackageImpact>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::package_impacts(tx, allowed).await).await
    }

    /// Findings that match a query for dependency graph and blast radius.
    pub async fn findings_for_graph(
        &self,
        query: &str,
        is_cve_query: bool,
        exclude_secrets: bool,
        allowed: &Visibility,
    ) -> Result<Vec<FindingOnScan>, StoreError> {
        let rows = self
            .read(async |tx| {
                persistence::catalog_queries::findings_for_graph(tx, query, is_cve_query, exclude_secrets, allowed)
                    .await
            })
            .await?;
        Ok(rows.into_iter().map(FindingOnScan::from).collect())
    }

    /// The SBOM document of one scan by identifier.
    pub async fn sbom(&self, id: i64) -> Result<Option<String>, StoreError> {
        Ok(self.read(async |tx| persistence::sbom(tx, id).await).await?.flatten())
    }

    /// Up to `limit` scans holding an SBOM strictly older than `before`, newest first.
    pub async fn ids_with_sbom_before(&self, before: i64, limit: i64) -> Result<Vec<i64>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::ids_with_sbom_before(tx, before, limit).await).await
    }

    /// Each repository's newest scan instant — a repository never scanned is absent.
    pub async fn last_scan_at_per_repository(&self) -> Result<BTreeMap<i64, OffsetDateTime>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::last_scan_at_per_repository(tx).await).await
    }

    /// `history(null, null, limit)` and `recentWithin`: the newest `limit` scans `allowed` permits, newest first. A
    /// restricted reader's targets are asked [`LOOKUP_BATCH`] at a time, repositories and images apart, the newest of
    /// each batch kept — the newest of a union are among the newest of each of its parts — and a scan naming a
    /// repository is its repository's, so an image granted does not let through a scan of a repository that is not.
    pub async fn recent(&self, allowed: &Visibility, limit: usize) -> Result<Vec<ScanView>, StoreError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = match allowed {
            Visibility::Everything => {
                self.read(async |tx| persistence::history_page(tx, None, None, limit, 0).await).await?
            }
            Visibility::Only(targets) => {
                let repositories: Vec<i64> = targets
                    .iter()
                    .filter_map(|target| match target {
                        ScanTarget::Repository(id) => Some(*id),
                        ScanTarget::Container(_) => None,
                    })
                    .collect();
                let containers: Vec<i64> = targets
                    .iter()
                    .filter_map(|target| match target {
                        ScanTarget::Container(id) => Some(*id),
                        ScanTarget::Repository(_) => None,
                    })
                    .collect();
                // `in ()` is not valid everywhere: the other column is asked for an id no identity column hands out.
                let none = [-1i64];
                let mut candidates = Vec::new();
                for batch in repositories.chunks(LOOKUP_BATCH) {
                    candidates.extend(
                        self.read(async |tx| persistence::history_within(tx, None, None, batch, &none, limit, 0).await)
                            .await?,
                    );
                }
                for batch in containers.chunks(LOOKUP_BATCH) {
                    candidates.extend(
                        self.read(async |tx| persistence::history_within(tx, None, None, &none, batch, limit, 0).await)
                            .await?,
                    );
                }
                candidates.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| b.id.cmp(&a.id)));
                candidates.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
                candidates
            }
        };
        Ok(rows.into_iter().map(ScanView::from).collect())
    }

    /// `targetsWithStatus`: each target holding a scan in this status, once — a scan naming a repository is its
    /// repository's, one naming neither is unclassifiable and left out.
    pub async fn targets_with_status(&self, status: &str) -> Result<Vec<ScanTarget>, StoreError> {
        let rows = self.read(async |tx| persistence::catalog_queries::targets_with_status(tx, status).await).await?;
        Ok(rows
            .into_iter()
            .filter_map(|(repository, container)| match (repository, container) {
                (Some(id), _) => Some(ScanTarget::Repository(id)),
                (None, Some(id)) => Some(ScanTarget::Container(id)),
                (None, None) => None,
            })
            .collect())
    }

    /// Whether the target holds a scan with this status, ignoring case.
    pub async fn has_scan_with_status(&self, target: ScanTarget, status: &str) -> Result<bool, StoreError> {
        self.read(async |tx| persistence::catalog_queries::has_scan_with_status(tx, target, status).await).await
    }

    /// Scans of one repository, newest first.
    pub async fn history(&self, repo_id: i64, branch: Option<&str>, limit: usize) -> Result<Vec<ScanView>, StoreError> {
        Ok(self
            .read(async |tx| persistence::catalog_queries::history_of_repository(tx, repo_id, branch, limit).await)
            .await?
            .into_iter()
            .map(ScanView::from)
            .collect())
    }

    /// The findings of several scans at once.
    pub async fn findings_of_scans(&self, scan_ids: &[i64]) -> Result<Vec<ScanFindingView>, StoreError> {
        self.read(async |tx| persistence::catalog_queries::findings_of_scans(tx, scan_ids).await).await
    }

    /// Where one issue was observed, newest scan first.
    pub async fn sightings(&self, issue_id: i64, limit: usize) -> Result<Vec<FindingOnScan>, StoreError> {
        Ok(self
            .read(async |tx| persistence::catalog_queries::sightings_of_issue(tx, issue_id, limit).await)
            .await?
            .into_iter()
            .map(FindingOnScan::from)
            .collect())
    }
    // ── what a checklist measures (decision 0032 §6) ─────────────────────────────────────────

    /// `newestExamining`: each of these repositories' newest **completed** scan created at or after `since` that
    /// recorded `kind` as examined. **A repository missing from the answer has no such scan** — never scanned for it in
    /// that time, every step absent, or only scans from before `examined_types` — and must not be read as "examined,
    /// and clean"; [`ScanCatalog::completed_within`] tells those apart.
    ///
    /// **Built-in types only**: a plugin's states live in `plugin_steps` and an import is its own row, neither ever in
    /// `examined_types`, so asking for one would answer "never examined" everywhere. Refused instead ([`Unsupported`]).
    pub async fn newest_examining(
        &self,
        repository_ids: &[i64],
        kind: FindingType,
        since: OffsetDateTime,
    ) -> Result<BTreeMap<i64, ExaminingScanRow>, StoreError> {
        if !BUILT_IN.contains(&kind) {
            return Err(StoreError(Box::new(Unsupported(format!(
                "No built-in step examines {}; its outcomes are not in examined_types.",
                kind.wire_name()
            )))));
        }
        // `ExaminedTypes.pattern`: no built-in wire name holds `%` or `_`, so nothing needs escaping.
        let pattern = format!("%,{},%", kind.wire_name());
        let repositories = distinct(repository_ids);
        let rows = self
            .read(async |tx| persistence::newest_examining(tx, &repositories, "completed", since, &pattern).await)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(repository_id, scan_id, created_at, sbom_stored)| {
                (repository_id, ExaminingScanRow { repository_id, scan_id, created_at, sbom_stored })
            })
            .collect())
    }

    /// `completedWithin`: each of these repositories' completed scans created at or after `since`, counted, the
    /// unrecorded among them apart. A repository with none is absent.
    pub async fn completed_within(
        &self,
        repository_ids: &[i64],
        since: OffsetDateTime,
    ) -> Result<BTreeMap<i64, ScansWithin>, StoreError> {
        let repositories = distinct(repository_ids);
        let rows = self.read(async |tx| persistence::count_within(tx, &repositories, "completed", since).await).await?;
        Ok(rows
            .into_iter()
            .map(|(repository_id, completed, unrecorded)| {
                (repository_id, ScansWithin { repository_id, completed, unrecorded })
            })
            .collect())
    }

    /// `pluginRunsWithin`: each of these repositories' completed scans created at or after `since` that name the
    /// plugin, with its outcome in each, newest first. A repository whose scans within the age never name it is
    /// absent: they ran without it, which the reader counts as absent (with [`ScanCatalog::completed_within`]), never
    /// as clean.
    ///
    /// **Read from the scan's own record**, `plugin_steps`: the statement narrows by the id in the column's text, and
    /// the outcome is then read back as the scan's page reads it, so a row the text matched by accident — the id inside
    /// another field — names no outcome and is left out.
    pub async fn plugin_runs_within(
        &self,
        repository_ids: &[i64],
        plugin_id: &str,
        since: OffsetDateTime,
    ) -> Result<BTreeMap<i64, Vec<PluginRun>>, StoreError> {
        let pattern = plugin_pattern(plugin_id)?;
        let repositories = distinct(repository_ids);
        let rows = self
            .read(async |tx| persistence::naming_plugin_within(tx, &repositories, "completed", since, &pattern).await)
            .await?;
        let mut runs: BTreeMap<i64, Vec<PluginRun>> = BTreeMap::new();
        for (repository_id, scan_id, created_at, column) in rows {
            // A `null` element is Java's `NullPointerException` past the parser's catch: the measurement fails, as
            // the scan's own page does, rather than reading the column as no outcome.
            let outcomes = PluginOutcome::read(column.as_deref()).map_err(|null| StoreError(Box::new(null)))?;
            if let Some(outcome) = outcomes.into_iter().find(|outcome| outcome.plugin_id.as_deref() == Some(plugin_id))
            {
                runs.entry(repository_id).or_default().push(PluginRun { repository_id, scan_id, created_at, outcome });
            }
        }
        Ok(runs)
    }

    /// `namingPluginBefore`: those of these repositories with a completed scan created strictly before `before` that
    /// names the plugin.
    pub async fn naming_plugin_before(
        &self,
        repository_ids: &[i64],
        plugin_id: &str,
        before: OffsetDateTime,
    ) -> Result<BTreeSet<i64>, StoreError> {
        let pattern = plugin_pattern(plugin_id)?;
        let repositories = distinct(repository_ids);
        let rows = self
            .read(async |tx| persistence::naming_plugin_before(tx, &repositories, "completed", before, &pattern).await)
            .await?;
        Ok(rows.into_iter().collect())
    }

    /// `languagesOf`: each of these scans' languages — what a checklist compares, on the very scan a measurement rests
    /// on, to tell a tree its static analysis read from one it did not (decision 0032 §6). A scan that does not exist
    /// is absent.
    pub async fn languages_of(&self, scan_ids: &[i64]) -> Result<BTreeMap<i64, RecordedLanguages>, StoreError> {
        let ids = distinct(scan_ids);
        let rows = self.read(async |tx| persistence::languages_of(tx, &ids).await).await?;
        Ok(rows
            .into_iter()
            .map(|(id, detected, sast_rules)| {
                (
                    id,
                    RecordedLanguages {
                        detected: recorded_languages(detected.as_deref()),
                        sast_rules: recorded_languages(sast_rules.as_deref()),
                    },
                )
            })
            .collect())
    }
}

/// `pluginPattern`: `%"pluginId":"<id>"%`, the id closed by its quote so that `java` never matches `java-arch`.
/// Refused for anything but an id's characters: a `%` or `_` would be a wildcard, and a quote would end the field.
fn plugin_pattern(plugin_id: &str) -> Result<String, StoreError> {
    let is_id = !plugin_id.is_empty()
        && plugin_id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !is_id {
        return Err(StoreError(Box::new(Unsupported(format!("Not a plugin id: {plugin_id}")))));
    }
    Ok(format!("%\"pluginId\":\"{plugin_id}\"%"))
}

/// `DetectedLanguages.read`: comma-separated wire names, **each trimmed and read as the column's own reader reads it**;
/// a name this version does not know is left out, and a column that is `null` stays `None` — unknown, never the empty
/// set. Compliance and checklists each ported this read, one trimming and one not; this is the one left.
fn recorded_languages(column: Option<&str>) -> Option<BTreeSet<Language>> {
    detected_languages::read(column).map(|names| names.into_iter().filter_map(Language::from_wire_name).collect())
}

/// The identifiers once each, in the order first given — Java's `batches` over a `LinkedHashSet`.
fn distinct(ids: &[i64]) -> Vec<i64> {
    let mut seen = BTreeSet::new();
    ids.iter().copied().filter(|id| seen.insert(*id)).collect()
}
