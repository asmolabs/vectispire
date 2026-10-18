//! Reading scans — `ScanQueryService`: the history, one scan's detail, its SBOM — each **within an allowance**, applied
//! in the query, a refusal answered as the absence it must look like (`Scan not found.`, the same for both).
//!
//! **The detail is the scan's findings, not the target's backlog**: the backlog carries history, an issue seen three
//! scans ago and still open; a scan reports what it observed that day.

use vectispire_cp_access::rows;
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_targets::naming::{self, Names};
use vectispire_domain::list_window::ListWindow;

use crate::Scanning;
use crate::error::ScanError;
use crate::persistence::{self, FindingRow, LOOKUP_BATCH, ScanRow, StoreError};
use crate::views::ScanView;

/// The detail's findings: a scan of a thousand findings shows five hundred, and says so.
pub const MAX_FINDINGS: i64 = 500;
/// The history's limit is clamped to this, as it always was; only the offset is refused.
pub const MAX_HISTORY: i32 = 200;
/// How deep a history read in several statements reaches: `offset + limit`, at most.
pub const MAX_MERGED_DEPTH: i64 = 10_000;

/// `SBOM` absent: a 404 and never an empty document — a scan that failed before the inventory has none, and an empty
/// one would claim it inventoried nothing.
pub const NO_SBOM: &str = "This scan produced no SBOM.";

/// A page of the history, and the names of the targets it shows.
#[derive(Debug, Clone)]
pub struct History {
    pub scans: Vec<ScanView>,
    pub names: Names,
}

/// One scan, its names, its findings and how many it recorded — which may exceed the findings carried.
#[derive(Debug, Clone)]
pub struct Detail {
    pub scan: ScanView,
    pub names: Names,
    pub findings: Vec<FindingRow>,
    pub findings_total: i64,
}

impl Detail {
    pub fn findings_truncated(&self) -> bool {
        self.findings_total > i64::try_from(self.findings.len()).unwrap_or(i64::MAX)
    }
}

impl Scanning {
    /// `history`: the scans `allowed` permits, newest first, optionally narrowed to one target — `limit` clamped to 1
    /// to 200, from the `offset`-th. **The allowance is in the query, and the page cut after it**: read for the estate
    /// and filtered afterwards, a restricted reader was shown whatever share of the latest scans happened to be theirs.
    pub async fn history(
        &self,
        allowed: &Visibility,
        repo: Option<i64>,
        container: Option<i64>,
        limit: i32,
        offset: Option<i32>,
    ) -> Result<History, ScanError> {
        let window = ListWindow::new(i64::from(limit.clamp(1, MAX_HISTORY)), i64::from(offset.unwrap_or(0)))
            .map_err(ScanError::Invalid)?;
        let names = naming::all(&self.db).await.map_err(ScanError::unexpected)?;
        let rows = match allowed {
            Visibility::Everything => {
                let mut tx = persistence::read(&self.db).await?;
                let rows = persistence::history_page(&mut tx, repo, container, window.limit, window.offset).await;
                tx.commit().await.map_err(StoreError::from)?;
                rows?
            }
            Visibility::Only(targets) => self.within(targets, repo, container, window).await?,
        };
        Ok(History { scans: rows.into_iter().map(ScanView::from).collect(), names })
    }

    /// One page of a restricted reader's history, the allowance bound into the statement **a thousand targets at a
    /// time**: one statement — the common case — pages in the database; several each read their newest `offset +
    /// limit`, which hold the union's, and the page is cut from those merged in the query's order. **Several reach
    /// [`MAX_MERGED_DEPTH`] deep and no deeper**: a deep offset otherwise loaded the history of every batch for one page.
    async fn within(
        &self,
        targets: &std::collections::BTreeSet<ScanTarget>,
        repo: Option<i64>,
        container: Option<i64>,
        window: ListWindow,
    ) -> Result<Vec<ScanRow>, ScanError> {
        let repositories: Vec<i64> = targets
            .iter()
            .filter_map(|target| match target {
                ScanTarget::Repository(id) => Some(*id),
                ScanTarget::Container(_) => None,
            })
            .collect();
        let images: Vec<i64> = targets
            .iter()
            .filter_map(|target| match target {
                ScanTarget::Container(id) => Some(*id),
                ScanTarget::Repository(_) => None,
            })
            .collect();
        let statements = batches(repositories.len()).max(batches(images.len()));
        if statements == 0 {
            return Ok(Vec::new());
        }
        let mut tx = persistence::read(&self.db).await?;
        let read = async {
            if statements == 1 {
                return persistence::history_within(
                    &mut tx,
                    repo,
                    container,
                    &batch(&repositories, 0),
                    &batch(&images, 0),
                    window.limit,
                    window.offset,
                )
                .await
                .map_err(ScanError::from);
            }
            if window.offset.saturating_add(window.limit) > MAX_MERGED_DEPTH {
                return Err(ScanError::Invalid(format!(
                    "For a reader of more than {LOOKUP_BATCH} targets, the history reaches {MAX_MERGED_DEPTH} scans \
                     deep: offset plus limit is {MAX_MERGED_DEPTH} at most."
                )));
            }
            let head = window.offset.saturating_add(window.limit);
            let mut candidates = Vec::new();
            for statement in 0..statements {
                candidates.extend(
                    persistence::history_within(
                        &mut tx,
                        repo,
                        container,
                        &batch(&repositories, statement),
                        &batch(&images, statement),
                        head,
                        0,
                    )
                    .await?,
                );
            }
            candidates.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(b.id.cmp(&a.id)));
            Ok(window.of(&candidates))
        }
        .await;
        tx.commit().await.map_err(StoreError::from)?;
        read
    }

    /// `detail`: the scan, or the same 404 whether it is absent or hidden.
    pub async fn detail(&self, id: i64, allowed: &Visibility) -> Result<Detail, ScanError> {
        let mut tx = persistence::read(&self.db).await?;
        let read = async {
            let scan = visible(persistence::scan(&mut tx, id).await?, allowed)?;
            let findings = persistence::findings_of_scan(&mut tx, id, MAX_FINDINGS).await?;
            let total = persistence::count_findings_of_scan(&mut tx, id).await?;
            Ok::<_, ScanError>((scan, findings, total))
        }
        .await;
        tx.commit().await.map_err(StoreError::from)?;
        let (scan, findings, findings_total) = read?;
        let names = naming::all(&self.db).await.map_err(ScanError::unexpected)?;
        Ok(Detail { scan, names, findings, findings_total })
    }

    /// `sbom`: the document as the cataloguer wrote it, served verbatim — re-serialized it would no longer be the bytes
    /// the cataloguer signed off.
    pub async fn sbom(&self, id: i64, allowed: &Visibility) -> Result<String, ScanError> {
        let mut tx = persistence::read(&self.db).await?;
        let read = async {
            visible(persistence::scan(&mut tx, id).await?, allowed)?;
            Ok::<_, ScanError>(persistence::sbom(&mut tx, id).await?.flatten())
        }
        .await;
        tx.commit().await.map_err(StoreError::from)?;
        read?.ok_or_else(|| ScanError::NotFound(NO_SBOM.to_owned()))
    }
}

/// `RowVisibility.requireVisibleScan`: one sentence for absent and hidden alike — ids are sequential, and two wordings
/// would let a restricted reader enumerate every scan.
fn visible(row: Option<ScanRow>, allowed: &Visibility) -> Result<ScanView, ScanError> {
    let scan = row.map(ScanView::from);
    Ok(rows::require_visible_scan(scan, ScanView::target, allowed)?)
}

fn batches(size: usize) -> usize {
    size.div_ceil(LOOKUP_BATCH)
}

/// The `index`-th batch, or an identifier no identity column hands out — what Java binds for an empty batch, kept so
/// that each statement is the same statement.
fn batch(ids: &[i64], index: usize) -> Vec<i64> {
    let from = index.saturating_mul(LOOKUP_BATCH);
    if from < ids.len() { ids[from..ids.len().min(from + LOOKUP_BATCH)].to_vec() } else { vec![-1] }
}
