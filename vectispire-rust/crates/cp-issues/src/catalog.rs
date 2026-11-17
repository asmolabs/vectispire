//! `IssueCatalog`: issues as other modules read them.

use std::collections::BTreeSet;

use vectispire_cp_db::Db;
use vectispire_domain::triage_status::TriageStatus;

use crate::error::IssueError;
use crate::persistence::IssueFilters;
use crate::persistence::IssueRepository;
use crate::persistence::StoreError;
use crate::persistence::checked::{self, UnsettledScope};
use crate::views::IssueView;

/// How many repositories one count binds — Java's `FLAG_BATCH`: a project's repositories are sized by the data.
const FLAG_BATCH: usize = 1_000;

/// `ScopeCount`: issues of one repository, severity and state in one scope — the rows a checklist's figures add up.
/// Every state is answered as stored; the reader counts one it does not know as open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeCount {
    pub repository_id: i64,
    pub severity: Option<String>,
    pub state: String,
    pub count: i64,
}

#[derive(Clone)]
pub struct IssueCatalog {
    db: Db,
}

impl IssueCatalog {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn count(&self, filters: &IssueFilters) -> Result<i64, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let total = IssueRepository::count_issues(&mut tx, filters).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;
        Ok(total)
    }

    pub async fn issues(&self, filters: &IssueFilters) -> Result<Vec<IssueView>, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let (rows, _) = IssueRepository::page_issues(&mut tx, filters, 10_000, 0).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;
        Ok(rows.into_iter().map(|r| r.to_view()).collect())
    }

    pub async fn find_by_id(&self, id: i64) -> Result<Option<IssueView>, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let row = IssueRepository::find_by_id(&mut tx, id).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;
        Ok(row.map(|r| r.to_view()))
    }

    pub async fn find_by_ids(&self, ids: &[i64]) -> Result<Vec<IssueView>, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let rows = IssueRepository::find_by_ids(&mut tx, ids).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;
        Ok(rows.into_iter().map(|r| r.to_view()).collect())
    }

    /// The issues in `state` of one target, as the gate weighs them — see `IssueRepository::find_by_state`.
    pub async fn gate_issues_of(
        &self,
        target: vectispire_cp_db::ScanTarget,
        state: &str,
    ) -> Result<Vec<IssueView>, IssueError> {
        self.in_state_of(state, Some(target)).await
    }

    /// Every issue in a state, across all targets.
    pub async fn in_state(&self, state: &str) -> Result<Vec<IssueView>, IssueError> {
        self.in_state_of(state, None).await
    }

    async fn in_state_of(
        &self,
        state: &str,
        target: Option<vectispire_cp_db::ScanTarget>,
    ) -> Result<Vec<IssueView>, IssueError> {
        let mut tx = crate::persistence::read(&self.db).await?;
        let rows = IssueRepository::find_by_state(&mut tx, state, target).await.map_err(IssueError::from)?;
        crate::persistence::commit(tx).await?;
        Ok(rows.into_iter().map(|r| r.to_view()).collect())
    }
    /// `countUnsettledOfTypeWithin`: these repositories' issues of one built-in type (its wire name), per repository,
    /// severity and state, settled triage left out — a triage status this version does not know is counted (decision
    /// 0032 §6). The resolved ones are counted too: a resolved ratio needs both sides.
    pub async fn count_unsettled_of_type_within(
        &self,
        kind: &str,
        repository_ids: &[i64],
    ) -> Result<Vec<ScopeCount>, IssueError> {
        self.scope_counts(UnsettledScope::Type(kind), repository_ids).await
    }

    /// `countUnsettledOfToolWithin`: the same, for one tool's issues, by the fingerprint's tool key — `plugin:<id>`,
    /// `import:<source>/<tool>`.
    pub async fn count_unsettled_of_tool_within(
        &self,
        tool_key: &str,
        repository_ids: &[i64],
    ) -> Result<Vec<ScopeCount>, IssueError> {
        self.scope_counts(UnsettledScope::Tool(tool_key), repository_ids).await
    }

    async fn scope_counts(
        &self,
        scope: UnsettledScope<'_>,
        repository_ids: &[i64],
    ) -> Result<Vec<ScopeCount>, IssueError> {
        // Fixed at three by the statement's placeholders; a fourth settled status must widen the statement, and is
        // refused here until it does rather than counted as unsettled.
        let &[first, second, third] = TriageStatus::settled_wire_names() else {
            return Err(IssueError::from(StoreError::Other(
                "the settled triage statuses are not the three the count binds".to_owned(),
            )));
        };
        // Once each, as Java's `LinkedHashSet`: a repository named twice would be counted in two batches.
        let distinct: Vec<i64> = repository_ids.iter().copied().collect::<BTreeSet<i64>>().into_iter().collect();
        let mut tx = crate::persistence::read(&self.db).await?;
        let mut counts = Vec::new();
        for batch in distinct.chunks(FLAG_BATCH) {
            let rows = checked::count_unsettled_within(&mut tx, scope, batch, [first, second, third])
                .await
                .map_err(IssueError::from)?;
            counts.extend(rows.into_iter().map(|(repository_id, severity, state, count)| ScopeCount {
                repository_id,
                severity,
                state,
                count,
            }));
        }
        crate::persistence::commit(tx).await?;
        Ok(counts)
    }
}

opaque_debug!(IssueCatalog);
