//! `IssueCatalog`: issues as other modules read them.

use vectispire_cp_db::Db;

use crate::error::IssueError;
use crate::persistence::IssueFilters;
use crate::persistence::IssueRepository;
use crate::views::IssueView;

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
}

opaque_debug!(IssueCatalog);
