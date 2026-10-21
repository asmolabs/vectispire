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

    /// The open issues of one target, as the gate weighs them.
    pub async fn gate_issues_of(
        &self,
        target: vectispire_cp_db::ScanTarget,
        state: &str,
    ) -> Result<Vec<IssueView>, IssueError> {
        let mut filters = IssueFilters::new(vectispire_cp_db::Visibility::Everything);
        filters.state = Some(state.to_owned());
        match target {
            vectispire_cp_db::ScanTarget::Repository(id) => filters.repo_id = Some(id),
            vectispire_cp_db::ScanTarget::Container(id) => filters.container_id = Some(id),
        }
        self.issues(&filters).await
    }

    /// Every issue in a state, across all targets.
    pub async fn in_state(&self, state: &str) -> Result<Vec<IssueView>, IssueError> {
        let mut filters = IssueFilters::new(vectispire_cp_db::Visibility::Everything);
        filters.state = Some(state.to_owned());
        self.issues(&filters).await
    }
}

opaque_debug!(IssueCatalog);
