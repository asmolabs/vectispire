//! `ChangeReviewDemand`: which repositories a `change_review` line asks about, for which branch and how far back
//! (decision 0037, lot G3) — what the forges' hourly reading reads before calling a forge, so that a forge is asked
//! only about the repositories of a project whose checklist measures it, and only as far back as the widest window
//! bound to it. The checklists that are not superseded count; a project's repositories are the ones filed in it now.
//!
//! **No statement of its own**: Java's `boundInUse` joins the checklists not superseded to their version's items whose
//! bound rule is a change review; here the same rows are read through the queries the module already holds — the
//! checklists of each live status, then each distinct version's items — and the rule parsed from its canonical form,
//! which is what Java's `like` on the kind's token pre-filters.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use vectispire_cp_db::{Db, Mode};

use crate::ports::ProjectDirectory;
use crate::rule::ChecklistRule;

/// One repository and branch to read; `branch` is `None` for the default branch the forge names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub repository_id: i64,
    pub branch: Option<String>,
    /// The widest window any line bound to it asks.
    pub window_days: i32,
}

/// The demand.
#[derive(Clone)]
pub struct ChangeReviewDemand {
    db: Db,
    projects: Arc<dyn ProjectDirectory>,
}

impl std::fmt::Debug for ChangeReviewDemand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ChangeReviewDemand")
    }
}

/// The statuses that are not superseded: a draft, a submission, a signed-off revision a reader opens.
const LIVE: [&str; 3] = ["draft", "submitted", "signed_off"];

impl ChangeReviewDemand {
    pub fn new(db: Db, projects: Arc<dyn ProjectDirectory>) -> ChangeReviewDemand {
        ChangeReviewDemand { db, projects }
    }

    /// Every repository and branch asked about, each with its widest window, by repository then branch.
    pub async fn wanted(&self) -> Result<Vec<Wanted>, String> {
        let mut tx = self.db.begin(Mode::ReadOnly).await.map_err(|failure| failure.to_string())?;
        let mut by_project: BTreeMap<i64, BTreeMap<Option<String>, i32>> = BTreeMap::new();
        let mut versions: BTreeMap<i64, Vec<(Option<String>, i32)>> = BTreeMap::new();
        for status in LIVE {
            let checklists =
                crate::persistence::checklists_in(&mut tx, status).await.map_err(|failure| failure.to_string())?;
            for checklist in checklists {
                if let std::collections::btree_map::Entry::Vacant(vacant) =
                    versions.entry(checklist.template_version_id)
                {
                    let items = crate::persistence::items_of(&mut tx, checklist.template_version_id)
                        .await
                        .map_err(|failure| failure.to_string())?;
                    let reviews = items
                        .iter()
                        .filter_map(|item| item.bound_rule.as_deref())
                        .filter_map(|bound| ChecklistRule::from_canonical(bound).ok())
                        .filter_map(|rule| match rule {
                            ChecklistRule::ChangeReview { window_days, branch, .. } => Some((branch, window_days)),
                            _ => None,
                        })
                        .collect();
                    vacant.insert(reviews);
                }
                for (branch, window) in versions.get(&checklist.template_version_id).into_iter().flatten() {
                    let widest = by_project.entry(checklist.project_id).or_default().entry(branch.clone()).or_insert(0);
                    *widest = (*widest).max(*window);
                }
            }
        }
        tx.commit().await.map_err(|failure| failure.to_string())?;
        let mut by_repository: BTreeMap<i64, BTreeMap<Option<String>, i32>> = BTreeMap::new();
        for (project, branches) in by_project {
            let Some(members) = self.projects.members(project).await? else {
                continue;
            };
            for repository in members.repository_ids.into_iter().collect::<BTreeSet<_>>() {
                for (branch, window) in &branches {
                    let widest = by_repository.entry(repository).or_default().entry(branch.clone()).or_insert(0);
                    *widest = (*widest).max(*window);
                }
            }
        }
        // By repository, then by branch as Java sorts it: the default branch (`""`) first, then by name.
        let mut wanted: Vec<Wanted> = by_repository
            .into_iter()
            .flat_map(|(repository_id, branches)| {
                branches.into_iter().map(move |(branch, window_days)| Wanted { repository_id, branch, window_days })
            })
            .collect();
        wanted.sort_by(|left, right| {
            left.repository_id.cmp(&right.repository_id).then_with(|| {
                vectispire_domain::java::compare_utf16(
                    left.branch.as_deref().unwrap_or(""),
                    right.branch.as_deref().unwrap_or(""),
                )
            })
        });
        Ok(wanted)
    }
}
