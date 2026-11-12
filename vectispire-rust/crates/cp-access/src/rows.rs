//! The guard for a read that reaches a row by its identifier — `RowVisibility`, the one copy of it.
//!
//! **404, never 403.** A 403 says "this exists and is not yours", which answers the question the caller was
//! probing with. A refusal is indistinguishable from an absence, in wording and in cost: **the absent row comes
//! here as `None`**, never refused by the caller first — nine Java routes did, each in its own words, and each
//! wording was an oracle. One sentence per kind of row, below, and nowhere else.

use std::collections::BTreeSet;

use vectispire_cp_db::{ScanTarget, Visibility};

use crate::visibility::Allowance;

/// The refusal every guard here gives: a 404 with one fixed sentence. `crate::security` turns it into the
/// problem document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct NotFound {
    pub message: &'static str,
}

pub const TARGET_NOT_FOUND: &str = "Target not found.";
pub const PROJECT_NOT_FOUND: &str = "Project not found.";
pub const SOLUTION_NOT_FOUND: &str = "Solution not found.";
pub const ISSUE_NOT_FOUND: &str = "Issue not found.";
pub const SCAN_NOT_FOUND: &str = "Scan not found.";
pub const REPOSITORY_NOT_FOUND: &str = "Repository not found.";

const fn refused(message: &'static str) -> NotFound {
    NotFound { message }
}

/// `Visibility.permits` with the Java signature's `null`: an unclassifiable row (`None`) is seen by an
/// unrestricted caller and by no restricted one.
fn permits(visibility: &Visibility, target: Option<ScanTarget>) -> bool {
    match (visibility, target) {
        (Visibility::Everything, _) => true,
        (Visibility::Only(_), None) => false,
        (Visibility::Only(_), Some(target)) => visibility.permits(target),
    }
}

/// `requireVisibleIssue`: the issue, or "Issue not found." for absent and hidden alike.
pub fn require_visible_issue<T>(
    issue: Option<T>,
    target_of: impl FnOnce(&T) -> Option<ScanTarget>,
    visibility: &Visibility,
) -> Result<T, NotFound> {
    match issue {
        Some(issue) if permits(visibility, target_of(&issue)) => Ok(issue),
        _ => Err(refused(ISSUE_NOT_FOUND)),
    }
}

/// `requireVisibleScan`: a scan is visible when its target is. **One message for both cases**: an absent scan
/// said "Scan not found." and a hidden one "Target not found.", and since ids are sequential the wording alone
/// let a restricted reader enumerate every scan.
pub fn require_visible_scan<T>(
    scan: Option<T>,
    target_of: impl FnOnce(&T) -> Option<ScanTarget>,
    visibility: &Visibility,
) -> Result<T, NotFound> {
    match scan {
        Some(scan) if permits(visibility, target_of(&scan)) => Ok(scan),
        _ => Err(refused(SCAN_NOT_FOUND)),
    }
}

/// `requireVisibleRepository`: for a route named by a repository.
pub fn require_visible_repository<T>(
    repository: Option<T>,
    repository_id: i64,
    visibility: &Visibility,
) -> Result<T, NotFound> {
    match repository {
        Some(repository) if visibility.permits(ScanTarget::Repository(repository_id)) => Ok(repository),
        _ => Err(refused(REPOSITORY_NOT_FOUND)),
    }
}

/// `requireVisible(Optional, target, visibility)`: a target's row, for a write that loads the row itself.
pub fn require_visible_row<T>(row: Option<T>, target: ScanTarget, visibility: &Visibility) -> Result<T, NotFound> {
    match row {
        Some(row) if visibility.permits(target) => Ok(row),
        _ => Err(refused(TARGET_NOT_FOUND)),
    }
}

/// The proof a service that may not decide takes in place of a bare target — only [`require_visible`] builds one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VisibleTarget(ScanTarget);

impl VisibleTarget {
    pub fn target(self) -> ScanTarget {
        self.0
    }
}

/// `requireVisible(target, visibility)`: a target named by its identifier, refused before anything is read about it.
pub fn require_visible(target: ScanTarget, visibility: &Visibility) -> Result<VisibleTarget, NotFound> {
    if visibility.permits(target) { Ok(VisibleTarget(target)) } else { Err(refused(TARGET_NOT_FOUND)) }
}

/// `seesWholeProject`: whether the caller sees an existing project **whole**.
///
/// - **A key narrowed to a repository is not a key to its project**, even when that repository is the project's
///   only one (the audit of 10 October 2026): a restriction names a target, the project is something else.
/// - Otherwise: everything, the project granted as such, or every one of its repositories visible **and at least
///   one** — "every one of none" is the vacuous truth that would hand an empty project to anybody who asked.
/// - Images play no part: the checklists speak for the project's repositories (decision 0023).
pub fn sees_whole_project(project_id: i64, repository_ids: &[i64], allowance: &Allowance) -> bool {
    if allowance.narrowed_by_credential {
        return false;
    }
    match &allowance.visibility {
        Visibility::Everything => true,
        only @ Visibility::Only(_) => {
            allowance.granted_projects.contains(&project_id)
                || (!repository_ids.is_empty()
                    && repository_ids.iter().all(|id| only.permits(ScanTarget::Repository(*id))))
        }
    }
}

/// The proof a checklist service takes in place of the bare project.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibleProject {
    pub project_id: i64,
    pub name: String,
}

/// `requireWhollyVisibleProject`: a project the caller sees whole, or "Project not found." — absent, hidden and
/// seen in part alike. `name` is `None` for a project that does not exist, passed here rather than refused by the
/// caller, whose own sentence would tell absent from hidden.
pub fn require_wholly_visible_project(
    project_id: i64,
    name: Option<&str>,
    repository_ids: &[i64],
    allowance: &Allowance,
) -> Result<VisibleProject, NotFound> {
    match name {
        Some(name) if sees_whole_project(project_id, repository_ids, allowance) => {
            Ok(VisibleProject { project_id, name: name.to_owned() })
        }
        _ => Err(refused(PROJECT_NOT_FOUND)),
    }
}

/// What a project or a solution is, to the caller: the visible targets filed under it, and whether some were not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VisibleScope {
    pub kind: ScopeKind,
    pub id: i64,
    pub name: String,
    /// Distinct, repositories then images, each ascending — a stable order for a document.
    pub visible: Vec<ScanTarget>,
    pub partial: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeKind {
    Project,
    Solution,
}

/// The permitted ones, distinct, repositories then images, each ascending. `ScanTarget`'s order is exactly that.
fn visible_of(filed: &[ScanTarget], visibility: &Visibility) -> Vec<ScanTarget> {
    filed.iter().copied().filter(|target| visibility.permits(*target)).collect::<BTreeSet<_>>().into_iter().collect()
}

/// `requireVisibleProject`: a project as far as the caller sees it — everything, the project granted as such (even
/// while it holds nothing), or one target filed in it visible. `filed` is every target filed now, **visible or
/// not**: what `partial` is measured against.
pub fn require_visible_project(
    project_id: i64,
    name: Option<&str>,
    filed: &[ScanTarget],
    allowance: &Allowance,
) -> Result<VisibleScope, NotFound> {
    let visible = visible_of(filed, &allowance.visibility);
    match name {
        Some(name)
            if matches!(allowance.visibility, Visibility::Everything)
                || allowance.granted_projects.contains(&project_id)
                || !visible.is_empty() =>
        {
            // `filed.size()` on the Java side counts duplicates, and `visible` is distinct: kept, to answer alike.
            let partial = visible.len() < filed.len();
            Ok(VisibleScope { kind: ScopeKind::Project, id: project_id, name: name.to_owned(), visible, partial })
        }
        _ => Err(refused(PROJECT_NOT_FOUND)),
    }
}

/// `requireEveryTargetOfProject`: the project export's guard — whole by its repositories **and** every filed target
/// visible, or "Project not found.".
pub fn require_every_target_of_project(
    project_id: i64,
    name: Option<&str>,
    repository_ids: &[i64],
    filed: &[ScanTarget],
    allowance: &Allowance,
) -> Result<VisibleScope, NotFound> {
    require_wholly_visible_project(project_id, name, repository_ids, allowance)?;
    let scope = require_visible_project(project_id, name, filed, allowance)?;
    if scope.partial {
        return Err(refused(PROJECT_NOT_FOUND));
    }
    Ok(scope)
}

/// `requireVisibleSolution`: the project's rule over the solution — everything, one of its projects granted as
/// such, or one target filed under it visible.
pub fn require_visible_solution(
    solution_id: i64,
    name: Option<&str>,
    project_ids: &[i64],
    filed: &[ScanTarget],
    allowance: &Allowance,
) -> Result<VisibleScope, NotFound> {
    let visible = visible_of(filed, &allowance.visibility);
    match name {
        Some(name)
            if matches!(allowance.visibility, Visibility::Everything)
                || project_ids.iter().any(|id| allowance.granted_projects.contains(id))
                || !visible.is_empty() =>
        {
            let partial = visible.len() < filed.len();
            Ok(VisibleScope { kind: ScopeKind::Solution, id: solution_id, name: name.to_owned(), visible, partial })
        }
        _ => Err(refused(SOLUTION_NOT_FOUND)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ScanTarget::{Container, Repository};

    fn only(targets: &[ScanTarget]) -> Allowance {
        Allowance {
            visibility: Visibility::only(targets.iter().copied()),
            granted_projects: BTreeSet::new(),
            narrowed_by_credential: false,
        }
    }

    #[test]
    fn an_absent_row_and_a_hidden_one_read_alike() {
        let hidden = require_visible_scan(Some(7), |_| Some(Repository(2)), &Visibility::only([Repository(1)]));
        let absent = require_visible_scan(None::<i32>, |_| Some(Repository(1)), &Visibility::only([Repository(1)]));
        assert_eq!(hidden, absent);
        assert_eq!(hidden, Err(NotFound { message: SCAN_NOT_FOUND }));
    }

    #[test]
    fn an_empty_project_is_not_seen_whole_by_the_vacuous_truth() {
        assert!(!sees_whole_project(1, &[], &only(&[Repository(1)])));
        let mut granted = only(&[]);
        granted.granted_projects.insert(1);
        assert!(sees_whole_project(1, &[], &granted));
    }

    #[test]
    fn a_narrowed_key_never_sees_a_project_whole() {
        let mut narrowed = only(&[Repository(1)]);
        narrowed.narrowed_by_credential = true;
        assert!(!sees_whole_project(1, &[1], &narrowed));
        assert!(sees_whole_project(1, &[1], &only(&[Repository(1)])));
    }

    #[test]
    fn a_partial_reader_is_served_the_aggregate_and_refused_the_export() {
        let reader = only(&[Repository(1)]);
        let filed = [Repository(1), Container(9)];
        let scope = require_visible_project(5, Some("p"), &filed, &reader).unwrap();
        assert!(scope.partial);
        assert_eq!(scope.visible, vec![Repository(1)]);
        assert_eq!(
            require_every_target_of_project(5, Some("p"), &[1], &filed, &reader),
            Err(NotFound { message: PROJECT_NOT_FOUND })
        );
    }
}
