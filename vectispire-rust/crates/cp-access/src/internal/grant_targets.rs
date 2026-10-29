//! `GrantTargets`: what a grant may name, for accounts and teams alike — one rule, because the two grant tables are
//! read by one resolution in the visibility.
//!
//! **A target must exist when it is granted, and be one the granting administrator sees.** A grant naming a project
//! nobody created resolves to no repository: it would show on the screen and grant nothing — until a project is
//! created with that identifier, when it would quietly grant a project the administrator never chose. Every kind is
//! checked, and refused as absent: **404, in the same words for absent and hidden**, the convention of the row guards.
//! A project is checked for existence only: a `Visibility` knows the repositories a project holds, not the project.
//!
//! **A grant already held is kept as it is.** The routes replace the set wholesale and the screen sends back every
//! grant it listed, the ones whose target went included; refusing those would make an account whose repository was
//! deleted before grants were revoked with their target uneditable.

use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_domain::team_rules::{self, KIND_CONTAINER, KIND_PROJECT, KIND_REPOSITORY};

use crate::administration::AdminError;
use crate::visibility::GrantableTargets;

/// `validate`: the kind normalized, or the refusal — `InvalidInput` for a kind that does not exist (400), `NotFound`
/// for a target that does not exist or that the granter does not see (404, one sentence for both).
///
/// `held` answers whether the grantee holds this grant already, asked with the kind normalized, as the tables store
/// it.
pub(crate) async fn validate(
    targets: &dyn GrantableTargets,
    kind: Option<&str>,
    id: i64,
    granter: &Visibility,
    held: impl Fn(&str, i64) -> bool,
) -> Result<String, AdminError> {
    let normalized = team_rules::validate_target_kind(kind).map_err(|refused| AdminError::InvalidInput(refused.0))?;
    if held(&normalized, id) {
        return Ok(normalized);
    }
    let grantable = match normalized.as_str() {
        KIND_PROJECT => targets.project_exists(id).await?,
        KIND_REPOSITORY => visible(targets, ScanTarget::Repository(id), granter).await?,
        KIND_CONTAINER => visible(targets, ScanTarget::Container(id), granter).await?,
        _ => false,
    };
    if !grantable {
        return Err(AdminError::NotFound(format!("No {normalized} with id {id}.")));
    }
    Ok(normalized)
}

/// Exists, then visible — in that order, as Java's `&&`: the granter's visibility is not asked of a target that is
/// not there.
async fn visible(targets: &dyn GrantableTargets, target: ScanTarget, granter: &Visibility) -> Result<bool, AdminError> {
    Ok(targets.exists(target).await? && granter.permits(target))
}

#[cfg(test)]
mod tests {
    //! `GrantTargetsTest`, case by case: the granter's visibility, on the one path the routes' suite cannot reach —
    //! the administrators who reach the grant routes see the whole estate.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeSet;
    use std::sync::Mutex;

    use vectispire_cp_http::credentials::BoxFuture;

    use super::*;
    use crate::visibility::{AccessError, Grant, Labels, TargetGrant};

    /// `mock(GrantableTargets.class)`: the targets that exist, and every question asked.
    #[derive(Default)]
    struct Existing {
        targets: BTreeSet<ScanTarget>,
        projects: BTreeSet<i64>,
        asked: Mutex<Vec<String>>,
    }

    impl GrantableTargets for Existing {
        fn targets_in<'a>(&'a self, _: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<Vec<ScanTarget>, AccessError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn named<'a>(&'a self, _: &'a [Grant]) -> BoxFuture<'a, Result<Vec<TargetGrant>, AccessError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn project_exists(&self, project_id: i64) -> BoxFuture<'_, Result<bool, AccessError>> {
            self.asked.lock().unwrap().push(format!("project {project_id}"));
            Box::pin(async move { Ok(self.projects.contains(&project_id)) })
        }
        fn exists(&self, target: ScanTarget) -> BoxFuture<'_, Result<bool, AccessError>> {
            self.asked.lock().unwrap().push(format!("{target:?}"));
            Box::pin(async move { Ok(self.targets.contains(&target)) })
        }
        fn labels(&self) -> BoxFuture<'_, Result<Labels, AccessError>> {
            Box::pin(async { Ok(Labels::default()) })
        }
    }

    fn sees_one() -> Visibility {
        Visibility::only([ScanTarget::Repository(1)])
    }

    fn refusal(result: Result<String, AdminError>) -> String {
        match result {
            Err(AdminError::NotFound(message)) => message,
            other => panic!("expected a 404, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_hidden_target_is_refused_in_the_words_of_an_absent_one() {
        let targets = Existing { targets: BTreeSet::from([ScanTarget::Repository(2)]), ..Existing::default() };

        let hidden = refusal(validate(&targets, Some("repository"), 2, &sees_one(), |_, _| false).await);
        let absent = refusal(validate(&targets, Some("repository"), 3, &Visibility::everything(), |_, _| false).await);

        assert_eq!(hidden, "No repository with id 2.");
        assert_eq!(absent, "No repository with id 3.");
    }

    #[tokio::test]
    async fn a_visible_target_is_granted_its_kind_normalized() {
        let targets = Existing { targets: BTreeSet::from([ScanTarget::Repository(1)]), ..Existing::default() };
        assert_eq!(validate(&targets, Some("Repository"), 1, &sees_one(), |_, _| false).await.unwrap(), "repository");
    }

    #[tokio::test]
    async fn a_grant_already_held_is_kept_without_asking_whether_its_target_is_still_there() {
        let targets = Existing::default();
        let granter = sees_one();
        let kept = validate(&targets, Some("container"), 9, &granter, |kind, id| kind == "container" && id == 9);
        assert_eq!(kept.await.unwrap(), "container");
        assert!(targets.asked.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn held_is_asked_with_the_kind_normalized() {
        let targets = Existing::default();
        let granter = sees_one();
        let kept = validate(&targets, Some(" CONTAINER "), 9, &granter, |kind, id| kind == "container" && id == 9);
        assert_eq!(kept.await.unwrap(), "container");
    }

    #[tokio::test]
    async fn a_project_is_checked_for_existence_only() {
        let targets = Existing { projects: BTreeSet::from([4]), ..Existing::default() };
        let nothing = Visibility::only([]);
        assert_eq!(validate(&targets, Some("project"), 4, &nothing, |_, _| false).await.unwrap(), "project");
        assert_eq!(
            refusal(validate(&targets, Some("project"), 5, &nothing, |_, _| false).await),
            "No project with id 5."
        );
    }

    #[tokio::test]
    async fn an_image_is_held_to_the_granter_as_a_repository_is() {
        let targets = Existing { targets: BTreeSet::from([ScanTarget::Container(6)]), ..Existing::default() };
        assert_eq!(
            refusal(validate(&targets, Some("container"), 6, &sees_one(), |_, _| false).await),
            "No container with id 6."
        );
        let sees_it = Visibility::only([ScanTarget::Container(6)]);
        assert_eq!(validate(&targets, Some("container"), 6, &sees_it, |_, _| false).await.unwrap(), "container");
    }

    #[tokio::test]
    async fn an_unknown_kind_is_a_bad_request_naming_it_as_sent() {
        let targets = Existing::default();
        match validate(&targets, Some("Solution"), 1, &Visibility::everything(), |_, _| true).await {
            Err(AdminError::InvalidInput(message)) => {
                assert_eq!(message, "Unknown target kind \"Solution\". Expected: repository, container, project.")
            }
            other => panic!("expected a 400, got {other:?}"),
        }
        match validate(&targets, None, 1, &Visibility::everything(), |_, _| true).await {
            Err(AdminError::InvalidInput(message)) => assert!(message.starts_with("Unknown target kind \"null\"")),
            other => panic!("expected a 400, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn existence_is_asked_before_visibility_and_absence_answers_without_it() {
        let targets = Existing::default();
        let _ = validate(&targets, Some("repository"), 8, &Visibility::everything(), |_, _| false).await;
        assert_eq!(*targets.asked.lock().unwrap(), vec!["Repository(8)".to_owned()]);
    }
}
