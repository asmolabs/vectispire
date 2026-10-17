//! What a caller may see, resolved once per request and asked everywhere — `VisibilityService`.
//!
//! **One resolution point, one enforcement point.** The rule is [`Visibility`] (`vectispire-cp-db`), pure; this
//! module answers which one applies to the request in hand, and the query applies it ([`VisibleSelect`] cannot be
//! built without it).
//!
//! **Two ways to be allowed, and why the operators differ:**
//!
//! - **team grants ∪ direct grants** — they answer the same question, what may this person read, from two
//!   directions; intersecting them would make joining a team *narrow* what somebody already had;
//! - **account ∩ credential** — they answer different questions, who is this and what is this key for; a narrow
//!   key held by a broad account stays narrow ([`Visibility::and`]).
//!
//! **A grant naming a project is resolved here and nowhere else** (decision 0023): turned into the project's
//! repositories *and images* at each request, before anything is queried, so what leaves this module is still a
//! set of targets. Copying them into target grants when the grant is made would be a snapshot, and a repository
//! filed afterwards would stay invisible to exactly the people the project was granted to.
//!
//! [`VisibleSelect`]: vectispire_cp_db::VisibleSelect

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_http::credentials::BoxFuture;

use crate::persistence::grants;

pub use crate::persistence::StoreError;
pub use crate::persistence::grants::Grant;
use crate::roles::{RoleFlags, role_of};

/// `VisibilityMode`: how much a non-administrator sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VisibilityMode {
    /// Every signed-in account sees every target. The default, so an upgrade changes nothing.
    Everyone,
    /// An account sees only what was assigned to it, and **an account with no assignment sees nothing**.
    Assigned,
}

impl VisibilityMode {
    pub fn wire_name(self) -> &'static str {
        match self {
            VisibilityMode::Everyone => "everyone",
            VisibilityMode::Assigned => "assigned",
        }
    }

    /// `VisibilityMode.byWireName`: trimmed as `String.trim` trims, compared without case.
    ///
    /// **Java's `trim`, not Rust's**: `String.trim` strips every character up to U+0020 — the ASCII controls
    /// included — and no other; `str::trim` strips Unicode white space, a no-break space among it, and leaves the
    /// controls. A no-break space before `everyone` is unreadable on the Java side, so here too (`modes.json`).
    pub fn by_wire_name(value: Option<&str>) -> Option<VisibilityMode> {
        let normalized = value.unwrap_or("").trim_matches(|c: char| c <= '\u{20}').to_lowercase();
        [VisibilityMode::Everyone, VisibilityMode::Assigned].into_iter().find(|mode| mode.wire_name() == normalized)
    }

    /// `VisibilityMode.of`: **an unreadable value reads as `Assigned`**, never `Everyone` — a typo in the settings
    /// table must not quietly open the deployment.
    pub fn of(value: Option<&str>) -> VisibilityMode {
        VisibilityMode::by_wire_name(value).unwrap_or(VisibilityMode::Assigned)
    }
}

/// `VisibilityService.Allowance`: what a caller may see, and which projects it was granted as such.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allowance {
    pub visibility: Visibility,
    /// Empty when the visibility is everything, and empty when the credential carries a restriction: a key
    /// narrowed to one repository reveals no project through its account's grants.
    pub granted_projects: BTreeSet<i64>,
    /// The credential carries a restriction of its own. Such a credential never sees a project **whole**, even one
    /// whose every repository it permits ([`crate::rows::sees_whole_project`]).
    pub narrowed_by_credential: bool,
}

impl Allowance {
    /// What a caller with no account sees: nothing. Reached only if a route forgot its marker, and the safe answer
    /// to "who is this" being unanswerable is "nothing".
    pub fn nothing() -> Allowance {
        Allowance { visibility: Visibility::only([]), granted_projects: BTreeSet::new(), narrowed_by_credential: false }
    }

    pub fn everything() -> Allowance {
        Allowance {
            visibility: Visibility::everything(),
            granted_projects: BTreeSet::new(),
            narrowed_by_credential: false,
        }
    }
}

/// The account a request is made for, as the visibility needs it: its id and its **stored** role, unparsed — an
/// unreadable role is not a global scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRef {
    pub id: i64,
    pub role: String,
}

/// `TeamRules.KIND_*`.
pub const KIND_REPOSITORY: &str = "repository";
pub const KIND_CONTAINER: &str = "container";
pub const KIND_PROJECT: &str = "project";

/// What the visibility reads of the settings: the stored or default value of `target_visibility`. The settings
/// module's store implements it; the value is the effective one, its default (`everyone`) already applied.
pub trait AccessSettings: Send + Sync {
    fn target_visibility(&self) -> BoxFuture<'_, Result<String, AccessError>>;
}

/// `GrantableTargets`: what access needs to know about the targets it grants — a port the targets module
/// implements, so that the dependency points from targets to access and nowhere else (decision 0029).
pub trait GrantableTargets: Send + Sync {
    /// The repositories and the images filed in these projects now. Never asked with an empty set.
    fn targets_in<'a>(&'a self, projects: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<Vec<ScanTarget>, AccessError>>;
}

/// A resolution that could not be made. **Never reduced to "nothing visible"**: that would answer a 404 or an
/// empty list for what is a failure of the server, and an empty list is an answer (decision 0007).
#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("the grants could not be read: {0}")]
    Database(#[from] StoreError),
    #[error("{0}")]
    Port(String),
}

/// `VisibilityService`.
#[derive(Clone)]
pub struct VisibilityService {
    db: Db,
    settings: Arc<dyn AccessSettings>,
    targets: Arc<dyn GrantableTargets>,
}

impl std::fmt::Debug for VisibilityService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("VisibilityService").field("db", &self.db).finish_non_exhaustive()
    }
}

impl VisibilityService {
    pub fn new(db: Db, settings: Arc<dyn AccessSettings>, targets: Arc<dyn GrantableTargets>) -> VisibilityService {
        VisibilityService { db, settings, targets }
    }

    pub async fn mode(&self) -> Result<VisibilityMode, AccessError> {
        Ok(VisibilityMode::of(Some(self.settings.target_visibility().await?.as_str())))
    }

    /// `allowance(user, restriction)`: the account's allowance narrowed by the credential's restriction.
    pub async fn allowance(
        &self,
        user: Option<&AccountRef>,
        restriction: &Visibility,
    ) -> Result<Allowance, AccessError> {
        let account = self.resolve(user).await?;
        Ok(narrow(account, restriction))
    }

    /// `of(user, restriction)`.
    pub async fn of(&self, user: Option<&AccountRef>, restriction: &Visibility) -> Result<Visibility, AccessError> {
        Ok(self.resolve(user).await?.visibility.and(restriction))
    }

    /// An agent's visibility: everything, deliberately — an agent reads no backlog, and the work it is given is
    /// already narrowed by the queue's label routing.
    pub fn of_agent(&self) -> Visibility {
        Visibility::everything()
    }

    async fn resolve(&self, user: Option<&AccountRef>) -> Result<Allowance, AccessError> {
        let Some(user) = user else {
            return Ok(Allowance::nothing());
        };
        // The mode first, as the Java condition reads it: a settings store that cannot answer fails the request
        // for every account, administrators included, rather than for some.
        if sees_everything(self.mode().await?, &user.role) {
            return Ok(Allowance::everything());
        }

        let grants = grants::of_account(&self.db, user.id).await?;
        let projects = projects_of(&grants);
        // The same guard: `project_id in ()` matching every row would hand an account with no project grant every
        // repository filed anywhere. The images filed in a granted project come with it, as its repositories do.
        let filed = if projects.is_empty() { Vec::new() } else { self.targets.targets_in(&projects).await? };
        Ok(assemble(&grants, filed))
    }
}

/// Whether an account sees everything without its grants being read: the mode says so, or its role has a global
/// security scope. **The mode is asked first**, as the Java condition reads it.
pub fn sees_everything(mode: VisibilityMode, role: &str) -> bool {
    mode == VisibilityMode::Everyone || role_of(Some(role)).is_some_and(RoleFlags::has_global_security_scope)
}

/// The projects the grants name as such — the ones whose targets [`GrantableTargets`] is asked for.
pub fn projects_of(grants: &[Grant]) -> BTreeSet<i64> {
    grants.iter().filter(|grant| grant.kind == KIND_PROJECT).map(|grant| grant.id).collect()
}

/// An assigned account's allowance from its grants — direct and through teams, **unioned** — and the targets filed
/// in the projects they name. A set, not a list: a target granted twice is one target.
pub fn assemble(grants: &[Grant], filed_in_projects: Vec<ScanTarget>) -> Allowance {
    let mut visible = BTreeSet::new();
    let mut projects = BTreeSet::new();
    for grant in grants {
        collect(grant, &mut visible, &mut projects);
    }
    visible.extend(filed_in_projects);
    Allowance { visibility: Visibility::Only(visible), granted_projects: projects, narrowed_by_credential: false }
}

/// The account's allowance narrowed by a credential's restriction — `allowance`'s second half, pure.
pub fn narrow(account: Allowance, restriction: &Visibility) -> Allowance {
    let narrowed = !matches!(restriction, Visibility::Everything);
    Allowance {
        visibility: account.visibility.and(restriction),
        granted_projects: if narrowed { BTreeSet::new() } else { account.granted_projects },
        narrowed_by_credential: narrowed,
    }
}

fn collect(grant: &Grant, visible: &mut BTreeSet<ScanTarget>, projects: &mut BTreeSet<i64>) {
    match grant.kind.as_str() {
        KIND_PROJECT => {
            projects.insert(grant.id);
        }
        KIND_REPOSITORY => {
            visible.insert(ScanTarget::Repository(grant.id));
        }
        KIND_CONTAINER => {
            visible.insert(ScanTarget::Container(grant.id));
        }
        // A kind nobody wrote grants nothing.
        _ => {}
    }
}

/// `ApiKeyAuthService.restrictionOf`: everything when the key is unrestricted, otherwise the one target it was
/// issued for — and **nothing** for a kind nobody wrote: a key nobody understands sees nothing, never everything.
pub fn restriction_of_key(target_kind: Option<&str>, target_id: Option<i64>) -> Visibility {
    let (Some(kind), Some(id)) = (target_kind, target_id) else {
        return Visibility::everything();
    };
    match kind {
        KIND_REPOSITORY => Visibility::only([ScanTarget::Repository(id)]),
        KIND_CONTAINER => Visibility::only([ScanTarget::Container(id)]),
        _ => Visibility::only([]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ScanTarget::{Container, Repository};

    #[test]
    fn an_unreadable_mode_is_the_strict_one() {
        assert_eq!(VisibilityMode::of(Some("everyone")), VisibilityMode::Everyone);
        assert_eq!(VisibilityMode::of(Some(" EVERYONE ")), VisibilityMode::Everyone);
        assert_eq!(VisibilityMode::of(Some("assigned")), VisibilityMode::Assigned);
        assert_eq!(VisibilityMode::of(Some("everybody")), VisibilityMode::Assigned);
        assert_eq!(VisibilityMode::of(Some("")), VisibilityMode::Assigned);
        assert_eq!(VisibilityMode::of(None), VisibilityMode::Assigned);
    }

    #[test]
    fn a_restricted_key_reveals_no_project_and_never_widens() {
        let account = Allowance {
            visibility: Visibility::only([Repository(1), Repository(2)]),
            granted_projects: BTreeSet::from([10]),
            narrowed_by_credential: false,
        };
        let narrowed = narrow(account.clone(), &Visibility::only([Repository(2), Repository(3)]));
        assert_eq!(narrowed.visibility, Visibility::only([Repository(2)]));
        assert!(narrowed.granted_projects.is_empty());
        assert!(narrowed.narrowed_by_credential);

        let unrestricted = narrow(account.clone(), &Visibility::everything());
        assert_eq!(unrestricted, account);

        // A global account holding a narrow key stays narrow.
        let global = narrow(Allowance::everything(), &Visibility::only([Container(5)]));
        assert_eq!(global.visibility, Visibility::only([Container(5)]));
        assert!(global.narrowed_by_credential);
    }

    #[test]
    fn a_key_of_an_unknown_kind_sees_nothing() {
        assert_eq!(restriction_of_key(None, None), Visibility::everything());
        assert_eq!(restriction_of_key(Some("repository"), None), Visibility::everything());
        assert_eq!(restriction_of_key(Some("repository"), Some(4)), Visibility::only([Repository(4)]));
        assert_eq!(restriction_of_key(Some("container"), Some(4)), Visibility::only([Container(4)]));
        assert!(restriction_of_key(Some("project"), Some(4)).is_empty());
        assert!(restriction_of_key(Some("Repository"), Some(4)).is_empty());
    }
}
