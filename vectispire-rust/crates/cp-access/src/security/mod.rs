//! `access::security` — what every route of every module marks itself with: the caller's allowance as the
//! route builder hands it to a `.scoped()` handler, and the 404 a refused row becomes.
//!
//! `Principal` → allowance is the one place a request's visibility is made: [`CallerVisibility`] implements the
//! chain's `VisibilityOf`, so `Scoped<CallerScope>` in a handler is the value `VisibilityService.allowance(user,
//! principal.credentialRestriction())` was on the Java side — resolved before the handler runs, for every route that
//! declared `.scoped()`, and for no other.

use std::sync::Arc;

use http::StatusCode;
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_http::Problem;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_http::principal::{Credential, Principal, Restriction};
use vectispire_cp_http::routes::VisibilityOf;

use crate::rows::NotFound;
use crate::visibility::{AccessError, AccountRef, Allowance, VisibilityService};

/// The account behind a principal and the restriction its credential carries — the credentials module's to answer
/// (sessions, API keys), a port here. A session carries no restriction of its own; an integration key carries its
/// target's (`restriction_of_key`).
pub trait PrincipalDirectory: Send + Sync {
    fn account<'a>(&'a self, principal: &'a Principal) -> BoxFuture<'a, Result<Option<AccountRef>, AccessError>>;
    fn restriction<'a>(&'a self, principal: &'a Principal) -> BoxFuture<'a, Result<Visibility, AccessError>>;
}

/// The [`PrincipalDirectory`] the binary composes: what the credentials module resolved, read back from the
/// principal it built (`Principal::grounds`) — the account's id and stored role, and **the credential's restriction**,
/// which the allowance is intersected with (`VisibilityService.allowance(user, credentialRestriction)`). No table is
/// read again per request: the credential was resolved against the tables a moment before, in the chain.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrincipalGrounds;

impl PrincipalDirectory for PrincipalGrounds {
    fn account<'a>(&'a self, principal: &'a Principal) -> BoxFuture<'a, Result<Option<AccountRef>, AccessError>> {
        Box::pin(async move {
            Ok(principal.grounds.account_id.map(|id| AccountRef {
                id,
                // An unreadable role travels as none, which is no global scope.
                role: principal.grounds.stored_role.clone().unwrap_or_default(),
            }))
        })
    }

    fn restriction<'a>(&'a self, principal: &'a Principal) -> BoxFuture<'a, Result<Visibility, AccessError>> {
        Box::pin(async move { Ok(visibility_of(principal.grounds.restriction)) })
    }
}

/// A restriction as the visibility reads it.
pub fn visibility_of(restriction: Restriction) -> Visibility {
    match restriction {
        Restriction::None => Visibility::everything(),
        Restriction::Target(vectispire_domain::ScanTarget::Repository(id)) => {
            Visibility::only([ScanTarget::Repository(id)])
        }
        Restriction::Target(vectispire_domain::ScanTarget::Container(id)) => {
            Visibility::only([ScanTarget::Container(id)])
        }
        Restriction::Nothing => Visibility::only([]),
    }
}

/// What a scoped handler reads: the allowance, or the failure to make one.
///
/// **A failure is not an empty allowance.** Reduced to "nothing visible", a database that did not answer would read
/// as a 404 or an empty list — an answer, where the truth is an error (decision 0007). The handler answers it as the
/// error handler answers any unexpected failure (`UnexpectedFailure`, with its reference), which is not this crate's.
pub type CallerScope = Result<Allowance, Unavailable>;

/// The allowance could not be resolved. Cloneable, as the extension a handler reads must be; the cause is logged
/// where it happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the caller's visibility could not be resolved")]
pub struct Unavailable;

/// `VisibilityService` behind the chain's `VisibilityOf`.
#[derive(Clone)]
pub struct CallerVisibility {
    service: VisibilityService,
    directory: Arc<dyn PrincipalDirectory>,
}

impl std::fmt::Debug for CallerVisibility {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("CallerVisibility").field("service", &self.service).finish_non_exhaustive()
    }
}

impl CallerVisibility {
    pub fn new(service: VisibilityService, directory: Arc<dyn PrincipalDirectory>) -> CallerVisibility {
        CallerVisibility { service, directory }
    }

    async fn resolve(&self, principal: &Principal) -> Result<Allowance, AccessError> {
        // An agent reads no backlog; its visibility is everything, deliberately (`VisibilityService.of(AgentView)`).
        if matches!(principal.credential, Credential::Agent { .. }) {
            return Ok(Allowance { visibility: self.service.of_agent(), ..Allowance::everything() });
        }
        let account = self.directory.account(principal).await?;
        let restriction = self.directory.restriction(principal).await?;
        self.service.allowance(account.as_ref(), &restriction).await
    }
}

impl VisibilityOf<CallerScope> for CallerVisibility {
    fn of<'a>(&'a self, principal: &'a Principal) -> BoxFuture<'a, CallerScope> {
        Box::pin(async move {
            self.resolve(principal).await.map_err(|failure| {
                tracing::error!(error = %failure, "the caller's visibility could not be resolved");
                Unavailable
            })
        })
    }
}

/// The problem document a refused row is answered with: 404, the guard's one sentence.
pub fn not_found(refusal: NotFound) -> Problem {
    Problem::handler(StatusCode::NOT_FOUND, refusal.message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vectispire_cp_http::Grounds;
    use vectispire_cp_http::principal::Account;

    fn grounded(restriction: Restriction, account_id: Option<i64>, role: Option<&str>) -> Principal {
        let account = Account { username: "u".into(), role: None, must_change_password: false };
        Principal::session(account).with_grounds(Grounds {
            account_id,
            stored_role: role.map(str::to_owned),
            restriction,
            actor: None,
        })
    }

    #[tokio::test]
    async fn the_grounds_carry_the_restriction_to_the_visibility() {
        let directory = PrincipalGrounds;
        let narrowed =
            grounded(Restriction::Target(vectispire_domain::ScanTarget::Repository(7)), Some(3), Some("ADMIN"));
        assert_eq!(directory.restriction(&narrowed).await.unwrap(), Visibility::only([ScanTarget::Repository(7)]));
        let image = grounded(Restriction::Target(vectispire_domain::ScanTarget::Container(8)), Some(3), Some("ADMIN"));
        assert_eq!(directory.restriction(&image).await.unwrap(), Visibility::only([ScanTarget::Container(8)]));
        // A key nobody understands sees nothing, never everything.
        let unknown = grounded(Restriction::Nothing, Some(3), Some("ADMIN"));
        assert_eq!(directory.restriction(&unknown).await.unwrap(), Visibility::only([]));
        let session = grounded(Restriction::None, Some(3), Some("USER"));
        assert_eq!(directory.restriction(&session).await.unwrap(), Visibility::everything());
        assert_eq!(directory.account(&session).await.unwrap(), Some(AccountRef { id: 3, role: "USER".into() }));
        // An unreadable role travels as none, which is no global scope.
        let unreadable = grounded(Restriction::None, Some(4), None);
        assert_eq!(directory.account(&unreadable).await.unwrap(), Some(AccountRef { id: 4, role: String::new() }));
        // No account: the visibility resolves to nothing.
        assert_eq!(directory.account(&grounded(Restriction::None, None, None)).await.unwrap(), None);
    }
}
