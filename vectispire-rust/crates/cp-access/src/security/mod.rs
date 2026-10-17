//! `access::security` — what every route of every module marks itself with: the caller's allowance as the
//! route builder hands it to a `.scoped()` handler, and the 404 a refused row becomes.
//!
//! `Principal` → allowance is the one place a request's visibility is made: [`CallerVisibility`] implements the
//! chain's `VisibilityOf`, so `Scoped<CallerScope>` in a handler is the value `VisibilityService.allowance(user,
//! principal.credentialRestriction())` was on the Java side — resolved before the handler runs, for every route that
//! declared `.scoped()`, and for no other.

use std::sync::Arc;

use http::StatusCode;
use vectispire_cp_db::Visibility;
use vectispire_cp_http::Problem;
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_http::principal::{Credential, Principal};
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
