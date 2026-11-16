//! `requireIssuerSees`: a key restricted to a target is issued only when the target exists and the account the key
//! acts for can see it. Not a hole otherwise — the account's visibility is intersected with the restriction when the
//! key is used — but a key restricted to nothing it can reach would pass issuance and then list nothing, silently.
//! Absent and hidden get the same answer, or issuing a key becomes a way to probe which identifiers exist.

use std::sync::Arc;

use vectispire_cp_db::{Db, ScanTarget, Visibility};
use vectispire_cp_http::credentials::BoxFuture;

use crate::credentials::{IssuerSees, StoreError};
use crate::persistence::credentials::accounts;
use crate::visibility::{AccountRef, GrantableTargets, VisibilityService};

/// [`IssuerSees`] answered by the targets and the issuer's visibility, as Java's `ApiKeyAdministrationService` does.
#[derive(Clone)]
pub struct IssuerVisibility {
    db: Db,
    visibility: VisibilityService,
    targets: Arc<dyn GrantableTargets>,
}

impl std::fmt::Debug for IssuerVisibility {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("IssuerVisibility").field("db", &self.db).finish_non_exhaustive()
    }
}

impl IssuerVisibility {
    pub fn new(db: Db, visibility: VisibilityService, targets: Arc<dyn GrantableTargets>) -> IssuerVisibility {
        IssuerVisibility { db, visibility, targets }
    }
}

fn port(error: impl std::error::Error + Send + Sync + 'static) -> StoreError {
    StoreError::from_port(Box::new(error))
}

impl IssuerSees for IssuerVisibility {
    fn issuer_sees<'a>(&'a self, issuer: i64, target: ScanTarget) -> BoxFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            if !self.targets.exists(target).await.map_err(port)? {
                return Ok(false);
            }
            let Some(account) = accounts::find(&self.db, issuer).await? else { return Ok(false) };
            let seen = self
                .visibility
                .of(Some(&AccountRef { id: issuer, role: account.role }), &Visibility::everything())
                .await
                .map_err(port)?;
            Ok(seen.permits(target))
        })
    }
}
