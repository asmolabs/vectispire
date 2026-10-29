//! An account's grants — the targets half of `AccountAdministrationService` (`targets`, `replaceTargets`) and the
//! transaction of `AccountAdminService.replaceTargets`.
//!
//! Beside [`crate::accounts::Accounts`] rather than in it: those methods are written against the `AccountStore` port,
//! these against the grant table and the targets module's `GrantableTargets`, and neither needs the other's.

use std::collections::BTreeSet;
use std::sync::Arc;

use vectispire_cp_db::{Db, Visibility};

use crate::accounts::{Audit, AuditOperation, RequestActor};
use crate::administration::{AdminError, record};
use crate::internal::grant_targets;
use crate::persistence::administration as store;
use crate::teams::TargetAssignment;
use crate::visibility::{Grant, GrantableTargets, TargetGrant};

/// The grants of one account, and their replacement.
pub struct AccountTargets<A> {
    db: Db,
    audit: A,
    targets: Arc<dyn GrantableTargets>,
}

impl<A> std::fmt::Debug for AccountTargets<A> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("AccountTargets").field("db", &self.db).finish_non_exhaustive()
    }
}

impl<A: Audit + Sync> AccountTargets<A> {
    pub fn new(db: Db, audit: A, targets: Arc<dyn GrantableTargets>) -> AccountTargets<A> {
        AccountTargets { db, audit, targets }
    }

    /// `targets`: what the account may see, each named. Empty means it sees nothing, in restricted mode. A project
    /// grant is listed as the project, not its repositories: the grant is what an administrator made and can revoke.
    pub async fn targets(&self, id: i64) -> Result<Vec<TargetGrant>, AdminError> {
        let mut tx = store::read(&self.db).await?;
        require_account(&mut tx, id).await?;
        let grants = store::user_targets(&mut tx, id).await?;
        store::commit(tx).await?;
        Ok(self.targets.named(&grants).await?)
    }

    /// `replaceTargets`: wholesale, because the operation that matters is removing one. Read as the team path reads
    /// it — an entry absent or without an identifier skipped, the kind validated and lower-cased, a new grant's target
    /// existing and seen by `granter`, a grant already held kept — and **de-duplicated**: the pair is the table's key,
    /// so the same target sent twice is one assignment, not a constraint violation. The delete and the inserts commit
    /// together: an account seeing an arbitrary subset of what was submitted is the state nobody would think to check.
    ///
    /// Answers the assignments as stored, named — what the screen must show, not what it sent.
    pub async fn replace_targets(
        &self,
        id: i64,
        requested: Option<&[Option<TargetAssignment>]>,
        granter: &Visibility,
        actor: &RequestActor,
    ) -> Result<Vec<TargetGrant>, AdminError> {
        let mut tx = store::read(&self.db).await?;
        let account = require_account(&mut tx, id).await?;
        let held: BTreeSet<(String, i64)> =
            store::user_targets(&mut tx, id).await?.into_iter().map(|grant| (grant.kind, grant.id)).collect();
        store::commit(tx).await?;

        let mut wanted: Vec<Grant> = Vec::new();
        for assignment in requested.unwrap_or_default().iter().flatten() {
            let Some(target_id) = assignment.id else { continue };
            let kind = grant_targets::validate(
                self.targets.as_ref(),
                assignment.kind.as_deref(),
                target_id,
                granter,
                |kind, target| held.contains(&(kind.to_owned(), target)),
            )
            .await?;
            let grant = Grant { kind, id: target_id };
            if !wanted.contains(&grant) {
                wanted.push(grant);
            }
        }

        let mut tx = store::write(&self.db).await?;
        store::delete_user_targets(&mut tx, id).await?;
        for grant in &wanted {
            store::insert_user_target(&mut tx, id, &grant.kind, grant.id).await?;
        }
        store::commit(tx).await?;

        // Audited like a role change: it changes what somebody can read, by a gesture just as quiet.
        let assigned = if wanted.is_empty() { "none".to_owned() } else { format!("{} assigned", wanted.len()) };
        record(
            &self.audit,
            actor,
            AuditOperation::UserUpdated,
            id.to_string(),
            format!("Visible targets of {}: {assigned}", account.username),
        )
        .await;
        Ok(self.targets.named(&wanted).await?)
    }
}

async fn require_account(tx: &mut vectispire_cp_db::Tx, id: i64) -> Result<store::AccountBrief, AdminError> {
    store::account(tx, id).await?.ok_or_else(|| AdminError::NotFound("Account not found.".to_owned()))
}
