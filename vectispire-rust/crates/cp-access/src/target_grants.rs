//! `TargetGrants`: the grants naming one target, to accounts and to teams — and the integration keys restricted to
//! it — revoked together when the target is deleted.
//!
//! **Why anybody outside `access` needs this.** A grant names its target as `(kind, id)`, which no foreign key can
//! follow into three tables, so nothing cascades: whoever deletes a repository, an image or a project has to revoke
//! what names it, or the row stays on the grant screens — and, should an engine hand the identifier out again,
//! grants a target nobody chose. `access` sits below `targets`, so it cannot hear `targets`' deletion event; the
//! deletion calls this, in its own transaction and before the purge's first phase (decision 0029).
//!
//! **The key itself goes, never its restriction.** A key without a restriction acts with its account's whole
//! visibility: clearing the restriction would wake the pipeline key for one repository up reading the estate.

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;
use vectispire_cp_db::Tx;

use crate::persistence::StoreError;
use crate::persistence::target_grants;

/// A key revoked with its target, as its audit entry names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokedKey {
    pub id: Uuid,
    pub name: String,
}

/// What went with a target: how many grants, and which keys — named, because each revoked key is an audit entry of
/// its own, filed under the key's id where whoever runs the pipeline looks.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Revoked {
    pub grants: u64,
    pub keys: Vec<RevokedKey>,
}

impl Revoked {
    /// Whether anybody's access changed — the deletion's entry signals it when so.
    pub fn changed_access(&self) -> bool {
        self.grants > 0 || !self.keys.is_empty()
    }

    /// For the deletion's audit entry: what went with the target, in words.
    pub fn summary(&self) -> String {
        format!("{} grant(s) and {} API key(s) revoked", self.grants, self.keys.len())
    }
}

/// Who holds a grant naming one project: accounts directly, and teams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grantees {
    pub accounts: i64,
    pub teams: i64,
}

/// `revokeAll(kind, id)`, in the caller's transaction: every grant naming the target, then the integration keys
/// restricted to it — read, then deleted by id, so that the entries name exactly the rows that went. An agent's key
/// (no owner) belongs to its agent and is left.
pub async fn revoke_all(tx: &mut Tx, kind: &str, target_id: i64) -> Result<Revoked, StoreError> {
    let grants = target_grants::delete_grants(tx, kind, target_id).await?;
    let restricted = target_grants::keys_restricted_to(tx, kind, target_id).await?;
    for key in &restricted {
        target_grants::delete_key(tx, key.id).await?;
    }
    Ok(Revoked { grants, keys: restricted.into_iter().map(|key| RevokedKey { id: key.id, name: key.name }).collect() })
}

/// `granteesOfProjects`: the grantees of each of these projects that has any; a project missing from the answer
/// has none.
pub async fn grantees_of_projects(
    tx: &mut Tx,
    projects: &BTreeSet<i64>,
) -> Result<BTreeMap<i64, Grantees>, StoreError> {
    let mut granted = BTreeMap::new();
    for project in projects {
        let (accounts, teams) = target_grants::count_grantees(tx, crate::visibility::KIND_PROJECT, *project).await?;
        if accounts > 0 || teams > 0 {
            granted.insert(*project, Grantees { accounts, teams });
        }
    }
    Ok(granted)
}
