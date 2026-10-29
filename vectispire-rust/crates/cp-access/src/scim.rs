//! What an identity provider may do to accounts and teams through SCIM (RFC 7644) — `ScimProvisioningService`.
//! SCIM's users are the accounts of `t_user`, its groups the teams of `t_team`; the routes (`/scim/v2/Users`,
//! `/scim/v2/Groups`) come with task 1.7 and map [`ScimError`] and the outcomes below to SCIM's error schema.
//!
//! **Deactivating an account closes its sessions in the same gesture.** That is the point of provisioning from a
//! directory: somebody who leaves is out when the directory says so, not when their session happens to expire.
//!
//! **What the directory may not do.** The SCIM token sits in the identity provider's configuration, outside this
//! deployment's control, so:
//! - an administrative account (ADMIN, SUPERUSER) is not the directory's to change — replacing, patching or deleting
//!   one is refused ([`ScimError::ProtectedAccount`], 403);
//! - the directory grants only the roles scoped to what they are given — USER and SECURITY_CHAMPION ([`grantable`]);
//! - an absent role leaves the account's role as it is;
//! - `externalId` is set once and never rebound, and an existing account holding a privileged role or a local second
//!   factor is not bound at all ([`bind_once`]);
//! - a role change closes the account's sessions, as a deactivation does.
//!
//! **SCIM marks its membership rows** ([`ORIGIN_SCIM`]): the OIDC claim's reconciliation removes only its own, so the
//! first sign-in does not carry away what provisioning has just written.
//!
//! **One transaction per gesture.** Java's group writes are one transaction already (`TransactionTemplate`); its
//! account writes are not — a replacement saves the row and then closes the sessions, a deletion closes the sessions
//! and then deletes the row, each its own commit. Here an account's row and the sessions its change closes, and an
//! account's deletion with its sessions, commit together, the row locked from its read to the commit; a group's
//! deletion takes its members, grants and channel with it, as the team administration's does. The answer of a gesture
//! that succeeds is Java's. **The audit entry is written after the commit**, never inside it: a write that rolls back
//! is not recorded.
//!
//! **Two corrections, made on the Java side first** (asmolabs/vectispire#92, see the crate's README): an `externalId`
//! another account is bound to is answered [`UserCreation::ExternalIdTaken`] / [`UserChange::ExternalIdTaken`] — 409
//! `uniqueness` — where the column's unique constraint answered 500. And a PATCH member entry whose `value` is an
//! object or an array names nobody ([`vectispire_domain::scim::member_value_text`]), where it answered 500.

use std::collections::BTreeMap;

use serde_json::Value;
use time::OffsetDateTime;
use vectispire_cp_db::{Db, Tx};
use vectispire_domain::scim::{self, MemberRef, Page, Removal, UserFilter};
use vectispire_domain::{bounded_text, java, team_rules};

use crate::account_rules::validate_username;
use crate::accounts::{Audit, AuditOperation, AuditRecord, Clock, RequestActor, UserView};
use crate::passwords;
use crate::persistence::administration::{self as teams, TeamRow};
use crate::persistence::scim::{self as store, AccountRow, Membership, NewAccountRow};
use crate::roles::{Role, RoleFlags};

/// `TeamMemberEntity.Origin.SCIM`: a membership the directory set, and that only the directory takes away.
pub const ORIGIN_SCIM: &str = "scim";

/// The width of `display_name`, `email` and `keycloak_id`.
const IDENTITY_COLUMN: usize = 255;

/// What every entry this service writes names as its resource.
const RESOURCE: &str = "SCIM";

/// A team the directory creates says where it came from.
const CREATED_VIA_SCIM: &str = "Created via SCIM";

/// An account as the directory describes it, already read out of the SCIM document: every field as received.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserAttributes {
    pub user_name: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub external_id: Option<String>,
    pub active: Option<bool>,
    pub role: Option<String>,
}

/// One operation of a PATCH, its `value` left as the tree the request carried: `None` when absent, `Value::Null`
/// when sent as `null`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PatchOperation {
    pub op: Option<String>,
    pub path: Option<String>,
    pub value: Option<Value>,
}

/// Why a SCIM gesture was refused, or could not be made — what the routes answer in SCIM's error schema.
#[derive(Debug, thiserror::Error)]
pub enum ScimError {
    /// `InvalidInputException`: 400, the message as the `detail`.
    #[error("{0}")]
    InvalidInput(String),
    /// `InvalidFilterException`: 400 with `scimType` `invalidFilter` — never the whole list.
    #[error("{0}")]
    InvalidFilter(String),
    /// `ProtectedAccountException`: 403 rather than 404 — the account exists and the directory may read it, only not
    /// change it.
    #[error("{0}")]
    ProtectedAccount(String),
    /// A statement failed: a 500, **never read as "absent" or "nothing"** (decision 0007).
    #[error("the directory's change could not be read or written: {0}")]
    Failed(String),
}

impl ScimError {
    /// The `scimType` of the refusal (RFC 7644 §3.12), when it has one.
    pub fn scim_type(&self) -> Option<&'static str> {
        match self {
            ScimError::InvalidFilter(_) => Some(scim::INVALID_FILTER),
            _ => None,
        }
    }
}

impl From<crate::persistence::StoreError> for ScimError {
    fn from(error: crate::persistence::StoreError) -> ScimError {
        ScimError::Failed(error.to_string())
    }
}

/// `UserCreation`.
#[derive(Debug, Clone, PartialEq)]
pub enum UserCreation {
    Created(Box<UserView>),
    /// Another account holds this `userName`: 409 `uniqueness`.
    UsernameTaken,
    /// Another account is bound to this `externalId`: 409 `uniqueness`, nothing written.
    ExternalIdTaken,
}

/// A replacement's outcome.
#[derive(Debug, Clone, PartialEq)]
pub enum UserChange {
    Changed(Box<UserView>),
    /// No such account: 404.
    Absent,
    /// Another account is bound to the `externalId` this one would be bound to: 409 `uniqueness`, nothing written.
    ExternalIdTaken,
}

/// `GroupMember`: the member's username, or its identifier when the account is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    pub user_id: i64,
    pub display: String,
}

/// `GroupView`: a team as SCIM describes it — the row's properties under their own names, and its members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    pub id: i64,
    pub name: String,
    pub created_at: OffsetDateTime,
    pub members: Vec<GroupMember>,
}

/// `GroupCreation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupCreation {
    Created(GroupView),
    /// Another team holds this name, whatever its case: 409 `uniqueness`.
    NameTaken,
}

/// `GroupChange`: a replacement's or a patch's outcome. `NameTaken` is a rename to a name another team holds, refused
/// with nothing written — the membership rewrite beside it included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupChange {
    Changed(GroupView),
    Absent,
    NameTaken,
}

/// What the provisioning is built from.
#[allow(missing_debug_implementations)] // a bag of parts, moved into the service at once
pub struct ScimParts<A, C> {
    pub db: Db,
    pub audit: A,
    pub clock: C,
    /// `vectispire.oidc.link-privileged-accounts`: whether the directory may bind a privileged account it did not
    /// create.
    pub link_privileged: bool,
}

/// `ScimProvisioningService`.
pub struct ScimProvisioning<A, C> {
    db: Db,
    audit: A,
    clock: C,
    link_privileged: bool,
}

impl<A, C> std::fmt::Debug for ScimProvisioning<A, C> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScimProvisioning")
            .field("db", &self.db)
            .field("link_privileged", &self.link_privileged)
            .finish_non_exhaustive()
    }
}

impl<A: Audit + Sync, C: Clock + Sync> ScimProvisioning<A, C> {
    pub fn new(parts: ScimParts<A, C>) -> ScimProvisioning<A, C> {
        let ScimParts { db, audit, clock, link_privileged } = parts;
        ScimProvisioning { db, audit, clock, link_privileged }
    }

    // ── users ────────────────────────────────────────────────────────────────────────────────────────────────────

    /// The accounts the filter matches — every one without a filter — by username, all of them or the page
    /// `start_index` and `count` name. A username is unique, so the order is one a page can be cut from. A filter
    /// this endpoint does not evaluate is refused before anything is read.
    pub async fn users(
        &self,
        filter: Option<&str>,
        start_index: Option<i32>,
        count: Option<i32>,
    ) -> Result<Page<UserView>, ScimError> {
        let filter = scim::user_filter(filter).map_err(|refused| ScimError::InvalidFilter(refused.0))?;
        let mut tx = teams::read(&self.db).await?;
        let found = match filter {
            None => store::accounts(&mut tx).await?,
            Some(UserFilter::UserName(name)) => store::account_named(&mut tx, &name).await?.into_iter().collect(),
            Some(UserFilter::ExternalId(subject)) => {
                store::account_bound_to(&mut tx, &subject).await?.into_iter().collect()
            }
        };
        teams::commit(tx).await?;
        Ok(Page::of(found, start_index, count).map(|account| view(&account)))
    }

    /// `user`: `None` when there is no such account.
    pub async fn user(&self, id: i64) -> Result<Option<UserView>, ScimError> {
        let mut tx = teams::read(&self.db).await?;
        let found = store::account(&mut tx, id).await?;
        teams::commit(tx).await?;
        Ok(found.as_ref().map(view))
    }

    /// `createUser`: the name trimmed and lower-cased in the root locale, held to the account rules; a password nobody
    /// knows, so the account signs in through the provider — and not "must change", which held every federated
    /// session of a provisioned account on a screen asking for a password nobody had.
    pub async fn create_user(
        &self,
        attributes: &UserAttributes,
        actor: &RequestActor,
    ) -> Result<UserCreation, ScimError> {
        let username = java::to_lower_root(java::trim(attributes.user_name.as_deref().unwrap_or("")));
        if let Some(refusal) = validate_username(Some(&username)) {
            return Err(ScimError::InvalidInput(refusal));
        }

        let mut tx = teams::write(&self.db).await?;
        if store::account_named(&mut tx, &username).await?.is_some() {
            return Ok(UserCreation::UsernameTaken);
        }
        let display_name = bounded(attributes.display_name.as_deref(), "displayName")?;
        let email = bounded(attributes.email.as_deref(), "emails")?;
        let keycloak_id = bounded(attributes.external_id.as_deref(), "externalId")?;
        let role = grantable(attributes.role.as_deref(), Role::User.name())?;
        // The insert met the unique constraint here and answered 500: the subject is asked first, under the
        // constraint's own comparison, and the directory is told what it can act on.
        if let Some(subject) = &keycloak_id
            && store::account_bound_to(&mut tx, subject).await?.is_some()
        {
            return Ok(UserCreation::ExternalIdTaken);
        }
        let id = store::insert_account(
            &mut tx,
            &NewAccountRow {
                username: username.clone(),
                email,
                display_name,
                keycloak_id,
                is_active: attributes.active.unwrap_or(true),
                role,
                password: passwords::hash_of_nothing_anybody_knows(),
                at: self.clock.now(),
            },
        )
        .await?;
        let saved = store::account(&mut tx, id)
            .await?
            .ok_or_else(|| ScimError::Failed(format!("the account {id} just inserted is not there")))?;
        teams::commit(tx).await?;

        self.record(actor, AuditOperation::UserCreated, &username, format!("SCIM provisioned account: {username}"))
            .await;
        Ok(UserCreation::Created(Box::new(view(&saved))))
    }

    /// `replaceUser`. An absent `active` is active; an absent role, or one this version does not know, keeps the
    /// account's; an absent `externalId` leaves the binding as it is. A role change closes the sessions — the
    /// directory took something away, and an open session would keep it — and so does a deactivation.
    pub async fn replace_user(
        &self,
        id: i64,
        attributes: &UserAttributes,
        actor: &RequestActor,
    ) -> Result<UserChange, ScimError> {
        let mut tx = teams::write(&self.db).await?;
        let Some(mut user) = store::account_to_change(&mut tx, id).await? else {
            return Ok(UserChange::Absent);
        };
        require_provisionable(&user)?;
        let was_active = user.is_active;
        let now_active = attributes.active.unwrap_or(true);
        let previous_role = user.role.clone();
        let role = grantable(attributes.role.as_deref(), &previous_role)?;

        user.display_name = bounded(attributes.display_name.as_deref(), "displayName")?;
        user.email = bounded(attributes.email.as_deref(), "emails")?;
        if let Some(external_id) = bounded(attributes.external_id.as_deref(), "externalId")? {
            let binding = user.keycloak_id.is_none();
            bind_once(&mut user, external_id, self.link_privileged)?;
            // As on creation: asked before the update reaches the unique constraint.
            if binding
                && let Some(subject) = &user.keycloak_id
                && store::account_bound_to(&mut tx, subject).await?.is_some_and(|other| other.id != id)
            {
                return Ok(UserChange::ExternalIdTaken);
            }
        }
        user.is_active = now_active;
        user.role = role.clone();
        user.updated_at = self.clock.now();
        store::update_account(&mut tx, &user).await?;

        let description = if role != previous_role && now_active {
            store::delete_sessions(&mut tx, id).await?;
            format!(
                "SCIM changed the role of {} from {previous_role} to {role} and revoked its sessions",
                user.username
            )
        } else if was_active && !now_active {
            store::delete_sessions(&mut tx, id).await?;
            format!("SCIM deactivated account and revoked all active sessions for {}", user.username)
        } else {
            format!("SCIM updated account: {}", user.username)
        };
        teams::commit(tx).await?;

        self.record(actor, AuditOperation::UserUpdated, &user.username, description).await;
        Ok(UserChange::Changed(Box::new(view(&user))))
    }

    /// `patchUser`: `active` and `displayName`, by path or in an object value; anything else is ignored. Only a
    /// deactivation is recorded, and it closes the sessions. `None` when there is no such account.
    pub async fn patch_user(
        &self,
        id: i64,
        operations: Option<&[PatchOperation]>,
        actor: &RequestActor,
    ) -> Result<Option<UserView>, ScimError> {
        let mut tx = teams::write(&self.db).await?;
        let Some(mut user) = store::account_to_change(&mut tx, id).await? else {
            return Ok(None);
        };
        require_provisionable(&user)?;
        let was_active = user.is_active;
        for operation in operations.unwrap_or_default() {
            apply_patch(&mut user, operation)?;
        }
        user.updated_at = self.clock.now();
        store::update_account(&mut tx, &user).await?;
        let deactivated = was_active && !user.is_active;
        if deactivated {
            store::delete_sessions(&mut tx, id).await?;
        }
        teams::commit(tx).await?;

        if deactivated {
            self.record(
                actor,
                AuditOperation::UserUpdated,
                &user.username,
                format!("SCIM deactivated account and revoked active sessions for {}", user.username),
            )
            .await;
        }
        Ok(Some(view(&user)))
    }

    /// `deleteUser`: idempotent, as RFC 7644 lets it be — an account that is not there is not an error, and records
    /// nothing. The sessions and the row go together; what else names the account goes by the schema's cascades.
    pub async fn delete_user(&self, id: i64, actor: &RequestActor) -> Result<(), ScimError> {
        let mut tx = teams::write(&self.db).await?;
        let Some(user) = store::account_to_change(&mut tx, id).await? else {
            return Ok(());
        };
        require_provisionable(&user)?;
        store::delete_sessions(&mut tx, id).await?;
        store::delete_account(&mut tx, id).await?;
        teams::commit(tx).await?;

        self.record(
            actor,
            AuditOperation::UserDeleted,
            &user.username,
            format!("SCIM deleted account: {}", user.username),
        )
        .await;
        Ok(())
    }

    // ── groups ───────────────────────────────────────────────────────────────────────────────────────────────────

    /// The teams by identifier, with their members, all of them or the page named: two statements whatever the
    /// number of teams — the memberships are read once, with their usernames, and grouped here.
    pub async fn groups(&self, start_index: Option<i32>, count: Option<i32>) -> Result<Page<GroupView>, ScimError> {
        let mut tx = teams::read(&self.db).await?;
        let page = Page::of(teams::teams(&mut tx).await?, start_index, count);
        let mut by_team: BTreeMap<i64, Vec<Membership>> = BTreeMap::new();
        if !page.resources.is_empty() {
            for membership in store::memberships(&mut tx).await? {
                by_team.entry(membership.team_id).or_default().push(membership);
            }
        }
        teams::commit(tx).await?;
        Ok(page.map(|team| group_view(&team, by_team.remove(&team.id).unwrap_or_default())))
    }

    /// `group`: `None` when there is no such team.
    pub async fn group(&self, id: i64) -> Result<Option<GroupView>, ScimError> {
        let mut tx = teams::read(&self.db).await?;
        let Some(team) = teams::team(&mut tx, id).await? else {
            teams::commit(tx).await?;
            return Ok(None);
        };
        let members = store::memberships_of(&mut tx, id).await?;
        teams::commit(tx).await?;
        Ok(Some(group_view(&team, members)))
    }

    /// `createGroup`: each member's value an account id or a username; one naming no account is skipped.
    pub async fn create_group(
        &self,
        display_name: Option<&str>,
        member_values: Option<&[Option<String>]>,
        actor: &RequestActor,
    ) -> Result<GroupCreation, ScimError> {
        let name = group_name(display_name)?;
        let mut tx = teams::write(&self.db).await?;
        if teams::team_named(&mut tx, &name).await?.is_some() {
            return Ok(GroupCreation::NameTaken);
        }
        let team = TeamRow {
            id: 0,
            name: name.clone(),
            description: Some(CREATED_VIA_SCIM.to_owned()),
            created_at: self.clock.now(),
        };
        let id = teams::insert_team(&mut tx, &team.name, team.description.as_deref(), team.created_at).await?;
        for value in member_values.unwrap_or_default() {
            if let Some(user_id) = resolve(&mut tx, value.as_deref()).await? {
                store::put_member(&mut tx, id, user_id, ORIGIN_SCIM).await?;
            }
        }
        let members = store::memberships_of(&mut tx, id).await?;
        teams::commit(tx).await?;

        self.record_group(actor, format!("SCIM created team: {name}"), &name).await;
        Ok(GroupCreation::Created(group_view(&TeamRow { id, ..team }, members)))
    }

    /// `replaceGroup`: the name, when one is given — a blank one is not a rename — and the whole membership, every
    /// member set as the directory's. **A name another team holds is refused before anything is written**, compared
    /// as the creation compares it, whatever its case.
    pub async fn replace_group(
        &self,
        id: i64,
        display_name: Option<&str>,
        member_values: Option<&[Option<String>]>,
        actor: &RequestActor,
    ) -> Result<GroupChange, ScimError> {
        let name = match display_name {
            Some(requested) if !java::is_blank(requested) => Some(group_name(Some(requested))?),
            _ => None,
        };
        let mut tx = teams::write(&self.db).await?;
        let Some(mut team) = teams::team(&mut tx, id).await? else {
            return Ok(GroupChange::Absent);
        };
        if let Some(name) = name {
            if taken_by_another(&mut tx, &name, id).await? {
                return Ok(GroupChange::NameTaken);
            }
            team.name = name;
            teams::update_team(&mut tx, id, &team.name, team.description.as_deref()).await?;
        }
        teams::delete_members(&mut tx, id).await?;
        for value in member_values.unwrap_or_default() {
            if let Some(user_id) = resolve(&mut tx, value.as_deref()).await? {
                store::put_member(&mut tx, id, user_id, ORIGIN_SCIM).await?;
            }
        }
        let members = store::memberships_of(&mut tx, id).await?;
        teams::commit(tx).await?;

        self.record_group(actor, format!("SCIM updated team: {}", team.name), &team.name).await;
        Ok(GroupChange::Changed(group_view(&team, members)))
    }

    /// `patchGroup`: the operations in order, in one transaction — an operation refused rolls back those before it.
    ///
    /// **A rename is an operation too** — `replace` (or `add`) with the path `displayName`, or with no path and
    /// `displayName` in the value — refused as the replacement refuses it. **A `replace` of the members replaces
    /// them** (RFC 7644 §3.5.2.3): whoever the list does not name leaves, whatever set their membership; whoever it
    /// names and was not in joins as the directory's; whoever was in keeps their row. An `add` adds; a `remove` takes
    /// away the member its path names, or everybody.
    pub async fn patch_group(
        &self,
        id: i64,
        operations: Option<&[PatchOperation]>,
        actor: &RequestActor,
    ) -> Result<GroupChange, ScimError> {
        let mut tx = teams::write(&self.db).await?;
        let Some(mut team) = teams::team(&mut tx, id).await? else {
            return Ok(GroupChange::Absent);
        };
        for operation in operations.unwrap_or_default() {
            let kind = java::to_lower_root(operation.op.as_deref().unwrap_or(""));
            if kind == "add" || kind == "replace" {
                if let Some(rename) = rename_of(operation)? {
                    if taken_by_another(&mut tx, &rename, id).await? {
                        // Dropped without a commit: what the operations before it wrote is rolled back.
                        return Ok(GroupChange::NameTaken);
                    }
                    team.name = rename;
                    teams::update_team(&mut tx, id, &team.name, team.description.as_deref()).await?;
                }
                let replacement = if kind == "replace" { member_replacement_of(operation)? } else { None };
                match replacement {
                    Some(items) => replace_members(&mut tx, id, items).await?,
                    None => add_members(&mut tx, id, operation.value.as_ref()).await?,
                }
            } else if kind == "remove" {
                match scim::removal(operation.path.as_deref()) {
                    Removal::One(value) => {
                        if let Some(user_id) = resolve(&mut tx, Some(&value)).await? {
                            store::delete_member(&mut tx, id, user_id).await?;
                        }
                    }
                    Removal::Everyone => {
                        teams::delete_members(&mut tx, id).await?;
                    }
                    Removal::Nothing => {}
                }
            }
        }
        let members = store::memberships_of(&mut tx, id).await?;
        teams::commit(tx).await?;

        self.record_group(actor, format!("SCIM patched team: {}", team.name), &team.name).await;
        Ok(GroupChange::Changed(group_view(&team, members)))
    }

    /// `deleteGroup`: idempotent — a team that is not there is not an error, and records nothing. Its memberships, its
    /// grants and its channel go with the row, in one transaction, as the team administration deletes a team.
    pub async fn delete_group(&self, id: i64, actor: &RequestActor) -> Result<(), ScimError> {
        let mut tx = teams::write(&self.db).await?;
        let Some(team) = teams::team(&mut tx, id).await? else {
            return Ok(());
        };
        teams::delete_members(&mut tx, id).await?;
        teams::delete_team_targets(&mut tx, id).await?;
        teams::delete_webhook(&mut tx, id).await?;
        teams::delete_team(&mut tx, id).await?;
        teams::commit(tx).await?;

        self.record_group(actor, format!("SCIM deleted team: {}", team.name), &team.name).await;
        Ok(())
    }

    /// The entry of an account's gesture: under `SCIM`, attributed to the account's username, as Java writes it.
    async fn record(&self, actor: &RequestActor, operation: AuditOperation, username: &str, description: String) {
        self.audit
            .record(AuditRecord {
                operation,
                resource: RESOURCE.to_owned(),
                description,
                username: Some(username.to_owned()),
                ip_address: actor.ip_address.clone(),
                user_agent: actor.user_agent.clone(),
                signal: None,
            })
            .await;
    }

    /// The entry of a group's gesture, written once its transaction has committed: `TEAM_UPDATED`, attributed to the
    /// team's name, as these entries always were.
    async fn record_group(&self, actor: &RequestActor, description: String, team_name: &str) {
        self.record(actor, AuditOperation::TeamUpdated, team_name, description).await;
    }
}

/// `UserView.of`.
fn view(account: &AccountRow) -> UserView {
    UserView {
        id: account.id,
        username: account.username.clone(),
        email: account.email.clone(),
        display_name: account.display_name.clone(),
        avatar_url: account.avatar_url.clone(),
        role: account.role.clone(),
        is_active: account.is_active,
        github_id: account.github_id.clone(),
        keycloak_id: account.keycloak_id.clone(),
        created_at: account.created_at,
        updated_at: account.updated_at,
        must_change_password: account.must_change_password,
        mfa_enabled: account.mfa_enabled,
    }
}

/// `viewOf`: a member is named by its username, or by its identifier when the account is gone.
fn group_view(team: &TeamRow, members: Vec<Membership>) -> GroupView {
    GroupView {
        id: team.id,
        name: team.name.clone(),
        created_at: team.created_at,
        members: members
            .into_iter()
            .map(|membership| GroupMember {
                user_id: membership.user_id,
                display: membership.username.unwrap_or_else(|| membership.user_id.to_string()),
            })
            .collect(),
    }
}

/// `applyPatch`: `active` by its path with a boolean, or `active` and `displayName` in an object value, whatever the
/// operation — the display name held to its column, not trimmed.
fn apply_patch(user: &mut AccountRow, operation: &PatchOperation) -> Result<(), ScimError> {
    let path = java::to_lower_root(operation.path.as_deref().unwrap_or(""));
    match &operation.value {
        Some(Value::Bool(active)) if path == "active" => user.is_active = *active,
        Some(Value::Object(fields)) => {
            if let Some(Value::Bool(active)) = fields.get("active") {
                user.is_active = *active;
            }
            if let Some(Value::String(name)) = fields.get("displayName") {
                user.display_name = bounded(Some(name), "displayName")?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// `grantable`: the role the directory asked for, if it may grant it. `unchanged` is what to keep when the document
/// names no role, or one this version does not know: the account's own on a replacement, USER on a creation.
///
/// **Not a role that administers or sees the whole estate**: the token held in the identity provider — a third system,
/// with its own operators — could otherwise make any account a CISO or an auditor. Naming the role an account already
/// holds is not a grant, so a directory that sends it back on every replacement is not refused.
fn grantable(requested: Option<&str>, unchanged: &str) -> Result<String, ScimError> {
    let role = requested.and_then(|requested| Role::of(Some(&java::to_upper_root(java::trim(requested)))));
    match role {
        None => Ok(unchanged.to_owned()),
        Some(role) if role.name() == unchanged => Ok(unchanged.to_owned()),
        Some(role) if role.administers() || role.has_global_security_scope() => Err(ScimError::InvalidInput(format!(
            "SCIM cannot grant the {} role: roles that administer or see the whole estate are granted in Vectispire.",
            role.name()
        ))),
        Some(role) => Ok(role.name().to_owned()),
    }
}

/// `requireProvisionable`: an administrative account is not the directory's to change.
fn require_provisionable(user: &AccountRow) -> Result<(), ScimError> {
    if Role::of(Some(&user.role)).is_some_and(Role::administers) {
        return Err(ScimError::ProtectedAccount(format!(
            "The account \"{}\" holds an administrative role and is administered in Vectispire, not through SCIM.",
            user.username
        )));
    }
    Ok(())
}

/// `bounded`: an attribute the provider sent, refused when its column cannot hold it — a truncated address is somebody
/// else's, a truncated subject one that does not exist. Not trimmed.
fn bounded(value: Option<&str>, attribute: &str) -> Result<Option<String>, ScimError> {
    value
        .map(|value| {
            bounded_text::within(value, IDENTITY_COLUMN, &format!("The SCIM attribute {attribute}"))
                .map(str::to_owned)
                .map_err(|refused| ScimError::InvalidInput(refused.0))
        })
        .transpose()
}

/// `bindOnce`: the identity provider's subject is set once. Rebinding it is how an account is taken over — the next
/// sign-in with the new subject lands on it. **A first binding is a takeover too, of an account that holds
/// something**: a privileged account (`ExternalIdentityService.privileged`, an unreadable role counting as one) is
/// not bound by the directory unless the operator allows privileged linking, and one with a local second factor never
/// is. A binding the account already has is not a binding, and passes.
fn bind_once(user: &mut AccountRow, external_id: String, link_privileged: bool) -> Result<(), ScimError> {
    match &user.keycloak_id {
        Some(bound) if *bound != external_id => {
            return Err(ScimError::InvalidInput(
                "externalId is immutable once set: this account is already bound to another identity-provider \
                 subject."
                    .to_owned(),
            ));
        }
        Some(_) => {}
        None => {
            if user.mfa_enabled {
                return Err(ScimError::InvalidInput(
                    "This account has a local second factor, so the directory does not bind it to an \
                     identity-provider subject; an administrator does, in Vectispire."
                        .to_owned(),
                ));
            }
            if Role::of(Some(&user.role)).is_none_or(privileged) && !link_privileged {
                return Err(ScimError::InvalidInput(
                    "This account holds a privileged role, so the directory does not bind it to an identity-provider \
                     subject; an administrator does, in Vectispire."
                        .to_owned(),
                ));
            }
        }
    }
    user.keycloak_id = Some(external_id);
    Ok(())
}

/// `ExternalIdentityService.privileged`: everything but a plain account — a role that administers, governs, sees the
/// whole estate's security, writes governance or approves triage.
fn privileged(role: Role) -> bool {
    role.administers()
        || role.governs_platform()
        || role.has_global_security_scope()
        || role.can_write_governance()
        || role.can_approve_triage()
}

/// `groupName`: trimmed, present, and within the column — a name past it was a 500 from the insert.
fn group_name(display_name: Option<&str>) -> Result<String, ScimError> {
    let name = java::trim(display_name.unwrap_or(""));
    if name.is_empty() {
        return Err(ScimError::InvalidInput("Group displayName cannot be blank.".to_owned()));
    }
    bounded_text::within(name, team_rules::MAX_NAME_LENGTH, "The SCIM attribute displayName")
        .map(str::to_owned)
        .map_err(|refused| ScimError::InvalidInput(refused.0))
}

/// `renameOf`: the name a PATCH operation sets, if it sets one; refused when it is not a name.
fn rename_of(operation: &PatchOperation) -> Result<Option<String>, ScimError> {
    let named = match operation.path.as_deref() {
        Some(path) if !java::is_blank(path) => {
            if java::to_lower_root(java::trim(path)) != "displayname" {
                return Ok(None);
            }
            operation.value.as_ref()
        }
        _ => match &operation.value {
            Some(Value::Object(fields)) if fields.contains_key("displayName") => fields.get("displayName"),
            _ => return Ok(None),
        },
    };
    match named {
        Some(Value::String(name)) => group_name(Some(name)).map(Some),
        _ => Err(ScimError::InvalidInput("Group displayName must be a string.".to_owned())),
    }
}

/// `memberReplacementOf`: the member list a `replace` sets, if it sets one — the value of the path `members`, or the
/// `members` of a value without a path. Refused when it is not a list, rather than read as nothing: an empty list is
/// a statement (nobody), an unreadable one is not.
fn member_replacement_of(operation: &PatchOperation) -> Result<Option<&[Value]>, ScimError> {
    let list = match operation.path.as_deref() {
        Some(path) if !java::is_blank(path) => {
            if java::to_lower_root(java::trim(path)) != "members" {
                return Ok(None);
            }
            operation.value.as_ref()
        }
        _ => match &operation.value {
            Some(Value::Object(fields)) if fields.contains_key("members") => fields.get("members"),
            _ => return Ok(None),
        },
    };
    match list {
        Some(Value::Array(items)) => Ok(Some(items)),
        _ => Err(ScimError::InvalidInput("Group members must be a list.".to_owned())),
    }
}

/// `replaceMembers`: the team's members become exactly the accounts listed. The others' memberships are removed,
/// whatever set them; the listed accounts not yet in join as the directory's; a listed account already a member keeps
/// its row, and the channel that set it. An entry naming no account is skipped, so a list of unknown accounts empties
/// the team: what the directory said is that none of the people it knows remains.
async fn replace_members(tx: &mut Tx, team_id: i64, items: &[Value]) -> Result<(), ScimError> {
    let mut listed: Vec<i64> = Vec::new();
    for value in items.iter().filter_map(entry_value) {
        if let Some(user_id) = resolve(tx, scim::member_value_text(value).as_deref()).await?
            && !listed.contains(&user_id)
        {
            listed.push(user_id);
        }
    }
    let current = teams::members_of(tx, team_id).await?;
    for user_id in current.iter().filter(|user_id| !listed.contains(user_id)) {
        store::delete_member(tx, team_id, *user_id).await?;
    }
    for user_id in listed.iter().filter(|user_id| !current.contains(user_id)) {
        store::put_member(tx, team_id, *user_id, ORIGIN_SCIM).await?;
    }
    Ok(())
}

/// `handleAddMembers`: the entries of a list value, or of a value's `members` list; anything else adds nobody. An
/// account already a member is the directory's from then on, as Java's merge of the pairing makes it.
async fn add_members(tx: &mut Tx, team_id: i64, value: Option<&Value>) -> Result<(), ScimError> {
    let items = match value {
        Some(Value::Array(items)) => items,
        Some(Value::Object(fields)) => match fields.get("members") {
            Some(Value::Array(items)) => items,
            _ => return Ok(()),
        },
        _ => return Ok(()),
    };
    for value in items.iter().filter_map(entry_value) {
        if let Some(user_id) = resolve(tx, scim::member_value_text(value).as_deref()).await? {
            store::put_member(tx, team_id, user_id, ORIGIN_SCIM).await?;
        }
    }
    Ok(())
}

/// `item.has("value")`: an entry's `value`, when the entry is an object that carries one, `null` included.
fn entry_value(item: &Value) -> Option<&Value> {
    item.as_object().and_then(|entry| entry.get("value"))
}

/// `resolveUserId`: the account a member's value names — an identifier an account holds, or a username — and nothing
/// otherwise. An identifier no account holds is skipped, as an unknown name is: it reached the insert, and the foreign
/// key answered the whole request 500.
async fn resolve(tx: &mut Tx, value: Option<&str>) -> Result<Option<i64>, ScimError> {
    Ok(match scim::member_ref(value) {
        None => None,
        Some(MemberRef::Id(id)) => teams::account(tx, id).await?.map(|account| account.id),
        Some(MemberRef::UserName(name)) => store::account_named(tx, &name).await?.map(|account| account.id),
    })
}

/// `takenByAnother`: a team other than `id` holds `name`, whatever its case.
async fn taken_by_another(tx: &mut Tx, name: &str, id: i64) -> Result<bool, ScimError> {
    Ok(teams::team_named(tx, name).await?.is_some_and(|other| other.id != id))
}
