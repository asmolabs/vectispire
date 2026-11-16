//! What the access routes answer, as Jackson writes the controllers' records: every component, `null` included, in
//! the record's order, under the component names the API publishes (camel case: the responses carry no
//! `@JsonProperty`), an instant as `DateTimeFormatter.ISO_INSTANT`.

use std::fmt::Write as _;

use serde::Serialize;
use time::OffsetDateTime;

use crate::accounts::{AccountRequestView, AccountView};
use crate::api_key_administration::{KeyView, TargetOption, TargetOptions};
use crate::teams::TeamView;
use crate::visibility::TargetGrant;

/// `DateTimeFormatter.ISO_INSTANT`, which Jackson's `InstantSerializer` writes: the fraction only when there is one,
/// in groups of three digits.
pub(crate) fn instant(instant: OffsetDateTime) -> String {
    let utc = instant.to_offset(time::UtcOffset::UTC);
    let mut out = String::with_capacity(30);
    let _ = write!(
        out,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    );
    let nanos = utc.nanosecond();
    if nanos != 0 {
        if nanos.is_multiple_of(1_000_000) {
            let _ = write!(out, ".{:03}", nanos / 1_000_000);
        } else if nanos.is_multiple_of(1_000) {
            let _ = write!(out, ".{:06}", nanos / 1_000);
        } else {
            let _ = write!(out, ".{nanos:09}");
        }
    }
    out.push('Z');
    out
}

/// `UsersController.UserAdminSummary`. Never the password hash: a hash that leaves the server is a hash to crack
/// offline.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UserAdminSummary {
    id: i64,
    username: String,
    email: Option<String>,
    display_name: Option<String>,
    role: String,
    is_active: bool,
    must_change_password: bool,
    /// Bound to an identity provider's subject.
    federated: bool,
    created_at: String,
    active_sessions: u64,
    mfa_enabled: bool,
    scim_managed: bool,
}

impl UserAdminSummary {
    pub(crate) fn of(view: &AccountView) -> UserAdminSummary {
        let user = &view.user;
        UserAdminSummary {
            id: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            display_name: user.display_name.clone(),
            role: user.role.clone(),
            is_active: user.is_active,
            must_change_password: user.must_change_password,
            federated: user.keycloak_id.is_some(),
            created_at: instant(user.created_at),
            active_sessions: view.active_sessions,
            mfa_enabled: user.mfa_enabled,
            scim_managed: user.scim_managed,
        }
    }
}

/// `UserListing`: the page, which account is the caller's own, and how many the list holds.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UserListing {
    pub(crate) users: Vec<UserAdminSummary>,
    pub(crate) current_user_id: Option<i64>,
    pub(crate) total: u64,
}

/// `AccountRequestView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountRequestJson {
    id: i64,
    kind: String,
    account_id: Option<i64>,
    username: String,
    email: Option<String>,
    display_name: Option<String>,
    held_role: Option<String>,
    requested_role: Option<String>,
    password_reset: bool,
    requested_by_id: i64,
    requested_by: String,
    requested_at: String,
}

impl AccountRequestJson {
    pub(crate) fn of(view: &AccountRequestView) -> AccountRequestJson {
        AccountRequestJson {
            id: view.id,
            kind: view.kind.clone(),
            account_id: view.account_id,
            username: view.username.clone(),
            email: view.email.clone(),
            display_name: view.display_name.clone(),
            held_role: view.held_role.clone(),
            requested_role: view.requested_role.clone(),
            password_reset: view.password_reset,
            requested_by_id: view.requested_by_id,
            requested_by: view.requested_by.clone(),
            requested_at: instant(view.requested_at),
        }
    }
}

/// `AccountRequestListing`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccountRequestListing {
    pub(crate) requests: Vec<AccountRequestJson>,
    pub(crate) total: u64,
}

/// `GrantableTargets.TargetGrant`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TargetGrantJson {
    kind: String,
    id: i64,
    name: String,
}

impl TargetGrantJson {
    pub(crate) fn all(grants: &[TargetGrant]) -> Vec<TargetGrantJson> {
        grants
            .iter()
            .map(|grant| TargetGrantJson { kind: grant.kind.clone(), id: grant.id, name: grant.name.clone() })
            .collect()
    }
}

/// `TeamsController.TeamSummary`: whether the team is notified, never where.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TeamSummary {
    id: i64,
    name: String,
    description: Option<String>,
    member_count: i32,
    target_count: i32,
    notified: bool,
}

impl TeamSummary {
    pub(crate) fn of(view: &TeamView) -> TeamSummary {
        TeamSummary {
            id: view.id,
            name: view.name.clone(),
            description: view.description.clone(),
            member_count: view.member_count,
            target_count: view.target_count,
            notified: view.notified,
        }
    }
}

/// `ApiKeysController.ApiKeySummary`: the prefix, never the hash.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiKeySummary {
    /// Hyphenated, as Jackson writes a `UUID`.
    id: String,
    name: String,
    prefix: Option<String>,
    scopes: Vec<String>,
    target_kind: Option<String>,
    target_id: Option<i64>,
    target_label: Option<String>,
    owner: Option<String>,
    created_at: String,
    last_used_at: Option<String>,
    expires_at: Option<String>,
    is_expired: bool,
}

impl ApiKeySummary {
    pub(crate) fn of(key: &KeyView) -> ApiKeySummary {
        ApiKeySummary {
            id: key.id.as_hyphenated().to_string(),
            name: key.name.clone(),
            prefix: key.prefix.clone(),
            scopes: key.scopes.clone(),
            target_kind: key.target_kind.clone(),
            target_id: key.target_id,
            target_label: key.target_label.clone(),
            owner: key.owner.clone(),
            created_at: instant(key.created_at),
            last_used_at: key.last_used_at.map(instant),
            expires_at: key.expires_at.map(instant),
            is_expired: key.expired,
        }
    }
}

/// `IssuedKey`: the key, and the only occurrence of its plaintext.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IssuedKey {
    pub(crate) key: ApiKeySummary,
    pub(crate) secret: String,
}

/// `ApiKeysController.Targets`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyTargets {
    repositories: Vec<TargetOptionJson>,
    containers: Vec<TargetOptionJson>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetOptionJson {
    id: i64,
    label: String,
}

impl KeyTargets {
    pub(crate) fn of(options: &TargetOptions) -> KeyTargets {
        let all = |options: &[TargetOption]| {
            options.iter().map(|option| TargetOptionJson { id: option.id, label: option.label.clone() }).collect()
        };
        KeyTargets { repositories: all(&options.repositories), containers: all(&options.containers) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn an_instant_is_written_as_iso_instant() {
        assert_eq!(instant(datetime!(2026-01-02 03:04:05 UTC)), "2026-01-02T03:04:05Z");
        assert_eq!(instant(datetime!(2026-01-02 03:04:05.120 UTC)), "2026-01-02T03:04:05.120Z");
        assert_eq!(instant(datetime!(2026-01-02 03:04:05.123456 UTC)), "2026-01-02T03:04:05.123456Z");
        assert_eq!(instant(datetime!(2026-01-02 03:04:05.000000001 UTC)), "2026-01-02T03:04:05.000000001Z");
    }
}
