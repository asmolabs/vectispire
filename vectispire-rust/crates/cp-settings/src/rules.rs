//! What the catalog answers about a setting beyond its definition: who may write it, whether it is withheld, and
//! what it accepts — `Setting`'s methods, as Java writes them.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use vectispire_domain::repository_url::java_uri;

use crate::catalog::Setting;
use crate::types::{Section, Sensitivity, SettingType};

/// `RepositoryUrl.USER_INFO`.
static USER_INFO: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new("^([A-Za-z][A-Za-z0-9+.-]*://)([^/]*)@").ok());

impl Setting {
    pub const fn key(self) -> &'static str {
        self.definition().key
    }

    pub const fn setting_type(self) -> SettingType {
        self.definition().setting_type
    }

    pub const fn section(self) -> Section {
        self.definition().section
    }

    pub const fn label(self) -> &'static str {
        self.definition().label
    }

    pub const fn help(self) -> &'static str {
        self.definition().help
    }

    pub const fn default_value(self) -> &'static str {
        self.definition().default_value
    }

    pub const fn sensitivity(self) -> Sensitivity {
        self.definition().sensitivity
    }

    /// Whether the value must be withheld from a non-administrator — true for both protected kinds: a reader
    /// that asked only for `Secret` would serve credentials to ordinary accounts the moment one was reclassified.
    pub const fn is_secret(self) -> bool {
        matches!(self.sensitivity(), Sensitivity::Secret | Sensitivity::Encrypted)
    }

    /// Whether this is a credential: encrypted at rest, written by its own route, never returned.
    pub const fn is_encrypted(self) -> bool {
        matches!(self.sensitivity(), Sensitivity::Encrypted)
    }

    /// Whether only an administrator may change it: a setting that decides where a credential is sent, the
    /// switches that open the internal network to the SIEM export and to the notification channels, and the
    /// tracker token's declared expiry, which describes a credential only an administrator sets.
    pub const fn administrator_only(self) -> bool {
        self.directs_credential().is_some()
            || matches!(
                self,
                Setting::TicketTokenExpiresOn
                    | Setting::SiemAllowPrivateDestination
                    | Setting::NotificationAllowPrivateUrl
            )
    }

    /// `None` when the value is acceptable, otherwise the message to show.
    ///
    /// **The tracker's address carries no credential**: a user name or a token typed into it is a second,
    /// unencrypted copy of the token, in a column the token's own route never reaches, shown back on the screen.
    pub fn validate(self, value: Option<&str>) -> Option<String> {
        if self == Setting::TicketBaseUrl && value.is_some_and(carries_user_info) {
            return Some(
                "the address carries a user name or a token: type the address alone, the token has a field of its own."
                    .to_owned(),
            );
        }
        self.setting_type().validate(value)
    }

    /// A key's definition, or `None` when it is not exposed — a removed setting's row is not an error, it is a
    /// setting nobody asks for any more.
    pub fn by_key(key: &str) -> Option<Setting> {
        Setting::ALL.into_iter().find(|setting| setting.key() == key)
    }

    /// The defaults, so a reader knows what an absent key is worth.
    pub fn defaults() -> BTreeMap<&'static str, &'static str> {
        Setting::ALL.into_iter().map(|setting| (setting.key(), setting.default_value())).collect()
    }
}

/// `Setting.carriesUserInfo`: `RepositoryUrl.carriesCredential`, or `new URI(value.trim()).getRawUserInfo()`
/// not null — which is what an `ssh://git@host` address and a scheme-less `//user@host` are caught by.
fn carries_user_info(value: &str) -> bool {
    let trimmed = value.trim_matches(|c: char| c <= ' ');
    carries_credential(trimmed) || raw_user_info(trimmed)
}

/// `RepositoryUrl.carriesCredential`: a user before the host, except the bare user of an `ssh://` address.
fn carries_credential(trimmed: &str) -> bool {
    let Some(captures) = USER_INFO.as_ref().and_then(|pattern| pattern.captures(trimmed)) else { return false };
    let scheme = captures.get(1).map_or("", |group| group.as_str());
    let user = captures.get(2).map_or("", |group| group.as_str());
    !scheme.eq_ignore_ascii_case("ssh://") || user.contains(':')
}

/// Whether `java.net.URI` parses the text with a server-based authority holding a user part: the parse succeeds,
/// a host was read, and the authority — `//` to the first `/`, `?` or `#` — has an `@`.
fn raw_user_info(trimmed: &str) -> bool {
    let Ok(parsed) = java_uri::parse(trimmed) else { return false };
    if parsed.host.is_none() {
        return false;
    }
    let after_scheme = match (&parsed.scheme, trimmed.split_once(':')) {
        (Some(_), Some((_, rest))) => rest,
        _ => trimmed,
    };
    after_scheme
        .strip_prefix("//")
        .is_some_and(|rest| rest.split(['/', '?', '#']).next().is_some_and(|authority| authority.contains('@')))
}
