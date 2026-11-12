//! An API key's rules — `common.domain.apikeys.ApiKeys` and `ApiKeyScope`, and the parts of `ApiKeyAuthService` and
//! `ApiKeyAdministrationService` that decide something without reading a table.
//!
//! A key is `zsk_` and 43 base64url characters. Its first twelve characters are stored in the clear, because they
//! are not a secret and they narrow the candidates of a lookup to one or two rows: without them, checking a key would
//! cost one Argon2 derivation per stored key on every request — a denial of service offered to anybody.

use rand_core::{OsRng, RngCore};
use vectispire_cp_db::{ScanTarget, Visibility};
use vectispire_cp_http::ApiKeyScope;
use vectispire_domain::secret::Secret;

use super::sessions::base64_url;
use super::text::{java_is_blank, java_split, java_trim, utf16_len};

pub const KEY_PREFIX: &str = "zsk";
/// `KEY_PREFIX.length() + 9`: `zsk_` and eight characters of the secret.
pub const PREFIX_LENGTH: usize = 12;
const SECRET_BYTES: usize = 32;
const MAX_LIFETIME_DAYS: i32 = 3650;
const MAX_NAME_LENGTH: usize = 100;

/// Every scope, in the enum's order — the order a key's stored scopes are written in.
pub const SCOPES: [ApiKeyScope; 6] = [
    ApiKeyScope::Read,
    ApiKeyScope::Scan,
    ApiKeyScope::Export,
    ApiKeyScope::SarifImport,
    ApiKeyScope::ReportImport,
    ApiKeyScope::Agent,
];

/// `ApiKeyScope.defaults()`: what an integration key gets when nobody names its scopes. Importing results is not
/// among them — a key that writes what the gate reads is asked for by name — and neither is `agent`.
pub const DEFAULT_SCOPES: [ApiKeyScope; 3] = [ApiKeyScope::Read, ApiKeyScope::Scan, ApiKeyScope::Export];

/// A key as it is handed out once: the whole key, and the prefix stored beside its hash.
#[derive(Debug)]
pub struct IssuedKey {
    pub full_key: Secret,
    pub prefix: String,
}

/// `ApiKeys.generate()`.
pub fn generate() -> IssuedKey {
    let mut secret = [0u8; SECRET_BYTES];
    OsRng.fill_bytes(&mut secret);
    let full_key = format!("{KEY_PREFIX}_{}", base64_url(&secret));
    secret.iter_mut().for_each(|byte| *byte = 0);
    let prefix = full_key.get(..PREFIX_LENGTH).unwrap_or_default().to_owned();
    IssuedKey { full_key: Secret::new(full_key), prefix }
}

/// The prefix a presented key is looked up by, or `None` when it is too short to be one — `presented.trim()` no
/// longer than twelve characters, counted as Java counts them.
///
/// A twelve-unit prefix that is not plain ASCII can name no stored key (every stored prefix is `zsk_` and base64url),
/// so it is `None` here where Java would run a lookup that finds nothing: the same answer, one query fewer.
pub fn lookup_prefix(trimmed: &str) -> Option<&str> {
    if utf16_len(trimmed) <= PREFIX_LENGTH {
        return None;
    }
    trimmed.get(..PREFIX_LENGTH).filter(|prefix| prefix.is_ascii())
}

/// `ApiKeyScope.fromWireName`: trimmed, lower-cased, and equal to a scope's name.
pub fn scope_from_wire_name(value: &str) -> Option<ApiKeyScope> {
    if java_is_blank(value) {
        return None;
    }
    let normalized = java_trim(value).to_lowercase();
    SCOPES.into_iter().find(|scope| scope.wire_name() == normalized)
}

/// `ApiKeyAuthService.hasScope`: the stored scopes split on commas, each trimmed, one equal to the scope's name —
/// **case and all**: a scope stored as `Read` grants nothing, because nothing on the Java side writes it so.
pub fn has_scope(stored: Option<&str>, scope: ApiKeyScope) -> bool {
    java_split(stored.unwrap_or(""), ',').into_iter().map(java_trim).any(|piece| piece == scope.wire_name())
}

/// The scopes a stored list grants, in the enum's order.
pub fn scopes_of(stored: Option<&str>) -> Vec<ApiKeyScope> {
    SCOPES.into_iter().filter(|scope| has_scope(stored, *scope)).collect()
}

/// `ApiKeyAuthService.restrictionOf`: everything when unrestricted, otherwise the one target the key was issued for.
/// A kind nobody wrote is a key nobody understands: it sees nothing, never everything.
pub fn restriction_of(target_kind: Option<&str>, target_id: Option<i64>) -> Visibility {
    match (target_kind, target_id) {
        (Some("repository"), Some(id)) => Visibility::only([ScanTarget::Repository(id)]),
        (Some("container"), Some(id)) => Visibility::only([ScanTarget::Container(id)]),
        (Some(_), Some(_)) => Visibility::only([]),
        _ => Visibility::everything(),
    }
}

/// Why a key is not issued — each sentence is the Java one, which the problem document carries.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IssueRefusal {
    /// `InvalidInputException`.
    #[error("{0}")]
    InvalidInput(String),
    /// `InvalidApiKeyException`.
    #[error("{0}")]
    InvalidKey(String),
}

impl IssueRefusal {
    fn key(message: impl Into<String>) -> IssueRefusal {
        IssueRefusal::InvalidKey(message.into())
    }
}

/// `ApiKeys.normalizeScopes`: the defaults for nothing asked, an error for a list of blanks or a name nobody knows,
/// otherwise the scopes asked for in the enum's order. `None` in the list is Java's `null` element, skipped.
pub fn normalize_scopes(requested: Option<&[Option<String>]>) -> Result<Vec<ApiKeyScope>, IssueRefusal> {
    let Some(requested) = requested.filter(|list| !list.is_empty()) else {
        return Ok(DEFAULT_SCOPES.to_vec());
    };
    let cleaned: Vec<&str> =
        requested.iter().flatten().filter(|scope| !java_is_blank(scope)).map(|scope| java_trim(scope)).collect();
    if cleaned.is_empty() {
        return Err(IssueRefusal::key("A key with no scope at all could do nothing."));
    }
    let mut unknown = Vec::new();
    let mut granted = Vec::new();
    for candidate in cleaned {
        match scope_from_wire_name(candidate) {
            Some(scope) => granted.push(scope),
            // Refused rather than ignored: a caller who misspells `agent` and gets a working key will believe the
            // scope was granted.
            None => unknown.push(candidate),
        }
    }
    if !unknown.is_empty() {
        return Err(IssueRefusal::key(format!("Unknown scope(s): {}", unknown.join(", "))));
    }
    Ok(SCOPES.into_iter().filter(|scope| granted.contains(scope)).collect())
}

/// `ApiKeys.normalizeLifetime`: no lifetime, or a number of days between 1 and 3650.
pub fn normalize_lifetime(expires_in_days: Option<i32>) -> Result<Option<i32>, IssueRefusal> {
    match expires_in_days {
        None => Ok(None),
        Some(days) if (1..=MAX_LIFETIME_DAYS).contains(&days) => Ok(Some(days)),
        Some(_) => Err(IssueRefusal::key(format!(
            "Invalid lifetime: a number of days between 1 and {MAX_LIFETIME_DAYS}, or nothing."
        ))),
    }
}

/// The name of a key, `trim()`med: required, and at most a hundred characters.
pub fn normalize_name(name: Option<&str>) -> Result<String, IssueRefusal> {
    let name = java_trim(name.unwrap_or(""));
    if name.is_empty() {
        return Err(IssueRefusal::InvalidInput("A name is required.".to_owned()));
    }
    if utf16_len(name) > MAX_NAME_LENGTH {
        return Err(IssueRefusal::key(format!("A key's name is at most {MAX_NAME_LENGTH} characters.")));
    }
    Ok(name.to_owned())
}

/// The target a restricted key is issued for, if any — `normalizeTargetKind`: both a kind and an id, or neither.
pub fn normalize_target(kind: Option<&str>, id: Option<i64>) -> Result<Option<ScanTarget>, IssueRefusal> {
    // `toLowerCase(Locale.ROOT)`: the refusal quotes the kind, and Rust's `to_lowercase` places a final sigma by
    // Unicode's rule where Java's root locale uses its word iterator.
    let kind = vectispire_domain::java::to_lower_root(java_trim(kind.unwrap_or("")));
    if kind.is_empty() && id.is_none() {
        return Ok(None);
    }
    let Some(id) = id.filter(|_| !kind.is_empty()) else {
        return Err(IssueRefusal::key("A restricted key needs both a target kind and a target id."));
    };
    match kind.as_str() {
        "repository" => Ok(Some(ScanTarget::Repository(id))),
        "container" => Ok(Some(ScanTarget::Container(id))),
        _ => Err(IssueRefusal::key(format!("Unknown target kind: \"{kind}\"."))),
    }
}

/// The stored `target_kind` of a target.
pub fn kind_of(target: ScanTarget) -> (&'static str, i64) {
    match target {
        ScanTarget::Repository(id) => ("repository", id),
        ScanTarget::Container(id) => ("container", id),
    }
}

/// The scopes as `t_api_key.scopes` holds them: wire names, comma-joined, in the enum's order.
pub fn stored_scopes(scopes: &[ApiKeyScope]) -> String {
    scopes.iter().map(|scope| scope.wire_name()).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_zsk_and_43_characters_with_a_twelve_character_prefix() {
        let key = generate();
        assert_eq!(key.full_key.expose().len(), 47);
        assert!(key.full_key.expose().starts_with("zsk_"));
        assert_eq!(key.prefix, key.full_key.expose().get(..12).unwrap());
        assert_eq!(lookup_prefix(key.full_key.expose()), Some(key.prefix.as_str()));
        assert_eq!(lookup_prefix("zsk_abcdefgh"), None, "twelve characters are a prefix, not a key");
    }

    #[test]
    fn a_stored_scope_matches_only_as_written() {
        assert!(has_scope(Some("read,scan,export"), ApiKeyScope::Scan));
        assert!(has_scope(Some(" read , scan "), ApiKeyScope::Scan));
        assert!(!has_scope(Some("Read"), ApiKeyScope::Read));
        assert!(!has_scope(Some(""), ApiKeyScope::Read));
        assert!(!has_scope(None, ApiKeyScope::Read));
        assert_eq!(scopes_of(Some("agent,read")), vec![ApiKeyScope::Read, ApiKeyScope::Agent]);
    }

    #[test]
    fn a_restriction_names_one_target_or_nothing_never_everything_by_mistake() {
        assert_eq!(restriction_of(None, None), Visibility::everything());
        assert_eq!(restriction_of(Some("repository"), None), Visibility::everything());
        assert_eq!(restriction_of(Some("repository"), Some(4)), Visibility::only([ScanTarget::Repository(4)]));
        assert_eq!(restriction_of(Some("container"), Some(4)), Visibility::only([ScanTarget::Container(4)]));
        assert_eq!(restriction_of(Some("solution"), Some(4)), Visibility::only([]));
    }

    #[test]
    fn issuing_refuses_with_the_java_sentences() {
        assert_eq!(normalize_name(Some("  ")), Err(IssueRefusal::InvalidInput("A name is required.".into())));
        assert!(normalize_name(Some(&"x".repeat(100))).is_ok());
        assert!(normalize_name(Some(&"x".repeat(101))).is_err());
        assert_eq!(normalize_target(Some(" Repository "), Some(3)), Ok(Some(ScanTarget::Repository(3))));
        assert_eq!(normalize_target(Some(""), None), Ok(None));
        assert_eq!(
            normalize_target(Some("repository"), None),
            Err(IssueRefusal::key("A restricted key needs both a target kind and a target id."))
        );
        assert_eq!(normalize_target(Some("team"), Some(1)), Err(IssueRefusal::key("Unknown target kind: \"team\".")));
        // Lower-cased in the root locale: Java's word iterator runs across the hyphen, so both sigmas are medial.
        assert_eq!(normalize_target(Some("ΣΣ-ı"), Some(1)), Err(IssueRefusal::key("Unknown target kind: \"σσ-ı\".")));
    }
}
