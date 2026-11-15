//! The settings catalog and its save — `SettingsController`'s first two routes:
//!
//! - `GET /api/v1/settings` (`list`): any account — every setting with its type, section, label, help, default, the
//!   value this reader may see, and who may change it;
//! - `PUT /api/v1/settings` (`update`): a security lead — the body a JSON object of keys to values, every change
//!   validated before any is written, answered `{"updated": n}`.
//!
//! The other ten routes of the controller — the four credential doors, their states, the tracker CA's description and
//! the AI endpoint check — wait for `tickets`, `notifications` and `ai` (`README.md`).

use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode, header};
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use vectispire_cp_audit::RequestActor;
use vectispire_cp_http::access::Access;
use vectispire_cp_http::extract::JsonBody;
use vectispire_cp_http::routes::{Route, RouteEntry};
use vectispire_cp_http::{Caller, ClientAddress, Problem};

use super::{bad_request, ok, unexpected};
use crate::settings::{AdministrationError, Entry, SettingsAdministration};

pub(super) const SETTINGS: &str = "/api/v1/settings";

/// `SettingView` as Jackson writes the record: every member, `null` included, `default` and the two role flags under
/// their wire names.
#[derive(Debug, Serialize, PartialEq, Eq)]
struct SettingView {
    key: &'static str,
    /// `setting.type().name().toLowerCase(Locale.ROOT)`.
    #[serde(rename = "type")]
    setting_type: String,
    /// The section's label, not its constant.
    section: &'static str,
    label: &'static str,
    help: &'static str,
    default: &'static str,
    value: Option<String>,
    configured: bool,
    governor_only: bool,
    administrator_only: bool,
}

impl SettingView {
    fn of(entry: Entry) -> SettingView {
        let setting = entry.setting;
        SettingView {
            key: setting.key(),
            setting_type: setting.setting_type().name().to_lowercase(),
            section: setting.section().label(),
            label: setting.label(),
            help: setting.help(),
            default: setting.default_value(),
            value: entry.value,
            configured: entry.configured,
            governor_only: entry.governor_only,
            administrator_only: entry.administrator_only,
        }
    }
}

#[derive(Debug, Serialize)]
struct Catalog {
    settings: Vec<SettingView>,
}

#[derive(Debug, Serialize)]
struct Updated {
    updated: usize,
}

/// `@RequestBody Map<String, String>`, as Jackson reads it into the `LinkedHashMap` Spring hands the controller.
///
/// - **In the order sent**, which is the audit entry's; a key sent twice keeps its first place and its last value, as
///   `LinkedHashMap.put` does.
/// - A string is itself; `null` is `None`, saved as empty; `true`, `false` and a number are read as their text —
///   **the text sent**, `1.50` and `1e3` as written, which is what Jackson's parser hands `StringDeserializer` and
///   what `serde_json`'s `f64` would not give back.
/// - An object or an array as a value, or a body that is not an object (`null` included, which leaves a required body
///   missing), is the unreadable body Spring refuses before the controller runs.
#[derive(Debug, Default, PartialEq, Eq)]
struct SettingsBody(Vec<(String, Option<String>)>);

impl<'de> Deserialize<'de> for SettingsBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<SettingsBody, D::Error> {
        struct Pairs;

        impl<'de> Visitor<'de> for Pairs {
            type Value = SettingsBody;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object of settings")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<SettingsBody, A::Error> {
                let mut pairs: Vec<(String, Option<String>)> = Vec::new();
                while let Some((key, raw)) = map.next_entry::<String, Box<RawValue>>()? {
                    let value = scalar_text(raw.get()).map_err(serde::de::Error::custom)?;
                    match pairs.iter_mut().find(|(seen, _)| *seen == key) {
                        Some(pair) => pair.1 = value,
                        None => pairs.push((key, value)),
                    }
                }
                Ok(SettingsBody(pairs))
            }
        }

        deserializer.deserialize_map(Pairs)
    }
}

/// One value as `StringDeserializer` reads it: a scalar's text, `null` as absent, a container refused.
fn scalar_text(raw: &str) -> Result<Option<String>, &'static str> {
    match raw.as_bytes().first() {
        Some(b'"') => serde_json::from_str::<String>(raw).map(Some).map_err(|_| "not a string"),
        Some(b'n') => Ok(None),
        Some(b'{' | b'[') | None => Err("a container is not a setting's value"),
        // `true`, `false` and a number: the token's own text.
        Some(_) => Ok(Some(raw.to_owned())),
    }
}

/// The caller as the service asks it: the account's name and its role's two properties. `principal.user()` is the
/// account behind a session or a key; nothing else reaches these routes.
fn caller_of(caller: &Caller) -> Option<crate::settings::Caller> {
    caller.0.account.as_ref().map(|account| crate::settings::Caller {
        username: account.username.clone(),
        administrative: account.role.is_some_and(|role| role.is_administrative()),
        governs_platform: account.role.is_some_and(|role| role.governs_platform()),
    })
}

/// `RequestActors.of(principal, request)`.
fn actor(caller: &Caller, address: &ClientAddress, headers: &HeaderMap) -> RequestActor {
    RequestActor {
        username: caller.0.actor(),
        ip_address: Some(address.0.clone()),
        user_agent: headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_owned),
    }
}

/// `ApiExceptionHandler` on what the save throws. **A service's `AccessDeniedException` is the chain's 403**, audited
/// `Access denied: <reason>` — answered here, it would leave no entry and shift the hash chain.
fn refuse(method: &str, error: AdministrationError) -> Response {
    match error {
        AdministrationError::InvalidInput(message) => bad_request(message),
        AdministrationError::AccessDenied(reason) => vectispire_cp_http::chain::denied(reason),
        refused @ AdministrationError::IntegrationDisabled { integration, .. } => {
            Problem::handler(StatusCode::CONFLICT, refused.to_string())
                .caused_by(vectispire_domain::integrations::DISABLED_CAUSE)
                .with("integration", integration.key())
                .into_response()
        }
        // `UnsafeUrlException`: the AI destination the save would produce, refused by the outbound guard.
        AdministrationError::UnsafeUrl(message) => {
            Problem::handler(StatusCode::UNPROCESSABLE_ENTITY, message).code("unsafe-url").into_response()
        }
        failure @ (AdministrationError::Settings(_)
        | AdministrationError::Storage(_)
        | AdministrationError::Collaborator(_)) => unexpected(method, SETTINGS, &failure),
    }
}

pub(super) fn routes(service: Arc<SettingsAdministration>, entries: &mut Vec<RouteEntry>) {
    // The catalog is any account's — the screen needs the labels and the types; the values are the service's to
    // withhold.
    let listing = service.clone();
    entries.push(Route::get(SETTINGS).requires(Access::Account).names_no_target().handler(move |caller: Caller| {
        let service = listing.clone();
        async move {
            match service.catalog(caller_of(&caller).as_ref()).await {
                Ok(all) => ok(&Catalog { settings: all.into_iter().map(SettingView::of).collect() }),
                Err(failure) => refuse("GET", failure),
            }
        }
    }));

    entries.push(Route::put(SETTINGS).requires(Access::SecurityLead).names_no_target().handler(
        move |caller: Caller, address: ClientAddress, headers: HeaderMap, JsonBody(body): JsonBody<SettingsBody>| {
            let service = service.clone();
            async move {
                let writer = caller_of(&caller);
                match service.update(&body.0, writer.as_ref(), &actor(&caller, &address, &headers)).await {
                    Ok(applied) => ok(&Updated { updated: applied.count }),
                    Err(refused) => refuse("PUT", refused),
                }
            }
        },
    ));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use vectispire_domain::integrations::Integration;

    fn read(body: &str) -> Result<Vec<(String, Option<String>)>, String> {
        serde_json::from_str::<SettingsBody>(body).map(|read| read.0).map_err(|failure| failure.to_string())
    }

    fn pair(key: &str, value: Option<&str>) -> (String, Option<String>) {
        (key.to_owned(), value.map(str::to_owned))
    }

    #[test]
    fn the_body_is_read_in_its_order_a_repeated_key_keeping_its_first_place_and_its_last_value() {
        assert_eq!(
            read(r#"{"b":"1","a":"2","b":"3"}"#).unwrap(),
            vec![pair("b", Some("3")), pair("a", Some("2"))],
            "LinkedHashMap.put"
        );
        assert_eq!(read("{}").unwrap(), Vec::new());
    }

    #[test]
    fn a_scalar_is_read_as_its_text_and_null_as_nothing() {
        assert_eq!(
            read(r#"{"a":null,"b":true,"c":false,"d":7,"e":1.50,"f":-1e3,"g":"xé\"y"}"#).unwrap(),
            vec![
                pair("a", None),
                pair("b", Some("true")),
                pair("c", Some("false")),
                pair("d", Some("7")),
                pair("e", Some("1.50")),
                pair("f", Some("-1e3")),
                pair("g", Some("x\u{e9}\"y")),
            ]
        );
    }

    #[test]
    fn a_container_or_a_body_that_is_not_an_object_is_unreadable() {
        assert!(read(r#"{"a":{}}"#).is_err());
        assert!(read(r#"{"a":["x"]}"#).is_err());
        assert!(read("null").is_err());
        assert!(read(r#"["a"]"#).is_err());
        assert!(read(r#""a""#).is_err());
    }

    #[test]
    fn the_caller_is_its_account_s_name_and_its_role_s_two_properties() {
        use vectispire_cp_http::principal::{Account, Principal, Role};
        let of = |role: Option<Role>| {
            caller_of(&Caller(Principal::session(Account {
                username: "someone".to_owned(),
                role,
                must_change_password: false,
            })))
            .map(|caller| (caller.username, caller.administrative, caller.governs_platform))
        };
        assert_eq!(of(Some(Role::Superuser)), Some(("someone".to_owned(), true, true)));
        assert_eq!(of(Some(Role::Admin)), Some(("someone".to_owned(), true, false)));
        assert_eq!(of(Some(Role::Ciso)), Some(("someone".to_owned(), false, false)));
        assert_eq!(of(None), Some(("someone".to_owned(), false, false)), "an unreadable role is no role");
        assert_eq!(caller_of(&Caller(Principal::scim())), None, "no account, no user");
    }

    #[test]
    fn a_refusal_is_answered_in_java_s_statuses() {
        let status = |error| refuse("PUT", error).status();
        assert_eq!(status(AdministrationError::InvalidInput("no".into())), StatusCode::BAD_REQUEST);
        assert_eq!(status(AdministrationError::AccessDenied("no".into())), StatusCode::FORBIDDEN);
        assert_eq!(status(AdministrationError::UnsafeUrl("no".into())), StatusCode::UNPROCESSABLE_ENTITY);
        let jira = Integration::by_key("tracker.jira").unwrap();
        assert_eq!(
            status(AdministrationError::IntegrationDisabled { integration: jira, lead: "" }),
            StatusCode::CONFLICT
        );
        assert_eq!(status(AdministrationError::Collaborator("x".into())), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(status(AdministrationError::Storage("x".into())), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn an_access_denial_is_left_to_the_chain_to_audit() {
        let response = refuse("PUT", AdministrationError::AccessDenied("the reason".into()));
        assert!(response.extensions().get::<vectispire_cp_http::chain::Denied>().is_some());
    }

    #[test]
    fn the_view_writes_jackson_s_names_in_the_record_s_order() {
        let setting = vectispire_cp_settings::Setting::SlaLowDays;
        let view = SettingView::of(Entry {
            setting,
            value: None,
            configured: false,
            governor_only: false,
            administrator_only: true,
        });
        let written = vectispire_domain::wire::to_wire_string(&view);
        let keys: Vec<String> = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&written)
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            keys,
            [
                "key",
                "type",
                "section",
                "label",
                "help",
                "default",
                "value",
                "configured",
                "governor_only",
                "administrator_only"
            ]
        );
        assert!(written.contains(r#""type":"integer""#) && written.contains(r#""value":null"#));
    }
}
