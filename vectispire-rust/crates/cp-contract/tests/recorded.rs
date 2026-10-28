//! The recorder's format read back (`recorded`), without a database: the placeholders' grammar, what a template
//! admits and refuses, the rows' comparison, and `golden/deferred.txt`. The comparison is the oracle of the port —
//! each test below is a way it could be made lenient, refused.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use vectispire_cp_contract::Document;
use vectispire_cp_contract::Json;
use vectispire_cp_contract::recorded::deferred::{Deferred, Listed, check_list, coverage};
use vectispire_cp_contract::recorded::format::Exchange;
use vectispire_cp_contract::recorded::placeholders::{
    Bindings, Context, Minting, NumberText, PasswordOf, Placeholder, SecretKind, Segment, in_window, renders_alike,
    secret_kinds, segments,
};
use vectispire_cp_contract::recorded::replay::{Outcome, Replayed, compare_headers, compare_rows};
use vectispire_cp_contract::recorded::rows::{Column, Kind, Schema, Table};
use vectispire_cp_db::Engine;

/// Credentials of the right shapes, deterministic: a hash is `$argon2id$fake$<the password>`.
struct Fake;

impl Minting for Fake {
    fn session_token(&self) -> String {
        format!("Tok3n{}", uuid_like())
    }
    fn api_key(&self) -> String {
        format!("zsk_{}", "Ab1".repeat(14) + "x")
    }
    fn sha256_hex(&self, text: &str) -> String {
        Sha256::digest(text.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
    }
    fn password_hash(&self, plain: &str) -> String {
        format!("$argon2id$fake${}", plain.replace(' ', "_"))
    }
    fn password_verifies(&self, plain: &str, hash: &str) -> bool {
        hash == self.password_hash(plain)
    }
}

fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    format!("{:038}", NEXT.fetch_add(1, Ordering::Relaxed))
}

const BASE: i64 = 709_000_000;

fn bindings() -> Bindings<'static> {
    let starts = BTreeMap::from([("t_repository".to_owned(), BASE + 1), ("t_user".to_owned(), 579_000_001)]);
    Bindings::new(starts, BTreeMap::new(), &Fake, OffsetDateTime::now_utc())
}

fn json(text: &str) -> Json {
    Json::parse(text).unwrap()
}

fn differences(bindings: &mut Bindings<'_>, expected: &str, actual: &str) -> Vec<String> {
    let mut out = Vec::new();
    bindings.match_json(&json(expected), &json(actual), "", NumberText::Exact, "", &mut out);
    out
}

#[test]
fn every_placeholder_of_the_recorder_is_read() {
    let read = |inner: &str| match segments(&format!("«{inner}»")).as_slice() {
        [Segment::Placeholder(found)] => Some(found.clone()),
        _ => None,
    };
    assert_eq!(read("t_repository#3"), Some(Placeholder::Id { table: "t_repository".into(), rank: Some(3) }));
    assert_eq!(read("t_repository#prior"), Some(Placeholder::Id { table: "t_repository".into(), rank: None }));
    assert_eq!(read("secret:2"), Some(Placeholder::Secret(2)));
    assert_eq!(read("secret:2:prefix"), Some(Placeholder::SecretPrefix(2)));
    assert_eq!(read("sha256(secret:4)"), Some(Placeholder::SecretHash(4)));
    assert_eq!(
        read("password-hash(correct horse battery staple)"),
        Some(Placeholder::PasswordHash(PasswordOf::Fixture))
    );
    assert_eq!(read("password-hash(secret:1)"), Some(Placeholder::PasswordHash(PasswordOf::Secret(1))));
    assert_eq!(read("password-hash(?)"), Some(Placeholder::PasswordHash(PasswordOf::Unknown)));
    assert_eq!(read("sha256:7"), Some(Placeholder::Digest(7)));
    assert_eq!(read("sha256-prefix:7"), Some(Placeholder::DigestPrefix(7)));
    assert_eq!(read("uuid:1"), Some(Placeholder::Uuid(1)));
    assert_eq!(read("n:5"), Some(Placeholder::Long(5)));
    assert_eq!(read("port:1"), Some(Placeholder::Port(1)));
    assert_eq!(read("pem:certificate:2"), Some(Placeholder::Pem { label: "certificate".into(), ordinal: 2 }));
    for fixed in
        ["sealed", "date", "datetime", "instant", "http-date", "stamp", "one-time-code", "window", "clock-step"]
    {
        assert!(read(fixed).is_some(), "{fixed}");
    }
    // A blob's digest is a row value of the recorder's, not a placeholder: compared as written.
    assert_eq!(segments("«bytes:12:0123456789abcdef»"), vec![Segment::Literal("«bytes:12:0123456789abcdef»".into())]);
    assert_eq!(
        segments("a «uuid:1» b «nothing» c"),
        vec![
            Segment::Literal("a ".into()),
            Segment::Placeholder(Placeholder::Uuid(1)),
            Segment::Literal(" b «nothing» c".into())
        ]
    );
}

#[test]
fn an_identity_is_the_number_its_rank_computes_and_nothing_else() {
    let mut b = bindings();
    assert!(differences(&mut b, r#"{"id":"«t_repository#2»"}"#, &format!(r#"{{"id":{}}}"#, BASE + 2)).is_empty());
    assert!(!differences(&mut b, r#"{"id":"«t_repository#2»"}"#, &format!(r#"{{"id":{}}}"#, BASE + 3)).is_empty());
    // In a sentence, too.
    assert!(
        b.match_text("Repository «t_repository#1» deleted", &format!("Repository {} deleted", BASE + 1), "").is_ok()
    );
    assert!(
        b.match_text("Repository «t_repository#1» deleted", &format!("Repository {} deleted", BASE + 2), "").is_err()
    );
    // Another table's number is not this table's.
    assert!(b.match_text("«t_user#1»", &(BASE + 1).to_string(), "").is_err());
    // A number the recorder did not write as a placeholder is compared as written.
    assert!(!differences(&mut b, r#"{"count":2}"#, r#"{"count":"2"}"#).is_empty());
}

#[test]
fn an_ordinal_names_one_value_and_a_value_one_ordinal() {
    let mut b = bindings();
    let first = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
    let second = "6fa459ea-ee8a-3ca4-894e-db77e160355e";
    assert!(b.match_text("«uuid:1»", first, "id").is_ok());
    assert!(b.match_text("«uuid:1»", first, "id").is_ok());
    assert!(b.match_text("«uuid:1»", second, "id").is_err(), "the same ordinal, another value");
    assert!(b.match_text("«uuid:2»", first, "id").is_err(), "another ordinal, the same value");
    assert!(b.match_text("«uuid:2»", second, "id").is_ok());
    assert!(b.match_text("«uuid:3»", "not-a-uuid", "id").is_err(), "a value of another shape");
    // Within one text too, before anything is bound.
    let mut b = bindings();
    assert!(b.match_text("«uuid:1»/«uuid:1»", &format!("{first}/{second}"), "").is_err());
    assert!(b.match_text("«uuid:1»/«uuid:2»", &format!("{first}/{first}"), "").is_err());
    // A refused text binds nothing.
    assert!(b.match_text("«uuid:1» x", &format!("{second} y"), "").is_err());
    assert!(b.match_text("«uuid:1»", first, "").is_ok());
    let mut b = bindings();
    assert!(b.match_text("«n:1»", "1760000000000", "").is_ok());
    assert!(b.match_text("«n:1»", "1760000000001", "").is_err());
    assert!(b.match_text("«n:2»", "17600", "").is_err(), "a long number has twelve digits or more");
}

#[test]
fn a_secret_hash_and_a_prefix_are_the_secrets() {
    let mut b = bindings();
    let token = b.concrete("«secret:1»", "authorization", Context::Wire).unwrap();
    assert_eq!(b.concrete("«secret:1»", "x", Context::Wire).unwrap(), token, "minted once");
    let hash = Fake.sha256_hex(&token);
    assert!(b.match_text("«sha256(secret:1)»", &hash, "token_hash").is_ok());
    assert!(b.match_text("«sha256(secret:1)»", &Fake.sha256_hex("other"), "token_hash").is_err());
    assert!(b.match_text("«secret:1»", "SomethingElse1", "token").is_err());
    // Seen in an answer before the replay knew it: bound there, and its hash seen earlier checked then.
    let mut b = bindings();
    assert!(b.match_text("«sha256(secret:2)»", &Fake.sha256_hex("wrong"), "token_hash").is_ok());
    assert!(b.match_text("«secret:2»", "ServerMinted1", "token").is_ok());
    assert_eq!(b.take_violations().len(), 1, "the owed check failed once the secret was known");
    let mut b = bindings();
    assert!(b.match_text("«sha256(secret:2)»", &Fake.sha256_hex("ServerMinted1"), "token_hash").is_ok());
    assert!(b.match_text("«secret:2»", "ServerMinted1", "token").is_ok());
    assert!(b.take_violations().is_empty());
    // Two secrets are two values.
    let mut b = bindings();
    assert!(b.match_text("«secret:1»", "ServerMinted1", "token").is_ok());
    assert!(b.match_text("«secret:2»", "ServerMinted1", "token").is_err());
    // An API key, minted as one when the test ever shows its prefix.
    let kinds = secret_kinds(["«secret:3:prefix»", "«secret:3»", "«secret:4»"]);
    assert_eq!(kinds.get(&3), Some(&SecretKind::ApiKey));
    assert_eq!(kinds.get(&4), Some(&SecretKind::Token));
    let mut b = Bindings::new(BTreeMap::new(), kinds, &Fake, OffsetDateTime::now_utc());
    let key = b.concrete("«secret:3»", "", Context::Wire).unwrap();
    assert!(key.starts_with("zsk_"));
    assert_eq!(b.concrete("«secret:3:prefix»", "", Context::Row).unwrap(), key.chars().take(12).collect::<String>());
    assert!(b.match_text("«secret:3:prefix»", "zsk_AAAAAAAA", "key_prefix").is_err());
}

#[test]
fn a_password_hash_holds_the_password_it_names() {
    let mut b = bindings();
    let fixture = b.concrete("«password-hash(correct horse battery staple)»", "password", Context::Row).unwrap();
    assert!(Fake.password_verifies("correct horse battery staple", &fixture));
    assert!(b.match_text("«password-hash(correct horse battery staple)»", &fixture, "password").is_ok());
    let other = Fake.password_hash("something else");
    assert!(b.match_text("«password-hash(correct horse battery staple)»", &other, "password").is_err());
    assert!(b.match_text("«password-hash(?)»", &other, "password").is_ok());
    assert!(b.match_text("«password-hash(?)»", &fixture, "password").is_err());
    assert!(b.match_text("«password-hash(?)»", "plain text", "password").is_err());
    let secret = b.concrete("«secret:1»", "", Context::Wire).unwrap();
    assert!(b.match_text("«password-hash(secret:1)»", &Fake.password_hash(&secret), "key_hash").is_ok());
    assert!(b.match_text("«password-hash(secret:1)»", &other, "key_hash").is_err());
    // A hash seen before its secret: checked when the secret is.
    let mut b = bindings();
    assert!(b.match_text("«password-hash(secret:5)»", &Fake.password_hash("Right0ne"), "key_hash").is_ok());
    assert!(b.match_text("«secret:5»", "Wrong0ne", "fullKey").is_ok());
    assert_eq!(b.take_violations().len(), 1);
    let mut b = bindings();
    assert!(b.match_text("«password-hash(secret:5)»", &Fake.password_hash("Right0ne"), "key_hash").is_ok());
    assert!(b.match_text("«secret:5»", "Right0ne", "fullKey").is_ok());
    assert!(b.take_violations().is_empty());
}

#[test]
fn a_clock_value_must_be_in_the_recorders_window() {
    let today = OffsetDateTime::now_utc().date();
    let year = today.year();
    assert!(in_window(today, year, 1, 1));
    assert!(in_window(today, year + 11, 1, 1));
    assert!(!in_window(today, year + 12, 1, 1));
    assert!(!in_window(today, year - 4, 1, 1));
    assert!(!in_window(today, year, 13, 1));
    assert!(!in_window(today, year, 1, 0));
    assert!(!in_window(today, year, 1, 32));
    assert!(in_window(today, year, 2, 31), "the day is clamped to the month, as LocalDate.of(…, min(day, length))");
    let mut b = bindings();
    let now = format!("{year}-03-04T05:06:07.123");
    assert!(b.match_text("«datetime»", &now, "created_at").is_ok());
    assert!(b.match_text("«datetime»", "2001-03-04T05:06:07", "created_at").is_err());
    assert!(b.match_text("«datetime»", "yesterday", "created_at").is_err());
    assert!(b.match_text("«instant»", &format!("{now}Z"), "at").is_ok());
    assert!(b.match_text("«instant»", &now, "at").is_err(), "an instant carries its zone");
    assert!(b.match_text("«date»", &format!("{year}-03-04"), "day").is_ok());
    assert!(b.match_text("«date»", &format!("{year}-03-04T00:00"), "day").is_err());
    assert!(b.match_text("«http-date»", &format!("Mon, 04 Mar {year} 05:06:07 GMT"), "expires").is_ok());
    assert!(b.match_text("«http-date»", "Mon, 04 Mar 1999 05:06:07 GMT", "expires").is_err());
    assert!(b.match_text("«stamp»", &format!("{year}0304T050607Z"), "").is_ok());
    assert!(b.match_text("«stamp»", "19990304T050607Z", "").is_err());
    // A seed's expiry is put ahead of now: a session seeded as expiring now would refuse its own request.
    let seeded = b.concrete("«datetime»", "expires_at", Context::Row).unwrap();
    let created = b.concrete("«datetime»", "created_at", Context::Row).unwrap();
    assert!(seeded > created, "{seeded} after {created}");
    assert!(seeded.contains(' ') && !seeded.contains('T'), "a row's datetime: {seeded}");
}

#[test]
fn the_rules_that_number_nothing_cover_only_their_shape() {
    let mut b = bindings();
    assert!(b.match_text("«sealed»", "v2:AAAAbbbb==", "git_token").is_ok());
    assert!(b.match_text("«sealed»", "ghp_plaintext", "git_token").is_err(), "a credential in the clear is not sealed");
    assert!(b.match_text("«one-time-code»", "123456", "code").is_ok());
    assert!(b.match_text("«one-time-code»", "123456", "description").is_err());
    assert!(b.match_text("«one-time-code»", "12345", "code").is_err());
    assert!(b.match_text("«sha256:1»", &"a".repeat(64), "digest").is_ok());
    assert!(b.match_text("«sha256:2»", &"b".repeat(40), "digest").is_err(), "64 hex digits outside a hash field");
    assert!(b.match_text("«sha256:2»", &"b".repeat(40), "entry_hash").is_ok());
    assert!(b.match_text("«sha256:3»", &"A".repeat(64), "digest").is_err(), "the digest of ordinal 1, in upper case");
    assert!(b.match_text("«port:1»", "54321", "").is_ok());
    assert!(b.match_text("«clock-step»", "-12", "totp_last_step").is_ok());
    assert!(b.match_text("literal", "literal", "").is_ok());
    assert!(b.match_text("literal", "Literal", "").is_err());
    assert!(b.match_text("«t_repository#prior»", &BASE.to_string(), "").is_ok());
    assert!(b.match_text("«t_repository#prior»", &(BASE + 1).to_string(), "").is_err());
}

#[test]
fn an_answer_is_compared_member_by_member() {
    let mut b = bindings();
    assert!(differences(&mut b, r#"{"a":1,"b":[true,null]}"#, r#"{"b":[true,null],"a":1}"#).is_empty(), "unordered");
    assert_eq!(differences(&mut b, r#"{"a":1}"#, r#"{"a":1,"b":2}"#).len(), 1, "an extra member");
    assert_eq!(differences(&mut b, r#"{"a":1,"b":2}"#, r#"{"a":1}"#).len(), 1, "a missing member");
    assert_eq!(differences(&mut b, r#"[1,2]"#, r#"[2,1]"#).len(), 2, "arrays in order");
    assert_eq!(differences(&mut b, r#"[1,2]"#, r#"[1,2,3]"#).len(), 1);
    assert_eq!(differences(&mut b, r#"{"a":1.0}"#, r#"{"a":1}"#).len(), 1, "an answer's numbers as Jackson wrote them");
    assert_eq!(differences(&mut b, r#"{"a":true}"#, r#"{"a":false}"#).len(), 1);
    assert_eq!(differences(&mut b, r#"{"a":null}"#, r#"{"a":"x"}"#).len(), 1);
    assert_eq!(differences(&mut b, r#"{"a":"x"}"#, r#"{"a":null}"#).len(), 1);
    assert_eq!(
        differences(&mut b, r#"{"a":"«uuid:9»"}"#, r#"{"a":7}"#).len(),
        1,
        "only an id or a long may be a number"
    );
    let mut rows = Vec::new();
    b.match_json(&json(r#"{"a":10.50}"#), &json(r#"{"a":10.5}"#), "", NumberText::Value, "", &mut rows);
    assert!(rows.is_empty(), "a row's numbers by value");
    b.match_json(&json(r#"{"a":10.50}"#), &json(r#"{"a":10.51}"#), "", NumberText::Value, "", &mut rows);
    b.match_json(&json(r#"{"a":-1}"#), &json(r#"{"a":1}"#), "", NumberText::Value, "", &mut rows);
    assert_eq!(rows.len(), 2);
}

#[test]
fn a_change_the_recorder_would_not_keep_is_not_one() {
    let today = OffsetDateTime::now_utc().date();
    let year = today.year();
    assert!(renders_alike(today, "last_seen_at", &format!("{year}-01-01T10:00"), &format!("{year}-01-01T10:01")));
    assert!(!renders_alike(today, "last_seen_at", "2001-01-01T10:00", "2001-01-01T10:01"), "outside the window");
    assert!(!renders_alike(today, "seen", &format!("{year}-01-01"), &format!("{year}-01-01T10:01")), "two kinds");
    assert!(renders_alike(today, "git_token", "v2:AAAA", "v2:BBBB"));
    assert!(!renders_alike(today, "git_token", "v2:AAAA", "plain"));
    assert!(!renders_alike(today, "id", "1", "2"));
    assert!(renders_alike(today, "totp_last_step", "1", "2"));
    assert!(!renders_alike(today, "other_step", "1", "2"));
}

fn schema() -> Schema {
    let column = |name: &str, kind| Column { name: name.into(), kind, cast: "text".into(), zoned: false };
    Schema {
        engine: Engine::MySql,
        tables: vec![
            Table {
                name: "t_repository".into(),
                columns: vec![column("id", Kind::Integer), column("url", Kind::Text)],
                key: vec![0],
                identity: Some(("id".into(), None)),
                always: false,
                base: Some(BASE),
            },
            Table {
                name: "t_audit_log".into(),
                columns: vec![column("id", Kind::Text), column("description", Kind::Text)],
                key: vec![0],
                identity: None,
                always: false,
                base: None,
            },
        ],
    }
}

fn rows(recorded: &str, actual: &str) -> Vec<String> {
    let mut b = bindings();
    let mut out = Vec::new();
    compare_rows(&schema(), &json(recorded), &json(actual), &mut b, &mut out);
    out
}

#[test]
fn rows_are_held_to_the_recorded_effect() {
    let id = |rank: i64| BASE + rank;
    let made =
        format!(r#"{{"t_repository":{{"inserted":[{{"id":{},"url":"a"}},{{"id":{},"url":"b"}}]}}}}"#, id(1), id(2));
    let recorded =
        r#"{"t_repository":{"inserted":[{"id":"«t_repository#1»","url":"a"},{"id":"«t_repository#2»","url":"b"}]}}"#;
    assert!(rows(recorded, &made).is_empty());
    // In id order: the same rows the other way round are not the same creations.
    let swapped =
        r#"{"t_repository":{"inserted":[{"id":"«t_repository#1»","url":"b"},{"id":"«t_repository#2»","url":"a"}]}}"#;
    assert!(!rows(swapped, &made).is_empty());
    assert!(!rows(r#"{}"#, &made).is_empty(), "a table changed that the recording did not change");
    assert!(!rows(recorded, "{}").is_empty(), "a recorded change not made");
    let one = r#"{"t_repository":{"inserted":[{"id":"«t_repository#1»","url":"a"}]}}"#;
    assert!(!rows(one, &made).is_empty(), "one row more");
    let deleted = format!(r#"{{"t_repository":{{"deleted":[{{"id":{},"url":"a"}}]}}}}"#, id(1));
    assert!(!rows(one, &deleted).is_empty(), "deleted is not inserted");
    // Keyed by a UUID: matched as a set, each recorded row to one row made.
    let audit =
        r#"{"t_audit_log":{"inserted":[{"id":"«uuid:1»","description":"one"},{"id":"«uuid:2»","description":"two"}]}}"#;
    let made_audit = r#"{"t_audit_log":{"inserted":[{"id":"6fa459ea-ee8a-3ca4-894e-db77e160355e","description":"two"},{"id":"1b4e28ba-2fa1-11d2-883f-0016d3cca427","description":"one"}]}}"#;
    assert!(rows(audit, made_audit).is_empty());
    let twice = r#"{"t_audit_log":{"inserted":[{"id":"6fa459ea-ee8a-3ca4-894e-db77e160355e","description":"two"},{"id":"1b4e28ba-2fa1-11d2-883f-0016d3cca427","description":"two"}]}}"#;
    assert!(!rows(audit, twice).is_empty(), "one made row cannot answer two recorded ones");
    // A table over the recorder's ceiling says nothing comparable.
    assert!(rows(r#"{"t_repository":{"overCeiling":true}}"#, &made).is_empty());
}

#[test]
fn headers_are_the_recorded_ones() {
    let pairs = |list: &[(&str, &str)]| {
        list.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect::<Vec<_>>()
    };
    let check = |recorded: &[(&str, &str)], actual: &[(&str, &str)]| {
        let mut out = Vec::new();
        compare_headers(&pairs(recorded), &pairs(actual), &mut bindings(), &mut out);
        out
    };
    let recorded = [("Content-Type", "application/json"), ("X-Frame-Options", "DENY")];
    assert!(
        check(&recorded, &[("content-type", "application/json"), ("x-frame-options", "DENY"), ("content-length", "2")])
            .is_empty()
    );
    assert_eq!(check(&recorded, &[("content-type", "application/json")]).len(), 1, "a missing header");
    assert_eq!(check(&recorded, &[("content-type", "text/plain"), ("x-frame-options", "DENY")]).len(), 1);
    assert_eq!(
        check(&recorded, &[("content-type", "application/json"), ("x-frame-options", "DENY"), ("x-extra", "1")]).len(),
        1,
        "a header Java did not send"
    );
    // Java's length counts the values the recorder hid, which the replay chooses: it is not held to it.
    let csv = [("Content-Type", "text/csv"), ("Content-Length", "770")];
    assert!(check(&csv, &[("content-type", "text/csv"), ("content-length", "791")]).is_empty());
}

#[test]
fn an_exchange_is_read_as_the_recorder_writes_it() {
    let text = r#"{"format":1,"test":{"class":"api.X","method":"m"},"sequence":2,
      "request":{"method":"POST","path":"/api/v1/repositories","query":"a=1","params":{"a":["1"]},
        "headers":["Content-Type: application/json","Authorization: Bearer «secret:1»"],
        "body":{"contentType":"application/json","json":{"url":"u"}}},
      "seed":{"t_repository":{"inserted":[{"id":"«t_repository#1»"}]}},
      "response":{"status":201,"headers":["Location: /x"],"body":{"contentType":"application/json","json":{}}},
      "effect":{}}"#;
    let exchange = Exchange::from_json(std::path::Path::new("x.json"), text).unwrap();
    assert_eq!((exchange.sequence, exchange.response.status), (2, 201));
    assert_eq!(exchange.request.headers[1], ("Authorization".to_owned(), "Bearer «secret:1»".to_owned()));
    assert_eq!(exchange.request.params, vec![("a".to_owned(), vec!["1".to_owned()])]);
    assert!(exchange.seed.is_some() && exchange.effect.is_some());
    let thrown =
        r#"{"format":1,"request":{"method":"GET","path":"/"},"response":{"thrown":"java.lang.IllegalStateException"}}"#;
    assert_eq!(Exchange::from_json(std::path::Path::new("x.json"), thrown).unwrap().response.status, 500);
    assert!(
        Exchange::from_json(std::path::Path::new("x.json"), &text.replace(r#""format":1"#, r#""format":2"#)).is_err()
    );
}

fn listed(name: &str, method: &str, path: &str, route: Option<(&str, &str)>, served: bool) -> Listed {
    Listed {
        name: name.into(),
        method: method.into(),
        path: path.into(),
        route: route.map(|(method, path)| (method.into(), path.into())),
        served,
    }
}

fn replayed(name: &str, outcome: Outcome) -> Replayed {
    Replayed { name: name.into(), route: None, served: true, outcome }
}

#[test]
fn every_recording_is_replayed_or_listed_and_no_line_is_stale() {
    let deferred = Deferred::parse(
        "# a comment\nroute GET /api/v1/teams | access — Phase 1, task 1.7\ngolden c/t--002 | a stand-in\noutside GET /nowhere | not an operation\n",
    )
    .unwrap();
    assert_eq!(deferred.len(), 3);
    let all = vec![
        listed("c/t--001", "GET", "/api/v1/teams", Some(("GET", "/api/v1/teams")), false),
        listed("c/t--002", "GET", "/api/v1/repositories", Some(("GET", "/api/v1/repositories")), true),
        listed("c/t--003", "GET", "/api/v1/repositories", Some(("GET", "/api/v1/repositories")), true),
        listed("c/t--004", "GET", "/nowhere", None, false),
    ];
    let ok = [replayed("c/t--002", Outcome::Differs(vec!["x".into()])), replayed("c/t--003", Outcome::Green)];
    assert_eq!(coverage(&deferred, &all, Some(&ok)), Vec::<String>::new());
    assert_eq!(coverage(&deferred, &all, None), Vec::<String>::new());
    // A served recording that differs and is not listed.
    let bad = [
        replayed("c/t--002", Outcome::Differs(vec!["x".into()])),
        replayed("c/t--003", Outcome::Unreplayable("y".into())),
    ];
    assert_eq!(coverage(&deferred, &all, Some(&bad)).len(), 1);
    // A listed recording that now replays green: its line is stale.
    let green = [replayed("c/t--002", Outcome::Green), replayed("c/t--003", Outcome::Green)];
    assert_eq!(coverage(&deferred, &all, Some(&green)).len(), 1);
    // A served recording the replay never ran.
    assert_eq!(coverage(&deferred, &all, Some(&ok[..1])).len(), 1);
    // A route not served and not listed; an unknown path not listed.
    let unlisted = Deferred::parse("golden c/t--002 | a stand-in\n").unwrap();
    assert_eq!(coverage(&unlisted, &all, Some(&ok)).len(), 2);
    // Lines no recording needs.
    let stale = Deferred::parse(
        "route GET /api/v1/teams | a\nroute GET /api/v1/users | b\ngolden c/t--002 | c\ngolden c/gone | d\noutside GET /nowhere | e\noutside GET /else | f\n",
    )
    .unwrap();
    assert_eq!(coverage(&stale, &all, Some(&ok)).len(), 3);
    // A served route listed whole, every recording of it now green: stale.
    let whole =
        Deferred::parse("route GET /api/v1/teams | a\nroute GET /api/v1/repositories | b\noutside GET /nowhere | e\n")
            .unwrap();
    assert!(coverage(&whole, &all, Some(&ok)).is_empty());
    assert_eq!(coverage(&whole, &all, Some(&green)).len(), 1);
}

#[test]
fn the_list_is_well_formed_and_held_to_its_ceiling() {
    assert!(Deferred::parse("route GET /x\n").is_err(), "no reason");
    assert!(Deferred::parse("route GET /x | \n").is_err(), "an empty reason");
    assert!(Deferred::parse("route GET | r\n").is_err());
    assert!(Deferred::parse("golden a | r\ngolden a | s\n").is_err(), "twice");
    let document = Document::embedded();
    let one = Deferred::parse("route GET /api/v1/teams | r\n").unwrap();
    assert!(check_list(&one, &document, "1").is_empty());
    assert_eq!(check_list(&one, &document, "0").len(), 1, "above the ceiling");
    assert_eq!(check_list(&one, &document, "2").len(), 1, "below it: lower it");
    let unknown = Deferred::parse("route GET /api/v1/nothing | r\n").unwrap();
    assert_eq!(check_list(&unknown, &document, "1").len(), 1);
    // The committed list.
    let committed = Deferred::embedded();
    assert_eq!(
        check_list(&committed, &document, vectispire_cp_contract::recorded::deferred::CEILING),
        Vec::<String>::new()
    );
}

#[test]
fn the_edges_of_each_rule_hold() {
    // An ordinal names the value whatever its case, as the recorder keyed UUIDs and digests in lower case.
    let mut b = bindings();
    assert!(b.match_text("«uuid:1»", "1b4e28ba-2fa1-11d2-883f-0016d3cca427", "").is_ok());
    assert!(b.match_text("«uuid:1»", "1B4E28BA-2FA1-11D2-883F-0016D3CCA427", "").is_ok());
    // Only an identity, a long number or a clock step may be a number where the recording has a string.
    assert_eq!(differences(&mut b, r#"{"p":"«port:1»"}"#, r#"{"p":8080}"#).len(), 1);
    // A prefix shown before its key: checked when the key is.
    let mut b = bindings();
    assert!(b.match_text("«secret:4:prefix»", "zsk_AAAAAAAA", "key_prefix").is_ok());
    assert!(b.match_text("«secret:4»", "zsk_BBBBBBBBccccdddd1", "fullKey").is_ok());
    assert_eq!(b.take_violations().len(), 1);
    // A date where a date-time was recorded.
    let year = OffsetDateTime::now_utc().year();
    assert!(b.match_text("«datetime»", &format!("{year}-03-04"), "at").is_err());
    // The template holds the whole text, not its end.
    assert!(b.match_text("«uuid:9»", "junk-6fa459ea-ee8a-3ca4-894e-db77e160355e", "").is_err());
    assert!(b.match_text("x «uuid:9»", "x 6fa459ea-ee8a-3ca4-894e-db77e160355e trailing", "").is_err());
}

#[test]
fn the_window_ends_where_the_recorder_s_does() {
    let today = OffsetDateTime::now_utc().date();
    let shift = |years: i32, days: i64| {
        let year = today.year() + years;
        let day = today.day().min(today.month().length(year));
        let date = time::Date::from_calendar_date(year, today.month(), day).unwrap() + time::Duration::days(days);
        (date.year(), u8::from(date.month()), date.day())
    };
    for (years, days, inside) in [(-3, 0, true), (-3, -1, false), (11, 0, true), (11, 1, false)] {
        let (year, month, day) = shift(years, days);
        assert_eq!(in_window(today, year, month, day), inside, "{years} years and {days} days");
    }
}

#[test]
fn rows_are_matched_one_to_one_and_in_every_kind() {
    let recorded = r#"{"t_audit_log":{"inserted":[{"id":"x","description":"same"},{"id":"x","description":"same"}]}}"#;
    let made = r#"{"t_audit_log":{"inserted":[{"id":"x","description":"same"},{"id":"x","description":"other"}]}}"#;
    assert!(!rows(recorded, made).is_empty(), "one made row cannot answer two recorded ones");
    let id = |rank: i64| BASE + rank;
    let recorded = r#"{"t_repository":{"deleted":[{"id":"«t_repository#1»","url":"a"}]}}"#;
    let made = format!(r#"{{"t_repository":{{"deleted":[{{"id":{},"url":"a"}}]}}}}"#, id(2));
    assert!(!rows(recorded, &made).is_empty(), "a deletion of another row");
    let recorded =
        r#"{"t_repository":{"updated":[{"key":{"id":"«t_repository#1»"},"changed":{"url":{"from":"a","to":"b"}}}]}}"#;
    let made = format!(
        r#"{{"t_repository":{{"updated":[{{"key":{{"id":{}}},"changed":{{"url":{{"from":"a","to":"c"}}}}}}]}}}}"#,
        id(1)
    );
    assert!(!rows(recorded, &made).is_empty(), "an update to another value");
}
