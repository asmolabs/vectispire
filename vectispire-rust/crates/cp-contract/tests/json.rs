//! The ordered JSON reader and the comparison: what a `serde_json::Value` comparison forgets.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use vectispire_cp_contract::{Compare, DifferenceKind, Json, MAX_DEPTH, Numbers, compare};

fn parse(text: &str) -> Json {
    Json::parse(text).unwrap()
}

fn differences(expected: &str, actual: &str, how: Compare) -> Vec<(String, DifferenceKind)> {
    compare(&parse(expected), &parse(actual), how)
        .into_iter()
        .map(|difference| (difference.pointer, difference.kind))
        .collect()
}

#[test]
fn a_document_keeps_its_key_order_and_the_spelling_of_its_numbers() {
    let json = parse(r#"{"b":1,"a":1.0,"c":[1e0,-0,0.10]}"#);
    assert_eq!(json.to_text(), r#"{"b":1,"a":1.0,"c":[1e0,-0,0.10]}"#);
}

#[test]
fn identical_documents_have_no_difference() {
    let text = r#"{"id":7,"tags":["a","b"],"owner":null,"ok":true}"#;
    assert!(differences(text, text, Compare::default()).is_empty());
}

#[test]
fn the_same_keys_in_another_order_are_a_difference_unless_the_order_is_not_pinned() {
    let found = differences(r#"{"a":1,"b":2}"#, r#"{"b":2,"a":1}"#, Compare::default());
    assert_eq!(
        found,
        vec![(
            String::new(),
            DifferenceKind::KeyOrder { expected: vec!["a".into(), "b".into()], actual: vec!["b".into(), "a".into()] }
        )]
    );
    let relaxed = Compare { key_order: false, ..Compare::default() };
    assert!(differences(r#"{"a":1,"b":2}"#, r#"{"b":2,"a":1}"#, relaxed).is_empty());
}

#[test]
fn one_and_one_point_zero_are_two_answers_unless_numbers_are_compared_by_value() {
    let found = differences(r#"{"n":1}"#, r#"{"n":1.0}"#, Compare::default());
    assert_eq!(found, vec![("/n".to_owned(), DifferenceKind::Value { expected: "1".into(), actual: "1.0".into() })]);
    let by_value = Compare { numbers: Numbers::Value, ..Compare::default() };
    assert!(differences(r#"{"n":1}"#, r#"{"n":1.0}"#, by_value).is_empty());
}

#[test]
fn a_missing_and_an_extra_key_are_named_by_pointer() {
    let found = differences(r#"{"a":{"b":1}}"#, r#"{"a":{"c":1}}"#, Compare::default());
    assert_eq!(found, vec![("/a/b".to_owned(), DifferenceKind::Missing), ("/a/c".to_owned(), DifferenceKind::Extra)]);
}

#[test]
fn a_key_with_a_slash_is_escaped_in_the_pointer() {
    let found = differences(r#"{"a/b":1}"#, r#"{"a/b":2}"#, Compare::default());
    assert_eq!(found[0].0, "/a~1b");
}

#[test]
fn arrays_differ_by_length_and_by_element() {
    let found = differences(r#"[1,2,3]"#, r#"[1,9]"#, Compare::default());
    assert_eq!(
        found,
        vec![
            (String::new(), DifferenceKind::Length { expected: 3, actual: 2 }),
            ("/1".to_owned(), DifferenceKind::Value { expected: "2".into(), actual: "9".into() })
        ]
    );
}

#[test]
fn another_kind_of_value_is_a_type_difference_and_null_is_not_absence() {
    let found = differences(r#"{"a":null}"#, r#"{"a":0}"#, Compare::default());
    assert_eq!(found, vec![("/a".to_owned(), DifferenceKind::Type { expected: "null", actual: "number" })]);
}

#[test]
fn a_duplicated_key_is_two_entries_and_the_last_one_wins_in_a_comparison() {
    let json = parse(r#"{"a":1,"a":2}"#);
    assert_eq!(json.as_object().unwrap().len(), 2);
    assert_eq!(json.get("a"), Some(&Json::Num("2".into())));
    assert!(differences(r#"{"a":1,"a":2}"#, r#"{"a":2}"#, Compare::default()).is_empty());
}

#[test]
fn strings_read_escapes_and_surrogate_pairs() {
    assert_eq!(parse(r#""a\n\u00e9\ud83d\ude00\/""#), Json::Str("a\né😀/".into()));
}

#[test]
fn writing_a_string_escapes_control_characters_in_upper_case_hex_as_jackson_does() {
    assert_eq!(Json::Str("\u{1f}".into()).to_text(), "\"\\u001F\"");
}

#[test]
fn what_json_does_not_allow_is_refused() {
    for bad in [
        "",
        "{",
        "[1,]",
        "{\"a\":1,}",
        "01",
        "1.",
        "1e",
        "-",
        "\"a\u{1}b\"",
        "\"\\x\"",
        "{\"a\" 1}",
        "{a:1}",
        "nul",
        "[1] 2",
        "\u{feff}{}",
        "'a'",
        "\"\\u12\"",
    ] {
        assert!(Json::parse(bad).is_err(), "{bad:?} should not parse");
    }
}

#[test]
fn nesting_past_the_limit_is_refused_and_at_the_limit_is_not() {
    let nested = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    assert!(Json::parse(&nested(MAX_DEPTH)).is_ok());
    assert!(Json::parse(&nested(MAX_DEPTH + 2)).is_err());
}

#[test]
fn a_parse_error_says_where() {
    let error = Json::parse("{\"a\": tru}").unwrap_err();
    assert_eq!(error.offset, 6);
}
