//! The collector the layer, SQL and `unsafe` rules stand on: what it reads out of a file, and what it skips.

#![allow(clippy::unwrap_used)]

use vectispire_cp_arch_tests::facts::{Facts, read};

fn paths(facts: &Facts) -> Vec<String> {
    facts.paths.iter().map(|used| used.segments.join("::")).collect()
}

#[test]
fn a_use_tree_is_flattened_to_every_leaf() {
    let facts = read("use a::b::{c, d::e as f, g::*, self};\nuse ::h::i;\n").unwrap();
    assert_eq!(paths(&facts), ["a::b::c", "a::b::d::e", "a::b::g::*", "a::b::self", "h::i"]);
}

#[test]
fn paths_in_expressions_types_patterns_and_bounds_are_read_but_a_single_name_is_not() {
    let facts = read(
        "fn f(x: a::T) -> b::U where c::V: d::Bound { let _ = e::g(); match x { h::K => {}, _ => {} } let _ = local; }",
    )
    .unwrap();
    let found = paths(&facts);
    for expected in ["a::T", "b::U", "c::V", "d::Bound", "e::g", "h::K"] {
        assert!(found.iter().any(|p| p == expected), "{expected} in {found:?}");
    }
    assert!(!found.iter().any(|p| p == "local"), "a one-segment name is a local, not a dependency: {found:?}");
}

#[test]
fn macro_tokens_attributes_and_derives_are_read() {
    let facts =
        read("#[derive(sqlx::FromRow)]\nstruct S;\nfn f() { x::run!(\"select 1 from t\", y::z(1)); }\n").unwrap();
    let found = paths(&facts);
    assert!(found.contains(&"sqlx::FromRow".to_owned()), "{found:?}");
    assert!(found.contains(&"x::run".to_owned()), "{found:?}");
    assert!(found.contains(&"y::z".to_owned()), "a path inside a macro's tokens: {found:?}");
    assert!(facts.paths.iter().filter(|p| p.segments[0] == "y").all(|p| p.in_macro));
    assert!(facts.literals.iter().any(|l| l.value == "select 1 from t"), "a literal in a macro's tokens");
}

#[test]
fn a_leading_double_colon_inside_a_macro_is_part_of_the_path() {
    let facts = read("fn f() { m!(::sqlx::query(\"x\")); }").unwrap();
    assert!(paths(&facts).contains(&"sqlx::query".to_owned()), "{:?}", paths(&facts));
}

#[test]
fn the_enclosing_function_names_a_literal() {
    let facts = read(
        "struct R;\nimpl R { fn find(&self) { go(\"a b\"); } }\nfn free() { go(\"c d\"); }\nconst C: &str = \"e f\";",
    )
    .unwrap();
    let context = |text: &str| facts.literals.iter().find(|l| l.value == text).unwrap().context.clone();
    assert_eq!(context("a b").as_deref(), Some("R::find"));
    assert_eq!(context("c d").as_deref(), Some("free"));
    assert_eq!(context("e f"), None);
}

#[test]
fn test_code_is_skipped_wherever_it_hides() {
    let facts = read(
        "#[cfg(test)] mod tests { use a::b; fn t() { unsafe { 1 }; } }\n\
         struct S;\nimpl S { #[cfg(test)] fn only_in_tests(&self) { c::d(); } fn kept(&self) { e::f(); } }\n\
         #[cfg(test)] use g::h;\nuse i::j;\n#[cfg(not(test))] use k::l;\n",
    )
    .unwrap();
    let found = paths(&facts);
    assert!(
        !found.contains(&"a::b".to_owned())
            && !found.contains(&"c::d".to_owned())
            && !found.contains(&"g::h".to_owned()),
        "{found:?}"
    );
    assert!(
        found.contains(&"e::f".to_owned()) && found.contains(&"i::j".to_owned()) && found.contains(&"k::l".to_owned()),
        "{found:?}"
    );
    assert!(facts.unsafes.is_empty(), "unsafe inside cfg(test) is not production code");
}

#[test]
fn inline_modules_are_tracked_for_relative_paths() {
    let facts = read("mod outer { mod inner { fn f() { super::g(); } } }\nmod flat;\npub mod open;\n").unwrap();
    let used = facts.paths.iter().find(|p| p.segments == ["super", "g"]).unwrap();
    assert_eq!(used.inline, ["outer", "inner"]);
    let names: Vec<(&str, bool, bool)> = facts.mods.iter().map(|m| (m.name.as_str(), m.public, m.inline)).collect();
    assert_eq!(names, [("outer", false, true), ("inner", false, true), ("flat", false, false), ("open", true, false)]);
}

#[test]
fn the_forbid_attribute_is_read_and_deny_is_not_it() {
    assert!(read("#![forbid(unsafe_code)]\n").unwrap().forbids_unsafe);
    assert!(read("#![forbid(unsafe_code, missing_docs)]\n").unwrap().forbids_unsafe);
    assert!(!read("#![deny(unsafe_code)]\n").unwrap().forbids_unsafe);
    assert!(!read("#![forbid(missing_docs)]\n").unwrap().forbids_unsafe);
    assert!(
        !read("fn f() {}\n#[forbid(unsafe_code)]\nfn g() {}\n").unwrap().forbids_unsafe,
        "an outer attribute is not the crate's"
    );
}

#[test]
fn a_file_that_does_not_parse_is_an_error_with_a_position() {
    let error = read("fn f( {\n").unwrap_err();
    assert!(error.starts_with("1:"), "{error}");
}
