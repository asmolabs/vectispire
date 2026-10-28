//! **A route without its two answers does not compile.** `RouteSpec::handler` exists only for a route that has declared its
//! role marker *and* how it handles visibility; these cases are the proof, and the compiler's own words are the expected
//! output (`tests/ui/*.stderr`), so a change that made one of them compile would show as a changed file.
//!
//! Rewrite the expectations on purpose, with `TRYBUILD=overwrite`, and read the diff: a toolchain bump moves the wording.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[test]
fn a_route_must_declare_its_marker_and_its_visibility_before_it_has_a_handler() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
    cases.pass("tests/ui/ok/*.rs");
}
