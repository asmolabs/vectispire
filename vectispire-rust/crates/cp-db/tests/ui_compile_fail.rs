//! The programs that must not compile: a query on a target's rows without a `Visibility`.
//!
//! "A route naming a target must resolve a Visibility and pass it to the query" (AGENTS.md) is a
//! compile error here, not a review finding. Each file under `tests/ui/` is one way to forget it, and
//! the `.stderr` beside it is the compiler's refusal — so the test fails both when a program starts
//! compiling and when it fails for another reason than the one it is there to show.

#[test]
fn a_query_on_a_targets_rows_needs_a_visibility() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
