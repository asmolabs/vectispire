//! `unsafe_code.rs` on synthetic workspaces: forbidden everywhere, except one file, a fixed number of times.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fixture, config};
use vectispire_cp_arch_tests::unsafe_code::check;

fn violations(fixture: &Fixture) -> Vec<String> {
    let (violations, read) = check(&config(), &fixture.workspace());
    assert!(read >= 10, "the check read {read} files");
    violations
}

fn mentions(violations: &[String], needle: &str) -> bool {
    violations.iter().any(|violation| violation.contains(needle))
}

#[test]
fn the_clean_workspace_has_no_unsafe() {
    let found = violations(&Fixture::clean());
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn an_unsafe_block_in_a_module_crate_fails() {
    let fixture = Fixture::clean();
    fixture.write(
        "vectispire-cp-targets",
        "src/internal/mod.rs",
        "pub(crate) fn list() { let _ = unsafe { 1 }; crate::persistence::rows(); }\n",
    );
    let found = violations(&fixture);
    assert!(
        mentions(&found, "vectispire-cp-targets: src/internal/mod.rs:1: `unsafe` outside the documented exception"),
        "{found:#?}"
    );
}

#[test]
fn every_form_of_unsafe_is_seen() {
    let forms = [
        "pub unsafe fn f() {}\n",
        "struct S;\nunsafe impl Send for S {}\n",
        "pub unsafe trait T {}\n",
        "unsafe extern \"C\" { pub fn abs(x: i32) -> i32; }\n",
        "struct S;\nimpl S { pub unsafe fn m(&self) {} }\n",
        // Inside a macro's tokens: a block no parser of the item tree would open.
        "macro_rules! m { () => {} }\nfn f() { m! { unsafe { 1 } }; }\n",
    ];
    for form in forms {
        let fixture = Fixture::clean();
        fixture.append("vectispire-cp-issues", "src/lib.rs", form);
        let found = violations(&fixture);
        assert!(mentions(&found, "`unsafe` outside the documented exception"), "{form}\n{found:#?}");
    }
}

#[test]
fn unsafe_in_a_test_or_a_build_script_fails() {
    let fixture = Fixture::clean();
    fixture.write("vectispire-cp-issues", "tests/it.rs", "fn t() { let _ = unsafe { 1 }; }\n");
    assert!(mentions(&violations(&fixture), "tests/it.rs:1"));

    let fixture = Fixture::clean();
    fixture.write("vectispire-domain", "build.rs", "fn main() { unsafe { std::env::set_var(\"A\", \"b\"); } }\n");
    assert!(mentions(&violations(&fixture), "vectispire-domain: build.rs:1"));
}

#[test]
fn the_documented_exception_is_one_file_and_two_uses() {
    let fixture = Fixture::clean();
    fixture.write("vectispire-git", "src/init.rs", "pub fn a() { unsafe { 1 }; }\npub fn b() { unsafe { 2 }; }\n");
    fixture.append("vectispire-git", "src/lib.rs", "pub mod init;\n");
    let found = violations(&fixture);
    assert!(found.is_empty(), "two uses in the file edges/ names are the exception: {found:#?}");

    // A third use is no longer the exception that was written.
    fixture.write(
        "vectispire-git",
        "src/init.rs",
        "pub fn a() { unsafe { 1 }; }\npub fn b() { unsafe { 2 }; }\npub fn c() { unsafe { 3 }; }\n",
    );
    assert!(mentions(&violations(&fixture), "3 uses of `unsafe`, and edges/ allows 2 here"));

    // And the same two uses in another file of the same crate are not it.
    let fixture = Fixture::clean();
    fixture.write("vectispire-git", "src/other.rs", "pub fn a() { unsafe { 1 }; }\n");
    fixture.append("vectispire-git", "src/lib.rs", "pub mod other;\n");
    assert!(mentions(
        &violations(&fixture),
        "vectispire-git: src/other.rs:1: `unsafe` outside the documented exception"
    ));
}

#[test]
fn a_control_plane_crate_has_to_forbid_it_itself() {
    // The workspace lint is `deny`, which a crate can relax; a control-plane crate says `forbid` in its own root.
    let fixture = Fixture::clean();
    fixture.write("vectispire-cp-targets", "src/lib.rs", "mod internal;\nmod persistence;\nmod web;\n");
    assert!(mentions(&violations(&fixture), "vectispire-cp-targets: src/lib.rs lacks `#![forbid(unsafe_code)]`"));

    // `deny` is not `forbid`.
    let fixture = Fixture::clean();
    fixture.write(
        "vectispire-cp-targets",
        "src/lib.rs",
        "#![deny(unsafe_code)]\nmod internal;\nmod persistence;\nmod web;\n",
    );
    assert!(mentions(&violations(&fixture), "lacks `#![forbid(unsafe_code)]`"));

    // The binary's root counts too.
    let fixture = Fixture::clean();
    fixture.write("vectispire-cp-app", "src/main.rs", "fn main() {}\n");
    assert!(mentions(&violations(&fixture), "vectispire-cp-app: src/main.rs lacks"));

    // The agent's crates carry the workspace lint, not this attribute: only the control plane is held to it here.
    assert!(violations(&Fixture::clean()).is_empty());
}
