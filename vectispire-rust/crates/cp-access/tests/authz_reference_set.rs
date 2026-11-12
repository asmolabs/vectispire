//! The access module held to what the Java code answers — `reference/access/`, written by
//! `vectispire-core`'s `AccessReferenceSetTest` and checked there on every build.
//!
//! Each test reads one file and fails on the first disagreement, naming the case. The resolution of grants is the
//! pure part here ([`assemble`], [`narrow`]); `tests/engines.rs` runs the same matrix through the real statements on
//! both engines.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "authz_support/mod.rs"]
mod support;

use std::collections::BTreeSet;

use serde_json::Value;
use support::{allowance, filed_in, grants_of_setup, reference, target, targets, visibility};
use vectispire_cp_access::four_eyes::{
    ApproverCounts, Decider, SwitchOnRefusal, required, settles_by_hand, settles_by_import, switch_on_refusal,
};
use vectispire_cp_access::roles::{self, ALL, Role, RoleFlags, flags_of, name_of, role_of};
use vectispire_cp_access::rows::{
    self, NotFound, VisibleScope, require_every_target_of_project, require_visible, require_visible_issue,
    require_visible_project, require_visible_repository, require_visible_row, require_visible_scan,
    require_visible_solution, require_wholly_visible_project, sees_whole_project,
};
use vectispire_cp_access::visibility::{
    Allowance, VisibilityMode, assemble, narrow, projects_of, restriction_of_key, sees_everything,
};
use vectispire_cp_arch_tests::routes::Requirement;
use vectispire_cp_http::Access;

fn role_named(name: &str) -> Role {
    role_of(Some(name)).unwrap_or_else(|| panic!("{name} is a role"))
}

#[test]
fn the_flags_are_the_java_enums() {
    let file = reference("roles.json");
    let java: Vec<&Value> = file["roles"].as_array().unwrap().iter().collect();
    assert_eq!(java.len(), ALL.len(), "the Java enum has {} roles, this one {}", java.len(), ALL.len());
    for (row, role) in java.iter().zip(ALL) {
        // Same order too: `Role.values()` decides the order of the approver lists.
        assert_eq!(row["name"], name_of(role));
        let flags = flags_of(role);
        assert_eq!(row["administrative"], flags.administrative, "{role:?}");
        assert_eq!(row["globalSecurityScope"], flags.global_security_scope, "{role:?}");
        assert_eq!(row["canApproveTriage"], flags.can_approve_triage, "{role:?}");
        assert_eq!(row["canWriteGovernance"], flags.can_write_governance, "{role:?}");
        assert_eq!(row["canCauseEffects"], flags.can_cause_effects, "{role:?}");
        assert_eq!(row["governsPlatform"], flags.governs_platform, "{role:?}");
    }
    for case in file["parse"].as_array().unwrap() {
        let parsed = role_of(case["input"].as_str()).map(name_of);
        assert_eq!(parsed, case["role"].as_str(), "Role.of({})", case["input"]);
    }
    let names = |roles: Vec<Role>| -> Vec<&str> { roles.into_iter().map(name_of).collect() };
    let java_names =
        |key: &str| -> Vec<&str> { file[key].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect() };
    assert_eq!(names(roles::administrative_roles()), java_names("administrative"));
    assert_eq!(names(roles::approver_roles()), java_names("approverRoles"));
    assert_eq!(names(roles::publisher_roles()), java_names("publisherRoles"));
}

/// What a marker's `@PreAuthorize` admits: `None` for a marker with no expression (anonymous, an agent's key).
fn admitted(expression: Option<&str>) -> Option<BTreeSet<&'static str>> {
    let expression = expression?;
    if expression == "isAuthenticated()" {
        return Some(ALL.into_iter().map(name_of).collect());
    }
    let inner = expression.strip_prefix("hasAnyRole(").and_then(|rest| rest.strip_suffix(')')).unwrap_or_else(|| {
        panic!("an expression this test does not read: {expression} — not understood means not trusted")
    });
    Some(
        inner.split(',').map(|quoted| quoted.trim().trim_matches('\'')).map(|name| name_of(role_named(name))).collect(),
    )
}

fn access_of(marker: &str) -> Access {
    [
        Access::Anonymous,
        Access::Account,
        Access::Administrator,
        Access::GovernanceRead,
        Access::PlatformGovernor,
        Access::SecurityLead,
        Access::WriteAccount,
        Access::AgentKey,
    ]
    .into_iter()
    .find(|access| access.marker() == marker)
    .unwrap_or_else(|| panic!("cp-http knows no marker {marker}"))
}

#[test]
fn every_marker_admits_the_roles_its_java_expression_names() {
    let file = reference("markers.json");
    let markers = file["markers"].as_array().unwrap();
    assert_eq!(markers.len(), 8, "the eight markers");
    for row in markers {
        let marker = row["marker"].as_str().unwrap();
        let access = access_of(marker);
        match admitted(row["expression"].as_str()) {
            Some(roles) => {
                for role in ALL {
                    assert_eq!(
                        access.admits(Some(role)),
                        roles.contains(name_of(role)),
                        "{marker} and {role:?}: the chain and the Java expression disagree"
                    );
                }
            }
            None => assert!(
                matches!(access, Access::Anonymous | Access::AgentKey),
                "{marker} carries no role expression, so it names no account"
            ),
        }
    }
}

/// `RouteAuthorizationTest`'s "… agree" tests: each marker's role list is exactly the roles holding the flag it is
/// named after — read from the Java expressions and the Java flags, so that a role added to one and not the other
/// fails here before it fails in a route.
#[test]
fn each_marker_is_the_flag_it_is_named_after() {
    let markers = reference("markers.json");
    let roles_file = reference("roles.json");
    let flag = |key: &str| -> BTreeSet<&str> {
        roles_file["roles"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row[key].as_bool().unwrap())
            .map(|row| name_of(role_named(row["name"].as_str().unwrap())))
            .collect()
    };
    let expression = |marker: &str| -> BTreeSet<&str> {
        let row = markers["markers"].as_array().unwrap().iter().find(|row| row["marker"] == marker).unwrap();
        admitted(row["expression"].as_str()).unwrap()
    };
    assert_eq!(expression("RequiresAdministrator"), flag("administrative"));
    assert_eq!(expression("RequiresGovernanceRead"), flag("globalSecurityScope"));
    assert_eq!(expression("RequiresSecurityLead"), flag("canWriteGovernance"));
    assert_eq!(expression("RequiresPlatformGovernor"), flag("governsPlatform"));
    assert_eq!(expression("RequiresWriteAccount"), flag("canCauseEffects"));
    // And the account that can lift the rule cannot act under it.
    for governor in flag("governsPlatform") {
        assert!(!expression("RequiresWriteAccount").contains(governor));
        assert!(!flag("canApproveTriage").contains(governor));
    }
}

/// `AuthorizationMarkers.SCOPE_GUARDS`: the markers whose every admitted role sees the whole estate — derived, never
/// listed — and `cp-arch-tests`' `settles_scope`, which has to be listed because that crate sees no role.
#[test]
fn the_scope_guards_are_the_markers_whose_every_role_is_global() {
    let markers = reference("markers.json");
    let requirement = |marker: &str| match marker {
        "OpenToAnonymous" => Requirement::Anonymous,
        "RequiresAccount" => Requirement::Account,
        "RequiresAdministrator" => Requirement::Administrator,
        "RequiresAgentKey" => Requirement::AgentKey,
        "RequiresGovernanceRead" => Requirement::GovernanceRead,
        "RequiresPlatformGovernor" => Requirement::PlatformGovernor,
        "RequiresSecurityLead" => Requirement::SecurityLead,
        "RequiresWriteAccount" => Requirement::WriteAccount,
        other => panic!("an unknown marker {other}"),
    };
    let mut guards = Vec::new();
    for row in markers["markers"].as_array().unwrap() {
        let marker = row["marker"].as_str().unwrap();
        let expression = row["expression"].as_str();
        // Only `hasAnyRole(…)` is understood; `isAuthenticated()` and no expression vouch for no scope.
        let derived = expression.is_some_and(|text| text.starts_with("hasAnyRole("))
            && admitted(expression).unwrap().iter().all(|name| role_named(name).has_global_security_scope());
        assert_eq!(requirement(marker).settles_scope(), derived, "{marker}: cp-arch-tests and the role model disagree");
        if derived {
            guards.push(marker);
        }
    }
    // Pinned, so that the derivation cannot quietly turn permissive.
    assert!(guards.contains(&"RequiresSecurityLead") && guards.contains(&"RequiresGovernanceRead"));
    assert!(!guards.contains(&"RequiresWriteAccount") && !guards.contains(&"RequiresAccount"));
}

#[test]
fn the_modes_read_as_java_reads_them() {
    for case in reference("modes.json")["modes"].as_array().unwrap() {
        let mode = VisibilityMode::of(case["input"].as_str());
        assert_eq!(mode.wire_name(), case["mode"].as_str().unwrap(), "VisibilityMode.of({})", case["input"]);
    }
}

#[test]
fn a_key_restricts_as_java_restricts_it() {
    for case in reference("key-restrictions.json")["keys"].as_array().unwrap() {
        let restriction = restriction_of_key(case["targetKind"].as_str(), case["targetId"].as_i64());
        assert_eq!(restriction, visibility(&case["restriction"]), "{case}");
    }
}

#[test]
fn four_eyes_settles_as_java_settles() {
    for case in reference("four-eyes.json")["cases"].as_array().unwrap() {
        let four_eyes = case["fourEyes"].as_bool().unwrap();
        let decider = if case["account"].as_bool().unwrap() {
            Decider::Account { role: case["role"].as_str().unwrap().to_owned() }
        } else {
            Decider::NotAnAccount
        };
        assert_eq!(settles_by_hand(four_eyes, &decider), case["settlesByHand"].as_bool().unwrap(), "by hand: {case}");
        assert_eq!(
            settles_by_import(four_eyes, &decider),
            case["settlesByImport"].as_bool().unwrap(),
            "import: {case}"
        );
    }
}

/// `SettingsService.isEnabled` and the guards of `SettingsAdministrationService.update`, over the spellings and every
/// answer the approver count could give. Where Rust refuses, Java refused in the same words; where Rust lets the
/// value through, Java refused it with none of the four-eyes sentences (its type's validation is the settings
/// module's) or saved it.
#[test]
fn the_four_eyes_switch_is_the_java_one() {
    let file = reference("four-eyes-switch.json");
    for line in file["isEnabled"].as_array().unwrap() {
        let row = match line["stored"].as_str().unwrap() {
            "<absent>" => None,
            "<null>" => Some(""),
            stored => Some(stored),
        };
        assert_eq!(required(row), line["enabled"].as_bool().unwrap(), "{line}");
    }

    let ours = [SwitchOnRefusal::NoApprover, SwitchOnRefusal::OnePublisher, SwitchOnRefusal::OneSignatory]
        .map(SwitchOnRefusal::message);
    let lines = file["switchOn"].as_array().unwrap();
    assert!(lines.len() >= 100, "the matrix is read whole: {} lines", lines.len());
    let mut refused = 0;
    for line in lines {
        let counts = ApproverCounts {
            any_active: line["anyActive"].as_bool().unwrap(),
            two_can_publish_templates: line["twoCanPublishTemplates"].as_bool().unwrap(),
            two_can_sign_off_checklists: line["twoCanSignOffChecklists"].as_bool().unwrap(),
        };
        let java = line["outcome"].as_str().unwrap();
        match switch_on_refusal(line["value"].as_str().unwrap(), counts) {
            Some(refusal) => {
                refused += 1;
                assert_eq!(refusal.message(), java, "{line}");
            }
            None => assert!(!ours.contains(&java), "Java refused what Rust lets through: {line}"),
        }
    }
    // Each of the three sentences is reached, so none of the comparisons above is vacuous.
    for message in ours {
        assert!(lines.iter().any(|line| line["outcome"] == message), "never reached: {message}");
    }
    assert!(refused > 40, "{refused} refusals");
}

#[test]
fn the_allowances_are_the_java_allowances() {
    let file = reference("allowances.json");
    let projects = &file["projects"];
    let setups = file["setups"].as_array().unwrap();
    let cases = file["cases"].as_array().unwrap();
    assert!(cases.len() > 900, "the matrix is read whole: {} cases", cases.len());
    for case in cases {
        let restriction = visibility(&case["restriction"]);
        let account = if case["setup"] == "no-account" {
            Allowance::nothing()
        } else {
            let setup = setups.iter().find(|setup| setup["name"] == case["setup"]).unwrap();
            let role = case["role"].as_str().unwrap();
            if sees_everything(VisibilityMode::of(case["mode"].as_str()), role) {
                Allowance::everything()
            } else {
                let grants = grants_of_setup(setup);
                let filed = filed_in(projects, &projects_of(&grants));
                assemble(&grants, filed)
            }
        };
        assert_eq!(narrow(account, &restriction), allowance(&case["allowance"]), "{case}");
    }
}

// ── the row guards ──────────────────────────────────────────────────────────────────────

fn outcome<T>(result: Result<T, NotFound>, ok: impl FnOnce(T) -> Value) -> Value {
    match result {
        Ok(value) => serde_json::json!({ "ok": ok(value) }),
        Err(refusal) => serde_json::json!({ "notFound": refusal.message }),
    }
}

fn target_json(target: vectispire_cp_db::ScanTarget) -> Value {
    match target {
        vectispire_cp_db::ScanTarget::Repository(id) => serde_json::json!({ "repository": id }),
        vectispire_cp_db::ScanTarget::Container(id) => serde_json::json!({ "container": id }),
    }
}

fn scope_json(scope: VisibleScope) -> Value {
    serde_json::json!({
        "kind": match scope.kind { rows::ScopeKind::Project => "PROJECT", rows::ScopeKind::Solution => "SOLUTION" },
        "id": scope.id,
        "name": scope.name,
        "visible": scope.visible.into_iter().map(target_json).collect::<Vec<_>>(),
        "partial": scope.partial,
    })
}

#[test]
fn the_row_guards_refuse_as_java_refuses() {
    let file = reference("rows.json");
    let allowances = file["allowances"].as_object().unwrap();
    let ids = |value: &Value| -> Vec<i64> { value.as_array().unwrap().iter().map(|id| id.as_i64().unwrap()).collect() };
    let cases = file["cases"].as_array().unwrap();
    let mut checked = 0;
    for case in cases {
        let allowance = allowance(&allowances[case["allowance"].as_str().unwrap()]);
        let visibility = &allowance.visibility;
        if let Some(id) = case.get("project").and_then(Value::as_i64) {
            let project = file["projects"].as_array().unwrap().iter().find(|p| p["id"] == id).unwrap();
            let name = project["name"].as_str();
            let repositories = ids(&project["repositories"]);
            let filed = targets(&project["filed"]);
            assert_eq!(
                sees_whole_project(id, &repositories, &allowance),
                case["seesWholeProject"].as_bool().unwrap(),
                "{case}"
            );
            let wholly = outcome(
                require_wholly_visible_project(id, name, &repositories, &allowance),
                |p| serde_json::json!({ "id": p.project_id, "name": p.name }),
            );
            assert_eq!(wholly, case["whollyVisibleProject"], "wholly visible: {case}");
            assert_eq!(
                outcome(require_visible_project(id, name, &filed, &allowance), scope_json),
                case["visibleProject"],
                "{case}"
            );
            assert_eq!(
                outcome(require_every_target_of_project(id, name, &repositories, &filed, &allowance), scope_json),
                case["everyTargetOfProject"],
                "{case}"
            );
        } else if let Some(id) = case.get("solution").and_then(Value::as_i64) {
            let solution = file["solutions"].as_array().unwrap().iter().find(|s| s["id"] == id).unwrap();
            let got = outcome(
                require_visible_solution(
                    id,
                    solution["name"].as_str(),
                    &ids(&solution["projects"]),
                    &targets(&solution["filed"]),
                    &allowance,
                ),
                scope_json,
            );
            assert_eq!(got, case["visibleSolution"], "{case}");
        } else if case["target"].is_null() {
            let text = |row: &str| Value::String(row.to_owned());
            assert_eq!(
                outcome(require_visible_issue(Some("row"), |_| None, visibility), text),
                case["issue"],
                "{case}"
            );
            assert_eq!(outcome(require_visible_scan(Some("row"), |_| None, visibility), text), case["scan"], "{case}");
            let absent = |_: &&str| Some(vectispire_cp_db::ScanTarget::Repository(101));
            assert_eq!(outcome(require_visible_issue(None, absent, visibility), text), case["issueAbsent"], "{case}");
            assert_eq!(outcome(require_visible_scan(None, absent, visibility), text), case["scanAbsent"], "{case}");
        } else {
            let scan_target = target(&case["target"]);
            let text = |row: &str| Value::String(row.to_owned());
            assert_eq!(
                outcome(require_visible(scan_target, visibility), |t| target_json(t.target())),
                case["visible"],
                "{case}"
            );
            assert_eq!(
                outcome(require_visible_row(Some("row"), scan_target, visibility), text),
                case["rowPresent"],
                "{case}"
            );
            assert_eq!(
                outcome(require_visible_row(None::<&str>, scan_target, visibility), text),
                case["rowAbsent"],
                "{case}"
            );
            assert_eq!(
                outcome(require_visible_issue(Some("row"), |_| Some(scan_target), visibility), text),
                case["issue"],
                "{case}"
            );
            assert_eq!(
                outcome(require_visible_scan(Some("row"), |_| Some(scan_target), visibility), text),
                case["scan"],
                "{case}"
            );
            if let vectispire_cp_db::ScanTarget::Repository(id) = scan_target {
                assert_eq!(
                    outcome(require_visible_repository(Some("row"), id, visibility), text),
                    case["repository"],
                    "{case}"
                );
                assert_eq!(
                    outcome(require_visible_repository(None::<&str>, id, visibility), text),
                    case["repositoryAbsent"],
                    "{case}"
                );
            }
        }
        checked += 1;
    }
    assert!(checked == cases.len() && checked > 90, "{checked} of {} cases read", cases.len());
}
