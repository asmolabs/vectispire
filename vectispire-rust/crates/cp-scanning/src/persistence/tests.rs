//! `catalog_queries` on real servers, both engines: every statement it writes, run once, its answer held to what the
//! Java side's `ScanCatalog`, `ScanRepository`, `FindingRepository` and `FindingGraphQueriesImpl` answer.
//!
//! **Written before the module's catalog was rewritten on SeaORM** (2026-10-27), so that one suite judges both
//! versions: until then its nineteen functions were run by nothing but the route tests. The scans and findings are
//! written through the module's own checked statements (`insert_scan`, `write_result`, `findings::save_all`), and a
//! scan read back is compared with `persistence::scan`'s, so that the reader under test is never judged by itself.
//!
//! Every check runs, and the failures are reported together.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::BTreeSet;

use self::support::Migrated;
use crate::persistence::catalog_queries::{self as catalog, ScanFindingView};
use crate::persistence::findings::{self, NewFinding};
use crate::persistence::{self, NewScan, ResultWrite};
use time::{Duration, OffsetDateTime};
use vectispire_cp_db::types::to_microseconds;
use vectispire_cp_db::{Engine, Mode, ScanTarget, Tx, Visibility};

const REPO_A: i64 = 101;
const REPO_B: i64 = 102;
const IMAGE_A: i64 = 201;
const IMAGE_B: i64 = 202;
const ISSUE_A: i64 = 301;
const ISSUE_B: i64 = 302;

#[test]
fn on_mysql() {
    run(Engine::MySql);
}

#[test]
fn on_postgresql() {
    run(Engine::PostgreSql);
}

type Check = Result<(), String>;

macro_rules! ensure_eq {
    ($left:expr, $right:expr, $($what:tt)+) => {{
        let (left, right) = (&$left, &$right);
        if left != right {
            return Err(format!("{}: {:?} != {:?}", format!($($what)+), left, right));
        }
    }};
}

fn run(engine: Engine) {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
        let server = Migrated::start(engine).await;
        seed(&server);
        let db = server.connect().await;
        let mut failures = Vec::new();
        macro_rules! each {
            ($($check:ident),* $(,)?) => {$(
                // Each check in a transaction of its own, rolled back: none sees another's rows.
                let mut tx = db.begin(Mode::ReadWrite).await.unwrap();
                if let Err(failure) = $check(&mut tx).await {
                    failures.push(format!("{}: {failure}", stringify!($check)));
                }
                tx.rollback().await.unwrap();
            )*};
        }
        each!(
            the_sboms_are_read_per_target_with_or_without_one,
            each_target_s_newest_completed_scan_is_found,
            a_target_s_recent_scans_are_newest_first_and_bounded,
            a_finding_reads_back_what_was_written,
            the_licence_findings_are_named_by_type_or_by_source,
            the_package_impacts_count_targets_by_the_dual_target_rule,
            the_graph_finds_packages_cves_and_keeps_secrets_out,
            a_wide_allowance_is_not_refused_by_the_driver,
            the_scans_holding_an_sbom_below_a_mark_are_newest_first,
            the_last_scan_of_each_repository_is_its_newest_whatever_its_status,
            a_repository_s_history_is_newest_first_by_branch,
            an_issue_s_sightings_are_newest_scan_first,
            the_latest_finished_scan_is_completed_or_failed_never_in_flight,
        );
        db.close().await;
        assert!(failures.is_empty(), "{engine}: {} check(s) failed:\n  {}", failures.len(), failures.join("\n  "));
    });
}

/// Two repositories, two images and two issues, fixed ids, for the foreign keys.
fn seed(server: &Migrated) {
    let overriding = match server.engine {
        Engine::MySql => "",
        Engine::PostgreSql => " overriding system value",
    };
    for id in [REPO_A, REPO_B] {
        server.sql_as_admin(&format!(
            "insert into t_repository (id, url, branch){overriding} values ({id}, 'https://forge.example/r{id}.git', 'main')"
        ));
    }
    for id in [IMAGE_A, IMAGE_B] {
        server.sql_as_admin(&format!(
            "insert into t_container (id, image_name, tag){overriding} values ({id}, 'registry.example/i{id}', 'v1')"
        ));
    }
    let falsity = match server.engine {
        Engine::MySql => "0",
        Engine::PostgreSql => "false",
    };
    for id in [ISSUE_A, ISSUE_B] {
        server.sql_as_admin(&format!(
            "insert into t_issue (id, repo_id, fingerprint, type, state, first_seen_at, last_seen_at, is_kev, times_seen, \
             triage_status, reachability, revision){overriding} values ({id}, {REPO_A}, 'fp-{id}', 'DEPENDENCY', 'open', \
             '2026-01-01 00:00:00', '2026-01-01 00:00:00', {falsity}, 1, 'under_review', 'unknown', 0)"
        ));
    }
}

fn at(seconds: i64) -> OffsetDateTime {
    to_microseconds(
        OffsetDateTime::from_unix_timestamp(1_760_000_000 + seconds).unwrap() + Duration::microseconds(123_456),
    )
}

/// A scan written as the trigger writes one, then given its status (and an SBOM) as a result writes them.
async fn scan(
    tx: &mut Tx,
    repo: Option<i64>,
    image: Option<i64>,
    status: &str,
    seconds: i64,
    sbom: Option<&str>,
) -> Result<i64, String> {
    scan_on(tx, repo, image, "main", status, seconds, sbom).await
}

async fn scan_on(
    tx: &mut Tx,
    repo: Option<i64>,
    image: Option<i64>,
    branch: &str,
    status: &str,
    seconds: i64,
    sbom: Option<&str>,
) -> Result<i64, String> {
    let new = NewScan {
        status: "pending".into(),
        created_at: at(seconds),
        repo_id: repo,
        container_id: image,
        branch: branch.into(),
        sub_path: None,
        required_agent_label: None,
        not_before: None,
    };
    let id = persistence::insert_scan(tx, &new).await.map_err(|e| e.to_string())?;
    let result = ResultWrite {
        id,
        status: status.into(),
        findings_count: 0,
        new_issues_count: 0,
        resolved_issues_count: 0,
        duration_ms: Some(1_500),
        sbom: sbom.map(str::to_owned),
        project: None,
        error: (status == "failed").then(|| "the clone failed".to_owned()),
        plugin_steps: None,
        detected_languages: None,
        examined_types: None,
    };
    persistence::write_result(tx, &result).await.map_err(|e| e.to_string())?;
    Ok(id)
}

fn finding(scan_id: i64, package: Option<&str>) -> NewFinding {
    NewFinding {
        scan_id,
        issue_id: None,
        type_: "DEPENDENCY".into(),
        source: "grype".into(),
        tool: Some("grype".into()),
        tool_name: Some("Grype".into()),
        tool_version: Some("0.92.0".into()),
        identifier: Some("CVE-2026-0001".into()),
        severity: Some("HIGH".into()),
        package_name: package.map(str::to_owned),
        package_version: Some("1.2.3".into()),
        purl: package.map(|name| format!("pkg:maven/org.example/{name}@1.2.3")),
        file_path: Some("pom.xml".into()),
        line: Some(12),
        direct_dependency: Some(true),
        owasp_category: Some("A06".into()),
        epss_score: Some(0.25),
        cvss_score: Some(7.5),
        cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".into()),
        fix_state: Some("fixed".into()),
        fix_versions: Some("1.2.4".into()),
        link: Some("https://advisories.example/CVE-2026-0001".into()),
        is_kev: true,
        description: Some("A flaw in the parser.".into()),
        created_at: at(0),
    }
}

async fn save(tx: &mut Tx, rows: &[NewFinding]) -> Check {
    findings::save_all(tx, rows).await.map_err(|e| e.to_string())
}

fn set<T: Ord + Clone>(items: impl IntoIterator<Item = T>) -> BTreeSet<T> {
    items.into_iter().collect()
}

fn only(targets: &[ScanTarget]) -> Visibility {
    Visibility::only(targets.iter().copied())
}

/// Java's `sbomsOfAll`, `sbomsOfUntargeted`, `sbomsOfRepositories` and `sbomsOfContainers`: **every** scan of what is
/// asked, its SBOM or none — the licence inventory reads a scan's licence findings by its identifier, and a scan
/// whose SBOM retention cleared (or that never had one) still has them. An image's scans are every scan naming it:
/// the inventory, not the query, leaves out the SBOM of one that also names a repository.
async fn the_sboms_are_read_per_target_with_or_without_one(tx: &mut Tx) -> Check {
    let repo = scan(tx, Some(REPO_A), None, "completed", 1, Some("{\"a\":1}")).await?;
    let repo_bare = scan(tx, Some(REPO_A), None, "completed", 2, None).await?;
    let both = scan(tx, Some(REPO_B), Some(IMAGE_A), "completed", 3, Some("{\"b\":1}")).await?;
    let image = scan(tx, None, Some(IMAGE_A), "completed", 4, Some("{\"c\":1}")).await?;
    let untargeted = scan(tx, None, None, "completed", 5, Some("{\"d\":1}")).await?;
    let untargeted_bare = scan(tx, None, None, "failed", 6, None).await?;

    let ids = |rows: Vec<catalog::ScanSbom>| set(rows.into_iter().map(|row| row.id));
    let all = catalog::sboms_of_all(tx).await.map_err(|e| e.to_string())?;
    let with_sbom = all.iter().find(|row| row.id == repo).map(|row| row.sbom.clone());
    ensure_eq!(with_sbom, Some(Some("{\"a\":1}".to_owned())), "a scan's SBOM, read back");
    ensure_eq!(ids(all), set([repo, repo_bare, both, image, untargeted, untargeted_bare]), "every scan");
    let read = catalog::sboms_of_untargeted(tx).await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(read), set([untargeted, untargeted_bare]), "the scans of no target");
    let read = catalog::sboms_of_targets(tx, &[ScanTarget::Repository(REPO_A)]).await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(read), set([repo, repo_bare]), "a repository's");
    let read = catalog::sboms_of_targets(tx, &[ScanTarget::Container(IMAGE_A)]).await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(read), set([both, image]), "an image's: every scan naming it");
    let read = catalog::sboms_of_targets(tx, &[ScanTarget::Repository(REPO_B), ScanTarget::Container(IMAGE_A)])
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 2, "a scan reached through both of its targets is read once");
    let read = catalog::sboms_of_targets(tx, &[]).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 0, "no target, no scan");
    Ok(())
}

/// Java's `findNewestWithStatusOfRepositories` and `…OfContainers`: the newest completed scan by identifier — a newer
/// failed or pending one is not it — and whether it still holds its SBOM.
async fn each_target_s_newest_completed_scan_is_found(tx: &mut Tx) -> Check {
    scan(tx, Some(REPO_A), None, "completed", 1, Some("{}")).await?;
    let repo_newest = scan(tx, Some(REPO_A), None, "completed", 2, None).await?;
    scan(tx, Some(REPO_A), None, "failed", 3, None).await?;
    scan(tx, Some(REPO_A), None, "pending", 4, None).await?;
    let image_newest = scan(tx, None, Some(IMAGE_A), "completed", 5, Some("{}")).await?;
    scan(tx, Some(REPO_B), None, "failed", 6, None).await?;

    let read = catalog::newest_completed(
        tx,
        &[
            ScanTarget::Repository(REPO_A),
            ScanTarget::Repository(REPO_B),
            ScanTarget::Container(IMAGE_A),
            ScanTarget::Container(IMAGE_B),
        ],
    )
    .await
    .map_err(|e| e.to_string())?;
    let summary: Vec<(ScanTarget, i64, bool, OffsetDateTime)> =
        read.iter().map(|(target, row)| (*target, row.scan_id, row.sbom_stored, row.created_at)).collect();
    ensure_eq!(
        summary,
        vec![
            (ScanTarget::Repository(REPO_A), repo_newest, false, at(2)),
            (ScanTarget::Container(IMAGE_A), image_newest, true, at(5)),
        ],
        "each target's newest completed scan; none for a target with no completed one"
    );
    Ok(())
}

async fn a_target_s_recent_scans_are_newest_first_and_bounded(tx: &mut Tx) -> Check {
    let first = scan(tx, Some(REPO_A), None, "completed", 1, None).await?;
    let second = scan(tx, Some(REPO_A), None, "failed", 2, None).await?;
    let third = scan(tx, Some(REPO_A), None, "pending", 3, None).await?;
    let image = scan(tx, None, Some(IMAGE_A), "completed", 4, None).await?;
    let read = catalog::recent_ids(tx, ScanTarget::Repository(REPO_A), 2).await.map_err(|e| e.to_string())?;
    ensure_eq!(read, vec![third, second], "the repository's two newest, whatever their status");
    let read = catalog::recent_ids(tx, ScanTarget::Repository(REPO_A), 10).await.map_err(|e| e.to_string())?;
    ensure_eq!(read, vec![third, second, first], "all of them");
    let read = catalog::recent_ids(tx, ScanTarget::Container(IMAGE_A), 10).await.map_err(|e| e.to_string())?;
    ensure_eq!(read, vec![image], "the image's");
    Ok(())
}

fn expected(id: i64, new: &NewFinding) -> ScanFindingView {
    ScanFindingView {
        id,
        scan_id: new.scan_id,
        type_: new.type_.clone(),
        severity: new.severity.clone(),
        identifier: new.identifier.clone(),
        package_name: new.package_name.clone(),
        package_version: new.package_version.clone(),
        purl: new.purl.clone(),
        file_path: new.file_path.clone(),
        owasp_category: new.owasp_category.clone(),
        source: Some(new.source.clone()),
        tool: new.tool.clone(),
        tool_name: new.tool_name.clone(),
        tool_version: new.tool_version.clone(),
        epss_score: new.epss_score,
        is_kev: new.is_kev,
        created_at: new.created_at,
        cvss_score: new.cvss_score,
        cvss_vector: new.cvss_vector.clone(),
        fix_state: new.fix_state.clone(),
        fix_versions: new.fix_versions.clone(),
        link: new.link.clone(),
        issue_id: new.issue_id,
        is_direct_dependency: new.direct_dependency,
        line: new.line,
        description: new.description.clone(),
    }
}

/// Every column of `t_finding`, read back by `findings` and by `findings_of_scans`, in key order; and the absent
/// values absent — a null flag read as `false`, a null line as `0`, would say what no scanner said.
async fn a_finding_reads_back_what_was_written(tx: &mut Tx) -> Check {
    let one = scan(tx, Some(REPO_A), None, "completed", 1, None).await?;
    let two = scan(tx, None, Some(IMAGE_A), "completed", 2, None).await?;
    let full = NewFinding { issue_id: Some(ISSUE_A), ..finding(one, Some("jackson-databind")) };
    let mut sparse = finding(one, None);
    sparse.is_kev = false;
    sparse.direct_dependency = None;
    sparse.line = None;
    sparse.epss_score = None;
    sparse.cvss_score = None;
    sparse.identifier = None;
    sparse.severity = None;
    sparse.description = None;
    sparse.tool = None;
    let other = finding(two, Some("openssl"));
    save(tx, &[full.clone(), sparse.clone(), other.clone()]).await?;

    let read = catalog::findings(tx, one).await.map_err(|e| e.to_string())?;
    let ids: Vec<i64> = read.iter().map(|row| row.id).collect();
    if ids.len() != 2 || ids[0] >= ids[1] {
        return Err(format!("the scan's two findings, in key order: {ids:?}"));
    }
    ensure_eq!(read, vec![expected(ids[0], &full), expected(ids[1], &sparse)], "the scan's findings, every column");
    let read = catalog::findings_of_scans(tx, &[two, one]).await.map_err(|e| e.to_string())?;
    let scans: Vec<i64> = read.iter().map(|row| row.scan_id).collect();
    ensure_eq!(scans, vec![one, one, two], "the findings of both scans, in key order");
    let read = catalog::findings_of_scans(tx, &[]).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 0, "no scan, no finding");
    Ok(())
}

/// Java's `findLicenseFindings`: `lower(type) = 'license' or lower(source) like '%license%'` — the licence scanner's
/// findings name it by their source — over the scans asked, each asked once however often it is named.
async fn the_licence_findings_are_named_by_type_or_by_source(tx: &mut Tx) -> Check {
    let one = scan(tx, Some(REPO_A), None, "completed", 1, None).await?;
    let two = scan(tx, Some(REPO_B), None, "completed", 2, None).await?;
    let by_type = NewFinding { type_: "LICENSE".into(), identifier: Some("GPL-3.0".into()), ..finding(one, Some("a")) };
    let by_source =
        NewFinding { source: "trivy-license".into(), identifier: Some("AGPL-3.0".into()), ..finding(one, Some("b")) };
    let neither = finding(one, Some("c"));
    let elsewhere = NewFinding { type_: "license".into(), ..finding(two, Some("d")) };
    save(tx, &[by_type, by_source, neither, elsewhere]).await?;
    let read = catalog::license_findings(tx, &[one, one]).await.map_err(|e| e.to_string())?;
    let found: Vec<Option<String>> = read.iter().map(|row| row.identifier.clone()).collect();
    ensure_eq!(
        found,
        vec![Some("GPL-3.0".to_owned()), Some("AGPL-3.0".to_owned())],
        "the licence findings of one scan"
    );
    let read = catalog::license_findings(tx, &[]).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 0, "no scan, no finding");
    Ok(())
}

/// Java's `packageImpacts`: per package, the distinct repositories, the distinct images **of scans naming no
/// repository**, direct and transitive usages (a null flag is not direct), the distinct CVEs among the identifiers,
/// the highest CVSS and the least purl; within what the reader may see, a scan naming both being the repository's.
async fn the_package_impacts_count_targets_by_the_dual_target_rule(tx: &mut Tx) -> Check {
    let repo_a = scan(tx, Some(REPO_A), None, "completed", 1, None).await?;
    let repo_b = scan(tx, Some(REPO_B), None, "completed", 2, None).await?;
    let image = scan(tx, None, Some(IMAGE_A), "completed", 3, None).await?;
    let both = scan(tx, Some(REPO_B), Some(IMAGE_B), "completed", 4, None).await?;
    let usage = |scan_id, direct: Option<bool>, identifier: &str, cvss: Option<f64>, purl: &str| NewFinding {
        direct_dependency: direct,
        identifier: Some(identifier.into()),
        cvss_score: cvss,
        purl: Some(purl.into()),
        ..finding(scan_id, Some("log4j-core"))
    };
    save(
        tx,
        &[
            usage(repo_a, Some(true), "CVE-2021-44228", Some(10.0), "pkg:maven/b"),
            usage(repo_a, Some(false), "cve-2021-45046", Some(9.0), "pkg:maven/a"),
            usage(repo_b, None, "CVE-2021-44228", None, "pkg:maven/c"),
            usage(image, Some(true), "GHSA-jfh8-c2jp-5v3q", Some(6.5), "pkg:maven/d"),
            usage(both, Some(false), "CVE-2021-44832", Some(6.6), "pkg:maven/e"),
            NewFinding { package_name: Some("   ".into()), ..finding(repo_a, Some("blank")) },
        ],
    )
    .await?;
    let impact_of = |rows: Vec<catalog::PackageImpact>| {
        rows.into_iter()
            .filter(|row| row.package_name == "log4j-core")
            .map(|row| {
                (
                    row.any_purl,
                    row.distinct_repositories,
                    row.distinct_containers,
                    row.direct_usages,
                    row.transitive_usages,
                    row.distinct_cves,
                    row.max_cvss,
                )
            })
            .collect::<Vec<_>>()
    };
    let all = catalog::package_impacts(tx, &Visibility::Everything).await.map_err(|e| e.to_string())?;
    ensure_eq!(all.len(), 1, "one package; a blank name is no package");
    ensure_eq!(
        impact_of(all),
        vec![(Some("pkg:maven/a".to_owned()), 2, 1, 2, 3, 3, Some(10.0))],
        "the estate's figures"
    );
    let read = catalog::package_impacts(tx, &only(&[ScanTarget::Container(IMAGE_B), ScanTarget::Container(IMAGE_A)]))
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(
        impact_of(read),
        vec![(Some("pkg:maven/d".to_owned()), 0, 1, 1, 0, 0, Some(6.5))],
        "a reader of the images: the scan naming a repository is not theirs"
    );
    let read =
        catalog::package_impacts(tx, &only(&[ScanTarget::Repository(REPO_B)])).await.map_err(|e| e.to_string())?;
    ensure_eq!(
        impact_of(read),
        vec![(Some("pkg:maven/c".to_owned()), 1, 0, 0, 2, 2, Some(6.6))],
        "a reader of the repository: the scan naming both is"
    );
    let read = catalog::package_impacts(tx, &only(&[])).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 0, "an allowance of nothing sees nothing");
    Ok(())
}

/// Java's `forGraph`: a package or purl substring, case-insensitively; a CVE exactly, case-insensitively; secrets
/// left out when asked (a finding with no type kept); within the reader's targets; and each row's scan read whole.
async fn the_graph_finds_packages_cves_and_keeps_secrets_out(tx: &mut Tx) -> Check {
    let repo = scan(tx, Some(REPO_A), None, "completed", 1, Some("{}")).await?;
    let both = scan(tx, Some(REPO_B), Some(IMAGE_A), "completed", 2, None).await?;
    let lib = |scan_id, name: &str, identifier: &str| NewFinding {
        identifier: Some(identifier.into()),
        ..finding(scan_id, Some(name))
    };
    save(
        tx,
        &[
            lib(repo, "Jackson-Databind", "CVE-2020-36518"),
            lib(repo, "commons-text", "CVE-2022-42889"),
            NewFinding { type_: "SECRET".into(), ..lib(repo, "jackson-secrets", "aws-key") },
            lib(both, "jackson-core", "CVE-2020-36518x"),
        ],
    )
    .await?;
    let names = |rows: &[catalog::FindingOnScanRow]| {
        rows.iter().map(|row| row.finding.package_name.clone().unwrap_or_default()).collect::<Vec<_>>()
    };
    let read = catalog::findings_for_graph(tx, " JACKSON ", false, true, &Visibility::Everything)
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(names(&read), vec!["Jackson-Databind", "jackson-core"], "a package substring, secrets left out");
    let scan_read = persistence::scan(tx, repo).await.map_err(|e| e.to_string())?;
    ensure_eq!(Some(read[0].scan.clone()), scan_read, "the row's scan, every column, as the checked reader reads it");
    let read = catalog::findings_for_graph(tx, "jackson", false, false, &Visibility::Everything)
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 3, "secrets kept when not asked to leave them out");
    let read = catalog::findings_for_graph(tx, "pkg:maven/org.example/commons", false, true, &Visibility::Everything)
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(names(&read), vec!["commons-text"], "a purl substring");
    let read = catalog::findings_for_graph(tx, "cve-2020-36518", true, true, &Visibility::Everything)
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(names(&read), vec!["Jackson-Databind"], "a CVE exactly, not a prefix of another");
    let read = catalog::findings_for_graph(tx, "jackson", false, true, &only(&[ScanTarget::Container(IMAGE_A)]))
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 0, "a reader of the image does not see the scan naming a repository");
    let read = catalog::findings_for_graph(tx, "", false, true, &only(&[ScanTarget::Repository(REPO_B)]))
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(names(&read), vec!["jackson-core"], "no query: every package the reader may see");
    let read = catalog::findings_for_graph(tx, "jackson", false, true, &only(&[])).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 0, "an allowance of nothing sees nothing");
    Ok(())
}

/// Java's `WideAllowanceIntegrationTest`: a reader granted more targets than a statement may bind parameters —
/// 65,535 on both drivers — is answered, not refused; the identifiers are written into the statement.
async fn a_wide_allowance_is_not_refused_by_the_driver(tx: &mut Tx) -> Check {
    let repo = scan(tx, Some(REPO_A), None, "completed", 1, None).await?;
    save(tx, &[finding(repo, Some("zlib"))]).await?;
    let wide =
        Visibility::only((1_000_000..1_070_000).map(ScanTarget::Repository).chain([ScanTarget::Repository(REPO_A)]));
    let read = catalog::package_impacts(tx, &wide).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 1, "the package impacts of 70,001 granted repositories");
    let read = catalog::findings_for_graph(tx, "zlib", false, true, &wide).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 1, "the graph of 70,001 granted repositories");
    Ok(())
}

async fn the_scans_holding_an_sbom_below_a_mark_are_newest_first(tx: &mut Tx) -> Check {
    let first = scan(tx, Some(REPO_A), None, "completed", 1, Some("{}")).await?;
    scan(tx, Some(REPO_A), None, "completed", 2, None).await?;
    let third = scan(tx, None, Some(IMAGE_A), "completed", 3, Some("{}")).await?;
    let fourth = scan(tx, None, None, "completed", 4, Some("{}")).await?;
    let read = catalog::ids_with_sbom_before(tx, fourth, 10).await.map_err(|e| e.to_string())?;
    ensure_eq!(read, vec![third, first], "below the mark, strictly, those with an SBOM");
    let read = catalog::ids_with_sbom_before(tx, fourth + 1, 1).await.map_err(|e| e.to_string())?;
    ensure_eq!(read, vec![fourth], "bounded");
    Ok(())
}

/// The fix of 2026-10-26, held: Java's `findLastScanInstantPerRepository` — every scan, whatever its status.
async fn the_last_scan_of_each_repository_is_its_newest_whatever_its_status(tx: &mut Tx) -> Check {
    scan(tx, Some(REPO_A), None, "completed", 1, None).await?;
    scan(tx, Some(REPO_A), None, "failed", 5, None).await?;
    scan(tx, Some(REPO_B), None, "pending", 3, None).await?;
    scan(tx, None, Some(IMAGE_A), "completed", 9, None).await?;
    let read = catalog::last_scan_at_per_repository(tx).await.map_err(|e| e.to_string())?;
    let read: Vec<(i64, OffsetDateTime)> = read.into_iter().collect();
    ensure_eq!(read, vec![(REPO_A, at(5)), (REPO_B, at(3))], "each repository's newest, no image");
    Ok(())
}

/// Newest first by instant then key — two scans in one instant included — on one branch or all; each row as the
/// checked reader reads it.
async fn a_repository_s_history_is_newest_first_by_branch(tx: &mut Tx) -> Check {
    let old = scan_on(tx, Some(REPO_A), None, "main", "completed", 1, Some("{}")).await?;
    let tie_low = scan_on(tx, Some(REPO_A), None, "main", "failed", 5, None).await?;
    let tie_high = scan_on(tx, Some(REPO_A), None, "main", "completed", 5, None).await?;
    let other = scan_on(tx, Some(REPO_A), None, "develop", "completed", 3, None).await?;
    scan_on(tx, Some(REPO_B), None, "main", "completed", 9, None).await?;
    let ids = |rows: &[persistence::ScanRow]| rows.iter().map(|row| row.id).collect::<Vec<_>>();
    let read = catalog::history_of_repository(tx, REPO_A, None, 10).await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(&read), vec![tie_high, tie_low, other, old], "every branch");
    for row in &read {
        let checked = persistence::scan(tx, row.id).await.map_err(|e| e.to_string())?;
        ensure_eq!(Some(row.clone()), checked, "scan {} as the checked reader reads it", row.id);
    }
    let read = catalog::history_of_repository(tx, REPO_A, Some("main"), 2).await.map_err(|e| e.to_string())?;
    ensure_eq!(ids(&read), vec![tie_high, tie_low], "one branch, bounded");
    Ok(())
}

async fn an_issue_s_sightings_are_newest_scan_first(tx: &mut Tx) -> Check {
    let early = scan(tx, Some(REPO_A), None, "completed", 1, None).await?;
    let late = scan(tx, Some(REPO_A), None, "completed", 7, None).await?;
    let middle = scan(tx, Some(REPO_A), None, "completed", 4, None).await?;
    save(
        tx,
        &[
            NewFinding { issue_id: Some(ISSUE_A), ..finding(early, Some("a")) },
            NewFinding { issue_id: Some(ISSUE_A), ..finding(late, Some("a")) },
            NewFinding { issue_id: Some(ISSUE_B), ..finding(middle, Some("b")) },
            NewFinding { issue_id: Some(ISSUE_A), ..finding(middle, Some("a")) },
        ],
    )
    .await?;
    let read = catalog::sightings_of_issue(tx, ISSUE_A, 10).await.map_err(|e| e.to_string())?;
    let scans: Vec<i64> = read.iter().map(|row| row.scan.id).collect();
    ensure_eq!(scans, vec![late, middle, early], "the issue's sightings, newest scan first");
    if read.iter().any(|row| row.finding.issue_id != Some(ISSUE_A) || row.finding.scan_id != row.scan.id) {
        return Err(format!("every sighting is the issue's, on its own scan: {read:?}"));
    }
    let read = catalog::sightings_of_issue(tx, ISSUE_A, 1).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 1, "bounded");
    Ok(())
}

/// Java's `findLatestWithStatusPer…` and `findNewestWithStatusOf…`, over the statuses not in flight: a newer pending
/// or running scan does not hide the last one that finished; an image's are every scan naming it.
async fn the_latest_finished_scan_is_completed_or_failed_never_in_flight(tx: &mut Tx) -> Check {
    scan(tx, Some(REPO_A), None, "completed", 1, None).await?;
    let repo_failed = scan(tx, Some(REPO_A), None, "failed", 2, None).await?;
    scan(tx, Some(REPO_A), None, "scanning", 3, None).await?;
    scan(tx, Some(REPO_B), None, "pending", 4, None).await?;
    let both = scan(tx, Some(REPO_B), Some(IMAGE_A), "completed", 5, None).await?;
    let image = scan(tx, None, Some(IMAGE_B), "completed", 6, None).await?;
    scan(tx, None, Some(IMAGE_B), "pending", 7, None).await?;

    let summary = |rows: Vec<persistence::LatestRow>| {
        let mut rows: Vec<(i64, i64, String)> =
            rows.into_iter().map(|row| (row.target_id, row.scan_id, row.status)).collect();
        rows.sort();
        rows
    };
    let read = catalog::latest_finished_per_repository(tx).await.map_err(|e| e.to_string())?;
    ensure_eq!(
        summary(read),
        vec![(REPO_A, repo_failed, "failed".to_owned()), (REPO_B, both, "completed".to_owned())],
        "per repository"
    );
    let read = catalog::latest_finished_per_container(tx).await.map_err(|e| e.to_string())?;
    ensure_eq!(
        summary(read),
        vec![(IMAGE_A, both, "completed".to_owned()), (IMAGE_B, image, "completed".to_owned())],
        "per image"
    );
    let read =
        catalog::latest_finished_of_target(tx, ScanTarget::Repository(REPO_A)).await.map_err(|e| e.to_string())?;
    let read = read.map(|row| (row.scan_id, row.error, row.created_at));
    ensure_eq!(read, Some((repo_failed, Some("the clone failed".to_owned()), at(2))), "one repository's, every column");
    let read =
        catalog::latest_finished_of_target(tx, ScanTarget::Container(IMAGE_B)).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.map(|row| row.scan_id), Some(image), "one image's");
    let read = catalog::latest_finished_of_target(tx, ScanTarget::Container(IMAGE_A + 999))
        .await
        .map_err(|e| e.to_string())?;
    ensure_eq!(read.map(|row| row.scan_id), None, "none for a target never scanned");
    Ok(())
}
