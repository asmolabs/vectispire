//! `InventoryRepository` on real servers, both engines: every statement it writes, run once, its answer held to what
//! the Java side's `ComponentRepository`, `BuildSbomRepository`, `BuildSbomComponentRepository`,
//! `ApiEndpointRepository`, `ApiContractRepository` and `LicenseGovernanceService` answer.
//!
//! **Written before the repository was rewritten on SeaORM** (2026-10-27), so that one suite judges both versions.
//!
//! **Each check commits, and the tables are emptied after it**, where the other modules' suites roll a transaction
//! back: half of this repository's reads take a `Db` and open their own transaction, which would not see a
//! rolled-back write. The upsert of the licence policy takes the instant it stamps in the port; it is reached
//! through [`store_policy`], the one place the two versions differ.
//!
//! Every check runs, and the failures are reported together.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use self::support::Migrated;
use crate::persistence::{
    ApiContractRow, ApiEndpointRow, BuildSbomRow, ComponentRow, InventoryRepository as Repo, NewApiContract,
    NewApiEndpoint, NewBuildSbom, NewBuildSbomComponent, NewComponent,
};
use time::{Duration, OffsetDateTime};
use vectispire_cp_db::parity;
use vectispire_cp_db::types::to_microseconds;
use vectispire_cp_db::{Db, Engine, Mode, Tx};

const REPO_A: i64 = 101;
const REPO_B: i64 = 102;
const IMAGE_A: i64 = 201;
/// Repository A's two scans, the image's, and one naming repository B and the image.
const SCAN_A1: i64 = 11;
const SCAN_A2: i64 = 12;
const SCAN_IMAGE: i64 = 13;
const SCAN_BOTH: i64 = 14;

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
                if let Err(failure) = $check(&db).await {
                    failures.push(format!("{}: {failure}", stringify!($check)));
                }
                empty(&server);
            )*};
        }
        each!(
            a_component_reads_back_what_was_written,
            the_components_of_several_scans_are_read_once_in_scan_then_key_order,
            the_components_of_a_scan_are_updated_counted_locked_and_deleted,
            a_component_is_searched_by_name_or_purl_newest_scan_first,
            a_component_s_versions_are_newest_first_by_name_or_purl,
            the_distinct_figures_are_read_across_the_estate,
            a_build_sbom_reads_back_what_was_written_newest_first,
            a_scan_s_build_sbom_states_its_branch_or_none,
            the_build_sboms_are_found_and_purged,
            the_licence_policy_is_read_and_stored_with_the_application_s_instant,
            an_api_endpoint_reads_back_what_was_written_in_path_order,
            an_api_contract_reads_back_what_was_written_newest_first,
            the_api_inventory_is_deleted_by_scan_by_repository_and_whole,
        );
        the_entities_agree_with_the_schema(&db).await.unwrap_or_else(|failure| {
            failures.push(format!("the_entities_agree_with_the_schema: {failure}"));
        });
        db.close().await;
        assert!(failures.is_empty(), "{engine}: {} check(s) failed:\n  {}", failures.len(), failures.join("\n  "));
    });
}

/// Two repositories, an image, and four scans, fixed ids, for the foreign keys.
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
    server.sql_as_admin(&format!(
        "insert into t_container (id, image_name, tag){overriding} values ({IMAGE_A}, 'registry.example/i', 'v1')"
    ));
    for (id, repo, image) in
        [(SCAN_A1, "101", "null"), (SCAN_A2, "101", "null"), (SCAN_IMAGE, "null", "201"), (SCAN_BOTH, "102", "201")]
    {
        server.sql_as_admin(&format!(
            "insert into t_scan (id, branch, status, created_at, repo_id, container_id){overriding} \
             values ({id}, 'main', 'completed', '2026-01-01 00:00:00', {repo}, {image})"
        ));
    }
}

/// The inventory's tables as the migrations left them: no row, and the licence policy's seed.
fn empty(server: &Migrated) {
    for table in ["t_component", "t_build_sbom_component", "t_build_sbom", "t_api_endpoint", "t_api_contract"] {
        server.sql_as_admin(&format!("delete from {table}"));
    }
    server.sql_as_admin(
        "update t_license_policy set disallowed_categories = 'STRONG_COPYLEFT,FORBIDDEN', allowed_licenses = '', \
         disallowed_licenses = '' where id = 1",
    );
}

fn at(seconds: i64) -> OffsetDateTime {
    to_microseconds(
        OffsetDateTime::from_unix_timestamp(1_760_000_000 + seconds).unwrap() + Duration::microseconds(123_456),
    )
}

async fn write(db: &Db) -> Result<Tx, String> {
    db.begin(Mode::ReadWrite).await.map_err(|e| e.to_string())
}

async fn commit(tx: Tx) -> Check {
    tx.commit().await.map_err(|e| e.to_string())
}

fn component(scan_id: i64, name: &str) -> NewComponent {
    let (repo_id, container_id) = match scan_id {
        SCAN_IMAGE => (None, Some(IMAGE_A)),
        SCAN_BOTH => (Some(REPO_B), Some(IMAGE_A)),
        _ => (Some(REPO_A), None),
    };
    NewComponent {
        scan_id,
        repo_id,
        container_id,
        scan_created_at: Some(at(scan_id)),
        name: name.into(),
        version: Some("1.0.0".into()),
        purl: Some(format!("pkg:maven/org.example/{name}@1.0.0")),
        type_: Some("library".into()),
        is_direct: Some(true),
        origin: Some("scan".into()),
        build_sbom_id: None,
        scanned_version: None,
        scanned_purl: None,
        declared_license: Some("Apache-2.0".into()),
    }
}

fn as_row(id: i64, new: &NewComponent) -> ComponentRow {
    ComponentRow {
        id,
        scan_id: new.scan_id,
        repo_id: new.repo_id,
        container_id: new.container_id,
        scan_created_at: new.scan_created_at,
        name: new.name.clone(),
        version: new.version.clone(),
        purl: new.purl.clone(),
        type_: new.type_.clone(),
        is_direct: new.is_direct,
        origin: new.origin.clone(),
        build_sbom_id: new.build_sbom_id,
        scanned_version: new.scanned_version.clone(),
        scanned_purl: new.scanned_purl.clone(),
        declared_license: new.declared_license.clone(),
    }
}

async fn insert_components(db: &Db, rows: &[NewComponent]) -> Check {
    let mut tx = write(db).await?;
    Repo::insert_components(&mut tx, rows).await.map_err(|e| e.to_string())?;
    commit(tx).await
}

fn names(rows: &[ComponentRow]) -> Vec<String> {
    rows.iter().map(|row| row.name.clone()).collect()
}

/// Every column, the absent ones absent: a null `is_direct` is "not known", not "transitive".
async fn a_component_reads_back_what_was_written(db: &Db) -> Check {
    let full = component(SCAN_A1, "jackson");
    let sparse = NewComponent {
        version: None,
        purl: None,
        type_: None,
        is_direct: None,
        origin: None,
        scan_created_at: None,
        declared_license: None,
        build_sbom_id: Some(7),
        scanned_version: Some("0.9".into()),
        scanned_purl: Some("pkg:maven/x@0.9".into()),
        ..component(SCAN_A1, "sparse")
    };
    let transitive = NewComponent { is_direct: Some(false), ..component(SCAN_A1, "transitive") };
    insert_components(db, &[full.clone(), sparse.clone(), transitive.clone()]).await?;
    let read = Repo::find_components_by_scan_id(db, SCAN_A1).await.map_err(|e| e.to_string())?;
    let ids: Vec<i64> = read.iter().map(|row| row.id).collect();
    if ids.len() != 3 || !ids.is_sorted() {
        return Err(format!("three components in key order: {ids:?}"));
    }
    ensure_eq!(read, vec![as_row(ids[0], &full), as_row(ids[1], &sparse), as_row(ids[2], &transitive)], "every column");
    Ok(())
}

/// Java's `namesOfScans`: `order by c.scanId, c.id` — the first of two rows naming one component decides the purl the
/// licence inventory shows — and each scan read once, however often it is named.
async fn the_components_of_several_scans_are_read_once_in_scan_then_key_order(db: &Db) -> Check {
    insert_components(db, &[component(SCAN_A2, "b"), component(SCAN_A1, "a"), component(SCAN_A2, "c")]).await?;
    let read = Repo::find_components_by_scan_ids(db, &[SCAN_A2, SCAN_A1, SCAN_A2]).await.map_err(|e| e.to_string())?;
    ensure_eq!(names(&read), vec!["a", "b", "c"], "by scan, then by key, each once");
    let read = Repo::find_components_by_scan_ids(db, &[]).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 0, "no scan, no component");
    Ok(())
}

async fn the_components_of_a_scan_are_updated_counted_locked_and_deleted(db: &Db) -> Check {
    insert_components(
        db,
        &[component(SCAN_A1, "a"), component(SCAN_A1, "b"), component(SCAN_A2, "c"), component(SCAN_IMAGE, "d")],
    )
    .await?;
    let count = Repo::count_components_by_scan_ids(db, &[SCAN_A1, SCAN_IMAGE]).await.map_err(|e| e.to_string())?;
    ensure_eq!(count, 3, "the components of two scans");
    let mut indexed = Repo::indexed_among(db, &[SCAN_A1, SCAN_BOTH, SCAN_IMAGE]).await.map_err(|e| e.to_string())?;
    indexed.sort_unstable();
    ensure_eq!(indexed, vec![SCAN_A1, SCAN_IMAGE], "the scans holding components");

    let mut tx = write(db).await?;
    let locked = Repo::lock_scan_components(&mut tx, SCAN_A1).await.map_err(|e| e.to_string())?;
    ensure_eq!(names(&locked), vec!["a", "b"], "the scan's rows, locked, in key order");
    let mut changed = locked.clone();
    changed[1].version = Some("2.0.0".into());
    changed[1].origin = Some("both".into());
    changed[1].build_sbom_id = Some(9);
    changed[1].scanned_version = Some("1.0.0".into());
    Repo::update_components(&mut tx, &changed).await.map_err(|e| e.to_string())?;
    commit(tx).await?;
    let read = Repo::find_components_by_scan_id(db, SCAN_A1).await.map_err(|e| e.to_string())?;
    ensure_eq!(read, changed, "the update, read back");

    let mut tx = write(db).await?;
    let deleted = Repo::delete_components_by_ids(&mut tx, &[changed[0].id]).await.map_err(|e| e.to_string())?;
    ensure_eq!(deleted, 1, "one by key");
    let deleted = Repo::delete_components_by_scan_id(&mut tx, SCAN_A1).await.map_err(|e| e.to_string())?;
    ensure_eq!(deleted, 1, "the scan's other one");
    let deleted =
        Repo::delete_components_by_scan_ids(&mut tx, &[SCAN_A2, SCAN_IMAGE]).await.map_err(|e| e.to_string())?;
    ensure_eq!(deleted, 2, "two scans'");
    commit(tx).await
}

/// Java's `search`: `lower(name) like :name or lower(purl) like :name`, the version exact, `order by scanCreatedAt
/// desc, name asc`, bounded — so that the bound keeps the newest, not the last written.
async fn a_component_is_searched_by_name_or_purl_newest_scan_first(db: &Db) -> Check {
    let named = |scan_id, name: &str, purl: &str, version: &str| NewComponent {
        purl: Some(purl.into()),
        version: Some(version.into()),
        ..component(scan_id, name)
    };
    // Written in an order that is neither the answer nor its reverse; the tie inside one scan is between names that
    // sort alike under MySQL's collation and PostgreSQL's.
    insert_components(
        db,
        &[
            named(SCAN_A1, "Log4j-Core", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "2.14.1"),
            named(SCAN_A1, "zeta", "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1", "2.14.1"),
            named(SCAN_A2, "beta", "pkg:maven/org.apache.logging.log4j/log4j-api@2.14.10", "2.14.10"),
            named(SCAN_A2, "alpha", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "2.14.1"),
            named(SCAN_BOTH, "jackson", "pkg:maven/com.fasterxml/jackson@2.0", "2.0"),
        ],
    )
    .await?;
    let read = Repo::search_components(db, "%log4j%", None, 10).await.map_err(|e| e.to_string())?;
    ensure_eq!(
        names(&read),
        vec!["alpha", "beta", "Log4j-Core", "zeta"],
        "by name or purl, newest scan first, then by name"
    );
    let read = Repo::search_components(db, "%log4j%", Some("2.14.1"), 10).await.map_err(|e| e.to_string())?;
    ensure_eq!(names(&read), vec!["alpha", "Log4j-Core", "zeta"], "the version exactly: 2.14.10 is another release");
    let read = Repo::search_components(db, "%log4j%", None, 1).await.map_err(|e| e.to_string())?;
    ensure_eq!(names(&read), vec!["alpha"], "bounded, the newest kept");
    Ok(())
}

/// Java's `versionsOf`: by name or purl, `order by version desc`, bounded; a row without a version is no version.
async fn a_component_s_versions_are_newest_first_by_name_or_purl(db: &Db) -> Check {
    let versioned = |scan_id, version: Option<&str>| NewComponent {
        version: version.map(str::to_owned),
        purl: Some("pkg:maven/org.apache.logging.log4j/core".into()),
        ..component(scan_id, "core")
    };
    insert_components(
        db,
        &[
            versioned(SCAN_A1, Some("2.14.1")),
            versioned(SCAN_A2, Some("2.17.0")),
            versioned(SCAN_A2, Some("2.14.1")),
            versioned(SCAN_IMAGE, Some("2.16.0")),
            versioned(SCAN_IMAGE, None),
        ],
    )
    .await?;
    let read = Repo::versions_of(db, "%log4j%", 10).await.map_err(|e| e.to_string())?;
    let versions: Vec<String> = read.iter().map(|(version, _, _)| version.clone()).collect();
    ensure_eq!(versions, vec!["2.17.0", "2.16.0", "2.14.1"], "each version and target once, newest first, by purl");
    let read = Repo::versions_of(db, "%log4j%", 1).await.map_err(|e| e.to_string())?;
    ensure_eq!(read, vec![("2.17.0".to_owned(), Some(REPO_A), None)], "bounded, the newest kept, with its target");
    Ok(())
}

async fn the_distinct_figures_are_read_across_the_estate(db: &Db) -> Check {
    insert_components(
        db,
        &[
            NewComponent { purl: Some("pkg:b".into()), ..component(SCAN_A1, "x") },
            NewComponent { purl: Some("pkg:a".into()), ..component(SCAN_A2, "y") },
            NewComponent { purl: Some("pkg:a".into()), ..component(SCAN_IMAGE, "z") },
            NewComponent { purl: None, ..component(SCAN_BOTH, "w") },
        ],
    )
    .await?;
    let mut purls = Repo::distinct_purls(db).await.map_err(|e| e.to_string())?;
    purls.sort();
    ensure_eq!(purls, vec!["pkg:a", "pkg:b"], "every purl once");
    let mut by_target = Repo::distinct_purls_by_target(db).await.map_err(|e| e.to_string())?;
    by_target.sort();
    ensure_eq!(
        by_target,
        vec![
            (None, Some(IMAGE_A), "pkg:a".to_owned()),
            (Some(REPO_A), None, "pkg:a".to_owned()),
            (Some(REPO_A), None, "pkg:b".to_owned())
        ],
        "each purl once per target"
    );
    let mut repos = Repo::distinct_repositories_with_components(db).await.map_err(|e| e.to_string())?;
    repos.sort_unstable();
    ensure_eq!(repos, vec![REPO_A, REPO_B], "the repositories");
    // Java's `distinctContainersWithComponents` does not add `repo_id is null`: the row naming both counts the image.
    let images = Repo::distinct_containers_with_components(db).await.map_err(|e| e.to_string())?;
    ensure_eq!(images, vec![IMAGE_A], "the images");

    let completed =
        |build_sbom_id: i64, scan_id| NewComponent { build_sbom_id: Some(build_sbom_id), ..component(scan_id, "c") };
    insert_components(db, &[completed(5, SCAN_A1), completed(5, SCAN_A2), completed(6, SCAN_A1)]).await?;
    let mut newest = Repo::newest_scan_completed_by(db, &[5, 6, 7]).await.map_err(|e| e.to_string())?;
    newest.sort_unstable();
    ensure_eq!(newest, vec![(5, SCAN_A2), (6, SCAN_A1)], "the newest scan each import completed");
    Ok(())
}

fn build_sbom(branch: Option<&str>, seconds: i64) -> NewBuildSbom {
    NewBuildSbom {
        source_id: 3,
        source_slug: "ci-main".into(),
        repo_id: REPO_A,
        spec_version: "1.6".into(),
        tool: Some("cyclonedx-maven-plugin".into()),
        components_count: 2,
        commit_sha: Some("0123456789abcdef0123456789abcdef01234567".into()),
        branch_name: branch.map(str::to_owned),
        document_sha256: "f".repeat(64),
        imported_at: at(seconds),
        imported_by: "ci-bot".into(),
        api_key_id: "00000000-0000-4000-8000-000000000001".into(),
    }
}

fn as_build_sbom(id: i64, new: &NewBuildSbom) -> BuildSbomRow {
    BuildSbomRow {
        id,
        source_id: new.source_id,
        source_slug: new.source_slug.clone(),
        repo_id: new.repo_id,
        spec_version: new.spec_version.clone(),
        tool: new.tool.clone(),
        components_count: new.components_count,
        commit_sha: new.commit_sha.clone(),
        branch_name: new.branch_name.clone(),
        document_sha256: new.document_sha256.clone(),
        imported_at: new.imported_at,
        imported_by: new.imported_by.clone(),
        api_key_id: new.api_key_id.clone(),
    }
}

async fn insert_build_sbom(db: &Db, new: &NewBuildSbom) -> Result<i64, String> {
    let mut tx = write(db).await?;
    let id = Repo::insert_build_sbom(&mut tx, new).await.map_err(|e| e.to_string())?;
    commit(tx).await?;
    Ok(id)
}

async fn a_build_sbom_reads_back_what_was_written_newest_first(db: &Db) -> Check {
    let first = build_sbom(Some("main"), 1);
    let bare = NewBuildSbom { tool: None, commit_sha: None, ..build_sbom(None, 2) };
    let one = insert_build_sbom(db, &first).await?;
    let two = insert_build_sbom(db, &bare).await?;
    let read = Repo::find_build_sboms_by_repo(db, REPO_A, 10).await.map_err(|e| e.to_string())?;
    ensure_eq!(read, vec![as_build_sbom(two, &bare), as_build_sbom(one, &first)], "every column, newest first");
    let read = Repo::find_build_sboms_by_repo(db, REPO_A, 1).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 1, "bounded");

    let mut tx = write(db).await?;
    let listed = [
        NewBuildSbomComponent {
            import_id: one,
            name: "b".into(),
            version: Some("1".into()),
            purl: Some("pkg:b".into()),
            type_: Some("library".into()),
            license: Some("MIT".into()),
        },
        NewBuildSbomComponent {
            import_id: one,
            name: "a".into(),
            version: None,
            purl: None,
            type_: None,
            license: None,
        },
        NewBuildSbomComponent {
            import_id: two,
            name: "c".into(),
            version: None,
            purl: None,
            type_: None,
            license: None,
        },
    ];
    Repo::insert_build_sbom_components(&mut tx, &listed).await.map_err(|e| e.to_string())?;
    let read = Repo::find_build_sbom_components(&mut tx, one).await.map_err(|e| e.to_string())?;
    commit(tx).await?;
    let read: Vec<(String, Option<String>, Option<String>)> =
        read.into_iter().map(|row| (row.name, row.purl, row.license)).collect();
    ensure_eq!(
        read,
        vec![("b".to_owned(), Some("pkg:b".to_owned()), Some("MIT".to_owned())), ("a".to_owned(), None, None)],
        "the import's components, in document order"
    );
    Ok(())
}

/// Java's `newestFor`: `b.branch is null or b.branch = :branch` — for a scan with no branch, `b.branch = null` is
/// unknown, and only an import stating no branch may speak for it, never another branch's.
async fn a_scan_s_build_sbom_states_its_branch_or_none(db: &Db) -> Check {
    let unbranched = insert_build_sbom(db, &build_sbom(None, 1)).await?;
    let main = insert_build_sbom(db, &build_sbom(Some("main"), 2)).await?;
    let develop = insert_build_sbom(db, &build_sbom(Some("develop"), 3)).await?;
    let newest = |row: Option<BuildSbomRow>| row.map(|row| row.id);
    let mut tx = write(db).await?;
    let found =
        Repo::find_newest_build_sbom_for_repo(&mut tx, REPO_A, Some("main")).await.map_err(|e| e.to_string())?;
    ensure_eq!(newest(found), Some(main), "main's, the newer than the unbranched one");
    let found =
        Repo::find_newest_build_sbom_for_repo(&mut tx, REPO_A, Some("release")).await.map_err(|e| e.to_string())?;
    ensure_eq!(newest(found), Some(unbranched), "a branch with no import of its own: the unbranched one");
    let found = Repo::find_newest_build_sbom_for_repo(&mut tx, REPO_A, None).await.map_err(|e| e.to_string())?;
    ensure_eq!(newest(found), Some(unbranched), "a scan with no branch: the unbranched one, not develop's");
    let found =
        Repo::find_newest_build_sbom_for_repo(&mut tx, REPO_B, Some("main")).await.map_err(|e| e.to_string())?;
    ensure_eq!(newest(found), None, "another repository's");
    commit(tx).await?;
    let _ = develop;
    Ok(())
}

async fn the_build_sboms_are_found_and_purged(db: &Db) -> Check {
    let old = insert_build_sbom(db, &build_sbom(None, 1)).await?;
    let older = insert_build_sbom(db, &build_sbom(None, 0)).await?;
    let new = insert_build_sbom(db, &build_sbom(None, 5)).await?;
    let elsewhere = insert_build_sbom(db, &NewBuildSbom { repo_id: REPO_B, ..build_sbom(None, 0) }).await?;
    let mut tx = write(db).await?;
    let mut ids = Repo::find_build_sbom_ids_by_repo(&mut tx, REPO_A).await.map_err(|e| e.to_string())?;
    ids.sort_unstable();
    ensure_eq!(ids, vec![old, older, new], "a repository's imports");
    let mut before = Repo::find_build_sbom_ids_imported_before(&mut tx, at(5), 10).await.map_err(|e| e.to_string())?;
    before.sort_unstable();
    ensure_eq!(before, vec![old, older, elsewhere], "imported strictly before the cutoff");
    let bounded = Repo::find_build_sbom_ids_imported_before(&mut tx, at(5), 2).await.map_err(|e| e.to_string())?;
    ensure_eq!(bounded.len(), 2, "bounded");
    Repo::insert_build_sbom_components(
        &mut tx,
        &[NewBuildSbomComponent {
            import_id: old,
            name: "a".into(),
            version: None,
            purl: None,
            type_: None,
            license: None,
        }],
    )
    .await
    .map_err(|e| e.to_string())?;
    let gone =
        Repo::delete_build_sbom_components_by_import_ids(&mut tx, &[old, new]).await.map_err(|e| e.to_string())?;
    ensure_eq!(gone, 1, "the imports' components");
    let gone = Repo::delete_build_sboms_by_ids(&mut tx, &[old, older]).await.map_err(|e| e.to_string())?;
    ensure_eq!(gone, 2, "the imports");
    commit(tx).await?;
    let read = Repo::find_build_sboms_by_repo(db, REPO_A, 10).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.into_iter().map(|row| row.id).collect::<Vec<_>>(), vec![new], "what the purge kept");
    Ok(())
}

/// The one place the two versions differ: the port stamps the instant it is given, the hand-written statement stamped
/// the database's `now()` and took none.
async fn store_policy(
    tx: &mut Tx,
    categories: &str,
    allowed: Option<&str>,
    disallowed: Option<&str>,
    at: OffsetDateTime,
) -> Check {
    Repo::upsert_license_policy(tx, categories, allowed, disallowed, at).await.map_err(|e| e.to_string())
}

/// Java's `updatePolicy`: the singleton row, replaced, stamped with the application's clock (`clock.instant()`) — not
/// the database's, whose `now()` is the session's time zone on MySQL. MySQL keeps the column to the second.
async fn the_licence_policy_is_read_and_stored_with_the_application_s_instant(db: &Db) -> Check {
    let seeded = Repo::find_license_policy(db).await.map_err(|e| e.to_string())?;
    ensure_eq!(
        seeded.as_ref().map(|row| (row.id, row.disallowed_categories.clone())),
        Some((1, "STRONG_COPYLEFT,FORBIDDEN".to_owned())),
        "the migrations' seed"
    );
    let stamped = OffsetDateTime::from_unix_timestamp(1_760_000_123).unwrap();
    let mut tx = write(db).await?;
    store_policy(&mut tx, "FORBIDDEN", Some("MIT,Apache-2.0"), None, stamped).await?;
    commit(tx).await?;
    let read = Repo::find_license_policy(db).await.map_err(|e| e.to_string())?.ok_or("no policy")?;
    ensure_eq!(
        (read.id, read.disallowed_categories, read.allowed_licenses, read.disallowed_licenses, read.updated_at),
        (1, "FORBIDDEN".to_owned(), Some("MIT,Apache-2.0".to_owned()), None, stamped),
        "the stored policy, stamped with the instant given"
    );
    Ok(())
}

fn endpoint(scan_id: i64, repo: Option<i64>, method: &str, path: &str) -> NewApiEndpoint {
    NewApiEndpoint {
        scan_id,
        repository_id: repo,
        http_method: method.into(),
        path: path.into(),
        auth_required: true,
        auth_type: Some("bearer".into()),
        visibility: "PUBLIC".into(),
        file_path: Some("src/main/java/Api.java".into()),
        line_number: Some(42),
        framework: Some("spring".into()),
        operation_id: Some(format!("{method}{path}")),
        summary: Some("An operation".into()),
        tags: Some("api".into()),
        created_at: at(1),
    }
}

fn as_endpoint(id: i64, new: &NewApiEndpoint) -> ApiEndpointRow {
    ApiEndpointRow {
        id,
        scan_id: new.scan_id,
        repository_id: new.repository_id,
        http_method: new.http_method.clone(),
        path: new.path.clone(),
        auth_required: new.auth_required,
        auth_type: new.auth_type.clone(),
        visibility: new.visibility.clone(),
        file_path: new.file_path.clone(),
        line_number: new.line_number,
        framework: new.framework.clone(),
        operation_id: new.operation_id.clone(),
        summary: new.summary.clone(),
        tags: new.tags.clone(),
        created_at: new.created_at,
    }
}

/// Java's `findByRepositoryIdOrderByPathAsc`; `auth_required` read both ways — a flag read as `false` whatever it
/// holds says the route is open.
async fn an_api_endpoint_reads_back_what_was_written_in_path_order(db: &Db) -> Check {
    let users = endpoint(SCAN_A1, Some(REPO_A), "GET", "/users");
    let open = NewApiEndpoint {
        auth_required: false,
        auth_type: None,
        file_path: None,
        line_number: None,
        framework: Some("express".into()),
        operation_id: None,
        summary: None,
        tags: None,
        ..endpoint(SCAN_A1, Some(REPO_A), "POST", "/admin")
    };
    let other = endpoint(SCAN_BOTH, Some(REPO_B), "GET", "/health");
    let mut tx = write(db).await?;
    Repo::insert_api_endpoints(&mut tx, &[users.clone(), open.clone(), other.clone()])
        .await
        .map_err(|e| e.to_string())?;
    commit(tx).await?;
    let all = Repo::find_all_api_endpoints(db).await.map_err(|e| e.to_string())?;
    let ids: Vec<i64> = all.iter().map(|row| row.id).collect();
    if ids.len() != 3 || !ids.is_sorted() {
        return Err(format!("three endpoints in key order: {ids:?}"));
    }
    ensure_eq!(
        all,
        vec![as_endpoint(ids[0], &users), as_endpoint(ids[1], &open), as_endpoint(ids[2], &other)],
        "every column"
    );
    let read = Repo::find_api_endpoints_by_repo(db, REPO_A).await.map_err(|e| e.to_string())?;
    let paths: Vec<String> = read.iter().map(|row| row.path.clone()).collect();
    ensure_eq!(paths, vec!["/admin", "/users"], "a repository's, by path");
    let read = Repo::find_api_endpoints_by_repos(db, &[REPO_B, REPO_A, REPO_B]).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 3, "several repositories', each once");
    let mut frameworks = Repo::find_distinct_frameworks(db).await.map_err(|e| e.to_string())?;
    frameworks.sort();
    ensure_eq!(frameworks, vec!["express", "spring"], "every framework once");
    Ok(())
}

/// A contract's path, scan, format, endpoint count and instant.
type ContractSummary = (String, Option<i64>, Option<String>, i32, OffsetDateTime);

/// Java's `findByRepositoryIdOrderByCreatedAtDesc`: a repository's contracts, newest first.
async fn an_api_contract_reads_back_what_was_written_newest_first(db: &Db) -> Check {
    let contract = |repo, scan: Option<i64>, path: &str, seconds| NewApiContract {
        repository_id: repo,
        scan_id: scan,
        contract_path: path.into(),
        format: Some("openapi-3".into()),
        title: Some("The API".into()),
        version: Some("1.0".into()),
        endpoints_count: 12,
        created_at: at(seconds),
    };
    let old = contract(REPO_A, Some(SCAN_A1), "openapi.yaml", 1);
    let new = NewApiContract { format: None, title: None, version: None, ..contract(REPO_A, None, "api/v2.yaml", 5) };
    let other = contract(REPO_B, Some(SCAN_BOTH), "spec.json", 3);
    let mut tx = write(db).await?;
    Repo::insert_api_contracts(&mut tx, &[old.clone(), new.clone(), other.clone()]).await.map_err(|e| e.to_string())?;
    commit(tx).await?;
    let read = Repo::find_api_contracts_by_repo(db, REPO_A).await.map_err(|e| e.to_string())?;
    let read: Vec<ContractSummary> = read
        .into_iter()
        .map(|row: ApiContractRow| (row.contract_path, row.scan_id, row.format, row.endpoints_count, row.created_at))
        .collect();
    ensure_eq!(
        read,
        vec![
            ("api/v2.yaml".to_owned(), None, None, 12, at(5)),
            ("openapi.yaml".to_owned(), Some(SCAN_A1), Some("openapi-3".to_owned()), 12, at(1)),
        ],
        "a repository's, newest first, every column"
    );
    let read = Repo::find_api_contracts_by_repos(db, &[REPO_A, REPO_A]).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 2, "each repository once");
    let read = Repo::find_all_api_contracts(db).await.map_err(|e| e.to_string())?;
    ensure_eq!(read.len(), 3, "every contract");
    Ok(())
}

async fn the_api_inventory_is_deleted_by_scan_by_repository_and_whole(db: &Db) -> Check {
    let contract = |repo, scan: Option<i64>| NewApiContract {
        repository_id: repo,
        scan_id: scan,
        contract_path: "openapi.yaml".into(),
        format: None,
        title: None,
        version: None,
        endpoints_count: 0,
        created_at: at(1),
    };
    let mut tx = write(db).await?;
    Repo::insert_api_endpoints(
        &mut tx,
        &[
            endpoint(SCAN_A1, Some(REPO_A), "GET", "/a"),
            endpoint(SCAN_A2, Some(REPO_A), "GET", "/b"),
            endpoint(SCAN_BOTH, Some(REPO_B), "GET", "/c"),
            endpoint(SCAN_IMAGE, None, "GET", "/d"),
        ],
    )
    .await
    .map_err(|e| e.to_string())?;
    Repo::insert_api_contracts(
        &mut tx,
        &[contract(REPO_A, Some(SCAN_A1)), contract(REPO_A, None), contract(REPO_B, Some(SCAN_BOTH))],
    )
    .await
    .map_err(|e| e.to_string())?;
    ensure_eq!(
        Repo::delete_api_endpoints_by_scan_id(&mut tx, SCAN_A1).await.map_err(|e| e.to_string())?,
        1,
        "a scan's endpoints"
    );
    ensure_eq!(
        Repo::delete_api_contracts_by_scan_id(&mut tx, SCAN_A1).await.map_err(|e| e.to_string())?,
        1,
        "a scan's contracts"
    );
    ensure_eq!(
        Repo::delete_api_endpoints_by_repo_tx(&mut tx, REPO_A).await.map_err(|e| e.to_string())?,
        1,
        "a repository's endpoints"
    );
    ensure_eq!(
        Repo::delete_api_contracts_by_repo_tx(&mut tx, REPO_A).await.map_err(|e| e.to_string())?,
        1,
        "a repository's contracts"
    );
    commit(tx).await?;
    ensure_eq!(
        Repo::delete_api_endpoints_by_repo(db, REPO_B).await.map_err(|e| e.to_string())?,
        1,
        "committed by itself"
    );
    ensure_eq!(
        Repo::delete_api_contracts_by_repo(db, REPO_B).await.map_err(|e| e.to_string())?,
        1,
        "committed by itself"
    );
    let mut tx = write(db).await?;
    ensure_eq!(
        Repo::delete_all_api_endpoints(&mut tx).await.map_err(|e| e.to_string())?,
        1,
        "what is left of the endpoints"
    );
    ensure_eq!(Repo::delete_all_api_contracts(&mut tx).await.map_err(|e| e.to_string())?, 0, "of the contracts");
    commit(tx).await
}

/// The six entities against the migrated schema, and a renamed column refused, so that a check that compared nothing
/// cannot pass.
async fn the_entities_agree_with_the_schema(db: &Db) -> Check {
    let tables = crate::persistence::entities::tables()?;
    parity::check_entities(db, &tables).await.map_err(|error| error.to_string())?;
    let mut renamed = tables.clone();
    let column = renamed[4].columns.iter_mut().find(|column| column.name == "auth_required").unwrap();
    column.name = "authenticated";
    match parity::check_entities(db, &renamed).await {
        Err(parity::ParityError::Mismatches { mismatches, .. }) => ensure_eq!(
            mismatches,
            vec![parity::Mismatch::MissingColumn { table: "t_api_endpoint", column: "authenticated" }],
            "a renamed column"
        ),
        other => return Err(format!("a renamed column: {other:?}")),
    }
    Ok(())
}
