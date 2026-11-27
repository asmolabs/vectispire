//! **The matcher against its real database**, through the agent's own path: `VulnerabilityDatabase`
//! downloading the publisher's database (some 3 GB unpacked) under the `fcntl` lock, `db update` into a
//! staging directory, `db status` reading it back, the rename into `generations/` and the pointer; then
//! the dependency step of a real tree and of a real image, matched read-only and offline against it.
//!
//! Every other suite runs a fake matcher, because a suite that downloads 3 GB at each run is a suite
//! nobody runs. These are **ignored, not skipped**: a run that leaves them out says so. The nightly's
//! `real-matcher` job runs them (with the network), then the Java side's `RealMatcherIntegrationTest` on
//! the same database snapshot, which reads what these wrote and refuses any difference in the findings
//! or in the fingerprints the control plane would give them.
//!
//! - `VECTISPIRE_REAL_GRYPE_CACHE`: the cache directory, kept between runs (a second run downloads
//!   nothing until the matcher says the database is stale).
//! - `VECTISPIRE_REAL_MATCHER_OUT`: where the findings are written, one file per target,
//!   `rust-<target>.json`, each finding in the agent's wire form.
//!
//! Needs Docker and the network, and fails without them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use vectispire_container::{ContainerRun, ContainerRunner, Mount, ScannerLimits};
use vectispire_scanners::dependencies::{self, DependenciesStep, DependencyFinding};
use vectispire_scanners::images;
use vectispire_scanners::vulnerability_database::{GENERATIONS, POINTER, VulnerabilityDatabase};
use vectispire_testkit::docker::docker;
use vectispire_testkit::proxy::SocketProxy;

/// alpine 3.12.0 — the reference set's image (`capture.sh`) — by its linux/amd64 manifest rather than the
/// multi-architecture index. **Both agents' export saves without a platform**, and on a daemon with the
/// containerd image store the save of an index then wants the *host's* variant: on an arm64 host it fails
/// (`content digest … not found`) when only the amd64 one was pulled, and exports the arm64 one when it is
/// there. A defect of both sides, reported (`README.md`, "Known differences"); a single-platform reference
/// is what lets the two be compared on any host meanwhile.
const ALPINE: &str = "alpine@sha256:a15790640a6690aa1730c38cf0a440e2aa44aaca9b0e8931a9f2b0d7cc90fd65";

fn variable(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name} names a directory")))
}

fn runner(proxy: &SocketProxy) -> Arc<ContainerRunner> {
    Arc::new(ContainerRunner::connect(Some(&proxy.address), ScannerLimits::default_for_this_host()).unwrap())
}

/// The polyglot fixture under its real names, at `<workspace>/source`, as a clone would leave it.
fn polyglot_workspace() -> tempfile::TempDir {
    let workspace = tempfile::Builder::new().prefix("vs-rs-real-matcher-").tempdir().unwrap();
    let fixture = vectispire_testkit::reference_root().join("dependencies/fixtures/polyglot");
    copy_fixture(&fixture, &workspace.path().join("source"));
    workspace
}

fn copy_fixture(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().unwrap().is_dir() {
            copy_fixture(&entry.path(), &to.join(&name));
        } else if let Some(real) = name.strip_suffix(".fixture") {
            std::fs::copy(entry.path(), to.join(real)).unwrap();
        }
    }
}

fn write_findings(out: &Path, target: &str, findings: &[DependencyFinding]) {
    std::fs::create_dir_all(out).unwrap();
    // `Findings::of`'s form: each finding as `serde_json` writes the type, in the matcher's order.
    let documents: Vec<Value> = findings.iter().map(|finding| serde_json::to_value(finding).unwrap()).collect();
    std::fs::write(out.join(format!("rust-{target}.json")), serde_json::to_string_pretty(&documents).unwrap()).unwrap();
}

fn step(outcome: (Result<DependenciesStep, dependencies::StepError>, Option<Value>), target: &str) -> DependenciesStep {
    match outcome.0 {
        Ok(step) => step,
        Err(failed) => panic!("the dependency step of {target} did not complete: {failed}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "downloads the real Grype database (3 GB): VECTISPIRE_REAL_GRYPE_CACHE, VECTISPIRE_REAL_MATCHER_OUT"]
async fn real_database_through_the_agent_s_path_then_a_tree_and_an_image_matched_against_it() {
    let cache = variable("VECTISPIRE_REAL_GRYPE_CACHE");
    let out = variable("VECTISPIRE_REAL_MATCHER_OUT");
    let proxy = SocketProxy::start();
    let runner = runner(&proxy);
    let database =
        VulnerabilityDatabase::with_defaults(Arc::clone(&runner), images::GRYPE, &cache, Duration::from_secs(900));

    let started = Instant::now();
    let generation = database.mountable().await.expect("the real database, downloaded and published");
    eprintln!("real-matcher: database ready in {:?}: {}", started.elapsed(), generation.display());
    assert_eq!(generation.parent().unwrap(), cache.join(GENERATIONS));
    assert_eq!(
        std::fs::read_to_string(cache.join(POINTER)).unwrap(),
        generation.file_name().unwrap().to_string_lossy()
    );
    // Nothing half done left beside it.
    let leftovers: Vec<String> = std::fs::read_dir(&cache)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("staging-") || name.starts_with("current."))
        .collect();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");

    let workspace = polyglot_workspace();
    let started = Instant::now();
    let tree = step(
        dependencies::tree_step(runner.as_ref(), &database, images::SYFT, images::GRYPE, workspace.path(), None).await,
        "the polyglot tree",
    );
    eprintln!("real-matcher: polyglot tree matched in {:?}: {} findings", started.elapsed(), tree.dependencies.len());
    write_findings(&out, "polyglot", &tree.dependencies);
    std::fs::write(out.join("rust-polyglot.sbom.json"), tree.sbom.to_string()).unwrap();

    let image_workspace = tempfile::Builder::new().prefix("vs-rs-real-matcher-image-").tempdir().unwrap();
    let started = Instant::now();
    let image = step(
        dependencies::image_step(
            runner.as_ref(),
            &database,
            images::SYFT,
            images::GRYPE,
            image_workspace.path(),
            ALPINE,
            dependencies::DEFAULT_PLATFORM,
        )
        .await,
        "the Alpine image",
    );
    eprintln!("real-matcher: Alpine image matched in {:?}: {} findings", started.elapsed(), image.dependencies.len());
    write_findings(&out, "alpine", &image.dependencies);
    std::fs::write(out.join("rust-alpine.sbom.json"), image.sbom.to_string()).unwrap();

    // A real database finds what the fixtures were chosen for: known-vulnerable versions in every
    // ecosystem of the tree, and the old Alpine's packages. Zero would be a matcher reading nothing.
    assert!(tree.dependencies.len() >= 10, "{} findings in the polyglot tree", tree.dependencies.len());
    assert!(image.dependencies.len() >= 5, "{} findings in the Alpine image", image.dependencies.len());
}

// ------------------------------------------------------------------------------------ the update path

/// The database at `root`, as the agent holds it.
fn database_at(runner: &Arc<ContainerRunner>, root: &Path) -> VulnerabilityDatabase<ContainerRunner> {
    VulnerabilityDatabase::with_defaults(Arc::clone(runner), images::GRYPE, root, Duration::from_secs(900))
}

/// A scenario's own cache, beside the shared one — on its file system, so a generation can be hard-linked into it
/// rather than copied.
fn scenario_cache(name: &str) -> PathBuf {
    let shared = variable("VECTISPIRE_REAL_GRYPE_CACHE");
    let cache = PathBuf::from(format!("{}-{name}", shared.display()));
    let _ = std::fs::remove_dir_all(&cache);
    std::fs::create_dir_all(&cache).unwrap();
    cache
}

/// Points `cache` at the generation `name`, checked at `checked`, the way the agent lays it out.
fn publish(cache: &Path, name: &str, checked: &str) -> PathBuf {
    std::fs::write(cache.join(POINTER), name).unwrap();
    std::fs::write(cache.join("checked"), checked).unwrap();
    cache.join(GENERATIONS).join(name)
}

/// The fresh generation's files in `to`: the database hard-linked, its small files copied.
fn link_generation(from: &Path, to: &Path) {
    std::fs::create_dir_all(to.join("6")).unwrap();
    for entry in std::fs::read_dir(from.join("6")).unwrap() {
        let entry = entry.unwrap();
        let target = to.join("6").join(entry.file_name());
        if entry.file_name() == "vulnerability.db" {
            std::fs::hard_link(entry.path(), target).unwrap();
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn leftovers(cache: &Path) -> Vec<String> {
    std::fs::read_dir(cache)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("staging-") || name.starts_with("current."))
        .collect()
}

fn size_of(directory: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(directory) else { return 0 };
    entries
        .flatten()
        .map(|entry| match entry.metadata() {
            Ok(metadata) if metadata.is_dir() => size_of(&entry.path()),
            Ok(metadata) => metadata.len(),
            Err(_) => 0,
        })
        .sum()
}

/// Kills the matcher's `db update` writing into `cache` once its staging directory holds `bytes` — a download
/// interrupted half-way, as a network cut, a drained node or an OOM kill would. Returns whether it killed one.
fn interrupt_the_download(cache: PathBuf, bytes: u64) -> std::thread::JoinHandle<bool> {
    std::thread::spawn(move || {
        let name = cache.file_name().unwrap().to_string_lossy().into_owned();
        let deadline = Instant::now() + Duration::from_secs(900);
        while Instant::now() < deadline {
            let staged = std::fs::read_dir(&cache)
                .into_iter()
                .flatten()
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("staging-"))
                .map(|entry| size_of(&entry.path()))
                .max()
                .unwrap_or(0);
            if staged >= bytes {
                let running = docker(&["ps", "-q", "--filter", &format!("ancestor={}", images::GRYPE)]);
                for id in running.lines() {
                    let described = docker(&[
                        "inspect",
                        "--format",
                        "{{json .Config.Cmd}} {{range .Mounts}}{{.Source}} {{end}}",
                        id,
                    ]);
                    if described.contains("\"update\"") && described.contains(&name) {
                        docker(&["kill", id]);
                        return true;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    })
}

/// A copy of the fresh generation the matcher reads as **built four days earlier**, so that `db check` says an
/// update is available: its build time rewritten (`python3`'s `sqlite3`), then imported by the pinned matcher itself,
/// which writes the `import.json` and the checksum a generation carries.
async fn aged_generation(runner: &ContainerRunner, fresh: &Path, to: &Path) {
    let beside = to.parent().unwrap().parent().unwrap();
    let edited = tempfile::Builder::new().prefix("vs-rs-aged-").tempdir_in(beside).unwrap();
    let database = edited.path().join("vulnerability.db");
    std::fs::copy(fresh.join("6/vulnerability.db"), &database).unwrap();
    let aged = std::process::Command::new("python3")
        .arg("-I")
        .arg("-c")
        .arg(
            "import sqlite3,sys\nc=sqlite3.connect(sys.argv[1])\n\
             c.execute(\"update db_metadata set build_timestamp=datetime(build_timestamp,'-4 days')\")\nc.commit()\nc.close()",
        )
        .arg(&database)
        .status()
        .unwrap();
    assert!(aged.success());
    std::fs::create_dir_all(to).unwrap();
    let import = ContainerRun::new(
        images::GRYPE,
        vec!["db".into(), "import".into(), "/in/vulnerability.db".into()],
        vec![
            Mount::read_only(edited.path().display().to_string(), "/in"),
            Mount::writable(to.display().to_string(), dependencies::DATABASE_CACHE),
        ],
        "grype (aged database import)",
    )
    .running_as_owner_of(to)
    .with_entrypoint(images::GRYPE_ENTRYPOINT);
    let imported = runner.run(&import).await.unwrap();
    assert_eq!(imported.exit_code, 0, "{}", imported.stderr);
}

/// **An interrupted download on an empty cache is absent**, never a database: the matcher killed half-way, the step
/// fails with its reason, and nothing half-written is left for the next scan to mount.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "downloads the real Grype database (3 GB): VECTISPIRE_REAL_GRYPE_CACHE"]
async fn an_interrupted_download_on_an_empty_cache_is_absent_and_leaves_nothing() {
    let proxy = SocketProxy::start();
    let runner = runner(&proxy);
    let cache = scenario_cache("interrupted");
    let killer = interrupt_the_download(cache.clone(), 64 * 1024 * 1024);

    let database = database_at(&runner, &cache);
    let outcome = dependencies::match_standalone_sbom(runner.as_ref(), &database, images::GRYPE, "{}").await;

    assert!(killer.join().unwrap(), "the download was interrupted half-way");
    match outcome {
        Err(failed) => eprintln!("real-matcher: interrupted, absent: {failed}"),
        Ok(answer) => panic!("an interrupted download answered {answer:?}"),
    }
    assert!(!cache.join(POINTER).exists());
    assert_eq!(size_of(&cache.join(GENERATIONS)), 0);
    assert!(leftovers(&cache).is_empty(), "left behind: {:?}", leftovers(&cache));
    std::fs::remove_dir_all(&cache).unwrap();
}

/// **A stale database whose update fails is kept, and one whose update completes is replaced whole**: the matcher
/// says the generation is four days old (`db check`, exit 100); the first update is killed half-way and the scan still
/// mounts and matches the old generation; the next, once the check is due again, publishes a new generation beside
/// the old one, which outlives it for the scans that resolved it before the switch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "downloads the real Grype database (3 GB) twice: VECTISPIRE_REAL_GRYPE_CACHE"]
async fn a_stale_database_is_kept_through_a_failed_update_and_replaced_whole_by_a_completed_one() {
    let proxy = SocketProxy::start();
    let runner = runner(&proxy);
    let fresh = database_at(&runner, &variable("VECTISPIRE_REAL_GRYPE_CACHE")).mountable().await.unwrap();
    let cache = scenario_cache("stale");
    let old = publish(&cache, "1790000000000-0000aaaa", "2026-01-01T00:00:00Z");
    aged_generation(runner.as_ref(), &fresh, &old).await;
    let database = database_at(&runner, &cache);

    let killer = interrupt_the_download(cache.clone(), 64 * 1024 * 1024);
    let mounted = database.mountable().await.expect("the old generation, kept");
    assert!(killer.join().unwrap(), "the update was interrupted half-way");
    assert_eq!(mounted, old);
    assert!(leftovers(&cache).is_empty(), "left behind: {:?}", leftovers(&cache));
    assert_eq!(std::fs::read_dir(cache.join(GENERATIONS)).unwrap().count(), 1);
    let sbom = vectispire_testkit::read_json("dependencies/sboms/01-polyglot.json").to_string();
    let findings = dependencies::match_standalone_sbom(runner.as_ref(), &database, images::GRYPE, &sbom)
        .await
        .unwrap()
        .expect("a match against the kept generation");
    assert!(!findings.is_empty());

    std::fs::write(cache.join("checked"), "2026-01-01T00:00:00Z").unwrap();
    let replaced = database.mountable().await.expect("a new generation");
    assert_ne!(replaced, old);
    assert_eq!(std::fs::read_to_string(cache.join(POINTER)).unwrap(), replaced.file_name().unwrap().to_string_lossy());
    assert!(old.join("6/vulnerability.db").exists(), "the replaced generation outlives its successor");
    assert!(leftovers(&cache).is_empty(), "left behind: {:?}", leftovers(&cache));
    std::fs::remove_dir_all(&cache).unwrap();
}

/// **A corrupted generation is absent, never empty**: a database whose checksum no longer matches, and one cut short,
/// each published and mounted, fail the step with the matcher's reason rather than answering "no vulnerability".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the real Grype database (3 GB): VECTISPIRE_REAL_GRYPE_CACHE"]
async fn a_corrupted_generation_fails_the_step_rather_than_answering_empty() {
    let proxy = SocketProxy::start();
    let runner = runner(&proxy);
    let fresh = database_at(&runner, &variable("VECTISPIRE_REAL_GRYPE_CACHE")).mountable().await.unwrap();
    let sbom = vectispire_testkit::read_json("dependencies/sboms/01-polyglot.json").to_string();
    let checked = vectispire_scanners::vulnerability_database::instant_text(std::time::SystemTime::now());
    let cache = scenario_cache("corrupted");

    let tampered = publish(&cache, "1790000000000-0000bbbb", &checked);
    tampered_generation(&fresh, &tampered);
    let database = database_at(&runner, &cache);
    let outcome = dependencies::match_standalone_sbom(runner.as_ref(), &database, images::GRYPE, &sbom).await;
    let failed = outcome.expect_err("a database whose checksum does not match is not read");
    assert!(failed.to_string().contains("checksum"), "{failed}");

    let truncated = publish(&cache, "1790000000000-0000cccc", &checked);
    truncated_generation(&fresh, &truncated);
    let outcome = dependencies::match_standalone_sbom(runner.as_ref(), &database, images::GRYPE, &sbom).await;
    let failed = outcome.expect_err("a database cut short is not read");
    eprintln!("real-matcher: a truncated generation is absent: {failed}");
    std::fs::remove_dir_all(&cache).unwrap();
}

/// A copy of the fresh generation at `to` whose recorded checksum no longer matches: the database hard-linked, its
/// `import.json` rewritten.
fn tampered_generation(fresh: &Path, to: &Path) {
    link_generation(fresh, to);
    let import = std::fs::read_to_string(to.join("6/import.json")).unwrap();
    let digest = import.split("xxh64:").nth(1).unwrap().get(..16).unwrap().to_owned();
    std::fs::write(to.join("6/import.json"), import.replace(&digest, "0000000000000000")).unwrap();
}

/// A copy of the fresh generation at `to` cut short at 64 MiB.
fn truncated_generation(fresh: &Path, to: &Path) {
    std::fs::create_dir_all(to.join("6")).unwrap();
    std::fs::copy(fresh.join("6/import.json"), to.join("6/import.json")).unwrap();
    let mut whole = std::fs::File::open(fresh.join("6/vulnerability.db")).unwrap();
    let mut cut = std::fs::File::create(to.join("6/vulnerability.db")).unwrap();
    std::io::copy(&mut std::io::Read::take(&mut whole, 64 * 1024 * 1024), &mut cut).unwrap();
}

/// **A corrupted published copy is replaced once its check is due**, never kept. The matcher's `db check` asks the
/// publisher and does not read the copy: a checksum that no longer matches is "current" to it, which kept the copy
/// until the publisher's next database, and a copy cut short is "update available", which kept it through every
/// failed download — each failing every dependency step meanwhile. The copy is read back first now: refused, a
/// download replaces it; and while the download fails the step is absent — not the refused copy, not marked
/// checked, so the next scan tries again and publishes the replacement.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "downloads the real Grype database (3 GB) twice: VECTISPIRE_REAL_GRYPE_CACHE"]
async fn a_corrupted_published_copy_is_replaced_by_a_download_once_its_check_is_due() {
    let proxy = SocketProxy::start();
    let runner = runner(&proxy);
    let fresh = database_at(&runner, &variable("VECTISPIRE_REAL_GRYPE_CACHE")).mountable().await.unwrap();
    let sbom = vectispire_testkit::read_json("dependencies/sboms/01-polyglot.json").to_string();

    // A checksum that no longer matches: "current" to the check, refused by the read-back, replaced.
    let cache = scenario_cache("replaced");
    let tampered = publish(&cache, "1790000000000-0000eeee", "2026-01-01T00:00:00Z");
    tampered_generation(&fresh, &tampered);
    let database = database_at(&runner, &cache);
    let started = Instant::now();
    let replaced = database.mountable().await.expect("a download in its place");
    eprintln!("real-matcher: a copy whose checksum no longer matches, replaced in {:?}", started.elapsed());
    assert_ne!(replaced, tampered);
    assert_eq!(std::fs::read_to_string(cache.join(POINTER)).unwrap(), replaced.file_name().unwrap().to_string_lossy());
    assert!(tampered.exists(), "retired like any replaced generation, not deleted under a scan");
    assert!(leftovers(&cache).is_empty(), "left behind: {:?}", leftovers(&cache));
    let findings = dependencies::match_standalone_sbom(runner.as_ref(), &database, images::GRYPE, &sbom)
        .await
        .unwrap()
        .expect("a match against the replacement");
    assert!(!findings.is_empty());
    std::fs::remove_dir_all(&cache).unwrap();

    // Cut short, and the download that would replace it interrupted: absent, the copy neither mounted nor
    // deleted; the next scan downloads again and publishes the replacement.
    let cache = scenario_cache("truncated-replaced");
    let truncated = publish(&cache, "1790000000000-0000ffff", "2026-01-01T00:00:00Z");
    truncated_generation(&fresh, &truncated);
    let database = database_at(&runner, &cache);
    let killer = interrupt_the_download(cache.clone(), 64 * 1024 * 1024);
    let outcome = dependencies::match_standalone_sbom(runner.as_ref(), &database, images::GRYPE, &sbom).await;
    assert!(killer.join().unwrap(), "the download was interrupted half-way");
    match outcome {
        Err(failed) => eprintln!("real-matcher: a copy cut short and no download, absent: {failed}"),
        Ok(answer) => panic!("a refused copy without a replacement answered {answer:?}"),
    }
    assert_eq!(std::fs::read_to_string(cache.join(POINTER)).unwrap(), truncated.file_name().unwrap().to_string_lossy());
    assert!(truncated.join("6/vulnerability.db").exists());
    assert!(leftovers(&cache).is_empty(), "left behind: {:?}", leftovers(&cache));
    let replaced = database.mountable().await.expect("the next scan's download in its place");
    assert_ne!(replaced, truncated);
    assert_eq!(std::fs::read_to_string(cache.join(POINTER)).unwrap(), replaced.file_name().unwrap().to_string_lossy());
    std::fs::remove_dir_all(&cache).unwrap();
}
