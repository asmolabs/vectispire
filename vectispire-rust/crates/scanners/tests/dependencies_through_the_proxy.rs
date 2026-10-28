//! The dependency step through a real daemon, behind the socket proxy as the composition configures it
//! — `VulnerabilityDatabaseIntegrationTest`, and the pinned cataloguer on the reference fixture.
//!
//! **A fake matcher, built here, and why** (as on the Java side): the real one downloads some 3 GB, and a
//! suite that did that at every run would be the reason nobody runs it. What has to be proven against
//! the daemon is the shape the matcher runs in — the database mounted read-only, no network, automatic
//! updates off, every file written into the cache this process's to delete. The fake is a shell script
//! on busybox that behaves as `grype db update`, `db status`, `db check` and a match do on their mounts,
//! and reports, as the one "finding" of a match, what it saw of its own container. Its image, like the
//! real one, has a `/tmp` only root may write, and it creates a file there before a download or a
//! check, as the real one does. The real matcher in that shape produced `reference/dependencies/
//! matches/0[1-3]` (`capture.sh`).
//!
//! Needs Docker, and fails without it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use vectispire_container::{ContainerRunner, ScannerLimits};
use vectispire_scanners::dependencies;
use vectispire_scanners::images;
use vectispire_scanners::vulnerability_database::VulnerabilityDatabase;
use vectispire_testkit::docker::docker;
use vectispire_testkit::proxy::SocketProxy;

const FAKE_GRYPE: &str = "vs-rs-fake-grype:1";
const BUSYBOX: &str = "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e";

const SCRIPT: &str = r#"#!/bin/sh
case "$1 $2" in
  "db update"|"db check")
    mktemp "$TMPDIR/grype-db-listing.XXXXXX" >/dev/null 2>&1 \
      || { echo "unable to create listing temp file: permission denied" >&2; exit 1; } ;;
esac
case "$1 $2" in
  "db update")
    sleep 1
    mkdir -p "$GRYPE_DB_CACHE_DIR/6" \
      && echo "fake database" > "$GRYPE_DB_CACHE_DIR/6/vulnerability.db" \
      && echo '{}' > "$GRYPE_DB_CACHE_DIR/6/import.json"
    exit $? ;;
  "db status")
    if [ -s "$GRYPE_DB_CACHE_DIR/6/vulnerability.db" ]; then echo '{"valid": true}'; exit 0; fi
    echo '{"valid": false}'; exit 1 ;;
  "db check")
    echo '{"updateAvailable": false}'; exit 0 ;;
esac
[ -s "$GRYPE_DB_CACHE_DIR/6/vulnerability.db" ] || { echo "database does not exist" >&2; exit 1; }
if touch "$GRYPE_DB_CACHE_DIR/probe" 2>/dev/null; then cache=writable; else cache=read-only; fi
if [ "$GRYPE_DB_AUTO_UPDATE" = "false" ]; then auto=off; else auto=on; fi
if [ -r /repo/sbom.json ]; then sbom=read; else sbom=missing; fi
net=$(ip -o addr | awk '{print $2}' | sort -u | tr '\n' ',')
echo "{\"matches\": [{\"vulnerability\": {\"id\": \"cache=$cache auto-update=$auto sbom=$sbom net=$net\"}, \"artifact\": {\"name\": \"probe\"}}]}"
"#;

/// Built once per run: the tests run in parallel, and two builds of one tag race on its name.
fn build_the_fake_matcher() {
    static BUILT: std::sync::Once = std::sync::Once::new();
    BUILT.call_once(build);
}

fn build() {
    let context = tempfile::Builder::new().prefix("vs-rs-fake-grype-").tempdir().unwrap();
    std::fs::write(context.path().join("grype"), SCRIPT).unwrap();
    std::fs::write(
        context.path().join("Dockerfile"),
        format!(
            "FROM {BUSYBOX}\nCOPY grype /grype\n# Root's alone, as in the real matcher's image.\nRUN chmod 755 /grype && chmod 0755 /tmp\nENTRYPOINT [\"/grype\"]\n"
        ),
    )
    .unwrap();
    docker(&["build", "-q", "-t", FAKE_GRYPE, &context.path().display().to_string()]);
}

fn runner(proxy: &SocketProxy) -> Arc<ContainerRunner> {
    Arc::new(ContainerRunner::connect(Some(&proxy.address), ScannerLimits::default_for_this_host()).unwrap())
}

fn cache() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("vs-rs-vulnerability-db-").tempdir().unwrap()
}

fn generations(cache: &Path) -> usize {
    std::fs::read_dir(cache.join("generations")).unwrap().count()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_match_reads_the_host_s_database_read_only_offline_with_automatic_updates_off() {
    build_the_fake_matcher();
    let proxy = SocketProxy::start();
    let runner = runner(&proxy);
    assert!(
        runner.is_available().await,
        "this suite needs a Docker daemon; it does not skip itself when there is none"
    );
    let cache = cache();
    let database = VulnerabilityDatabase::with_defaults(
        Arc::clone(&runner),
        FAKE_GRYPE,
        cache.path(),
        ScannerLimits::default_for_this_host().timeout,
    );

    let findings =
        dependencies::match_standalone_sbom(runner.as_ref(), &database, FAKE_GRYPE, "{}").await.unwrap().unwrap();

    let [finding] = findings.as_slice() else { panic!("{findings:?}") };
    assert_eq!(finding.identifier, "cache=read-only auto-update=off sbom=read net=lo,");
    assert_eq!(generations(cache.path()), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_scans_at_once_on_an_empty_cache_share_one_download_and_each_mounts_it() {
    build_the_fake_matcher();
    let proxy = SocketProxy::start();
    let runner = runner(&proxy);
    let cache = cache();
    let database = Arc::new(VulnerabilityDatabase::with_defaults(
        Arc::clone(&runner),
        FAKE_GRYPE,
        cache.path(),
        ScannerLimits::default_for_this_host().timeout,
    ));

    let scans: Vec<_> = (0..4)
        .map(|_| {
            let (runner, database) = (Arc::clone(&runner), Arc::clone(&database));
            tokio::spawn(async move {
                dependencies::match_standalone_sbom(runner.as_ref(), database.as_ref(), FAKE_GRYPE, "{}").await
            })
        })
        .collect();
    for scan in scans {
        assert_eq!(scan.await.unwrap().unwrap().unwrap().len(), 1);
    }

    assert_eq!(generations(cache.path()), 1);
    let staging: Vec<_> = std::fs::read_dir(cache.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("staging-"))
        .collect();
    assert!(staging.is_empty(), "no staging directory left behind: {staging:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn what_the_matcher_wrote_into_the_cache_is_this_process_s_to_delete_every_file_of_it() {
    use std::os::unix::fs::MetadataExt;
    build_the_fake_matcher();
    let proxy = SocketProxy::start();
    let runner = runner(&proxy);
    let cache = cache();
    let database = VulnerabilityDatabase::with_defaults(
        Arc::clone(&runner),
        FAKE_GRYPE,
        cache.path(),
        ScannerLimits::default_for_this_host().timeout,
    );
    dependencies::match_standalone_sbom(runner.as_ref(), &database, FAKE_GRYPE, "{}").await.unwrap();

    // As root, the directories the download created were root's on the host and the cleanup skipped
    // them. (Docker Desktop maps every bind-mounted file to the host user whoever wrote it, so on a Mac
    // only a Linux daemon can tell the two apart; `tests/vulnerability_database.rs` pins the user asked.)
    let owner = std::fs::metadata(cache.path()).unwrap().uid();
    let mut pending = vec![cache.path().to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.uid(), owner, "owner of {}", path.display());
        if metadata.is_dir() {
            pending.extend(std::fs::read_dir(&path).unwrap().map(|entry| entry.unwrap().path()));
        }
    }
    let path = cache.path().to_path_buf();
    cache.close().unwrap();
    assert!(!path.exists());
}

/// The pinned cataloguer, through the proxy, on the reference set's own fixture tree: the inventory the
/// committed `sboms/01-polyglot.json` was taken from, package for package — so the real outputs the
/// parser is held to are what this runner gets from this image.
#[tokio::test(flavor = "multi_thread")]
async fn the_pinned_cataloguer_inventories_the_reference_fixture_as_the_reference_says() {
    let proxy = SocketProxy::start();
    let runner = runner(&proxy);
    let workspace = tempfile::Builder::new().prefix("vs-rs-deps-tree-").tempdir().unwrap();
    let fixture = vectispire_testkit::reference_root().join("dependencies/fixtures/polyglot");
    let mut pending = vec![fixture.clone()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let relative =
                    path.strip_prefix(&fixture).unwrap().to_string_lossy().trim_end_matches(".fixture").to_owned();
                let target = workspace.path().join("source").join(relative);
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::copy(&path, target).unwrap();
            }
        }
    }

    let sbom =
        dependencies::sbom_of_directory(runner.as_ref(), images::SYFT, workspace.path(), None).await.unwrap().unwrap();

    let packages = |sbom: &serde_json::Value| -> BTreeSet<(String, String, String)> {
        sbom["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|artifact| {
                let field = |name: &str| artifact[name].as_str().unwrap_or_default().to_owned();
                (field("name"), field("version"), field("purl"))
            })
            .collect()
    };
    let reference = vectispire_testkit::read_json("dependencies/sboms/01-polyglot.json");
    assert_eq!(packages(&sbom), packages(&reference));
    assert!(packages(&sbom).len() >= 10);
}

/// The real matcher on the real database, through this runner: the committed polyglot SBOM matched to
/// the committed findings. **Run by hand**, against a database matching the one the reference was
/// captured with (2026-10-16): `VECTISPIRE_GRYPE_DB=<grype cache> cargo test -- --ignored real_matcher`.
/// Ignored rather than skipped, so a run that left it out says so.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a real 3 GB Grype database: VECTISPIRE_GRYPE_DB=<cache directory>"]
async fn real_matcher_on_the_real_database_gives_the_reference_findings() {
    struct Fixed(std::path::PathBuf);
    impl dependencies::MountableDatabase for Fixed {
        async fn mountable(&self) -> Result<std::path::PathBuf, vectispire_scanners::failure::ScannerError> {
            Ok(self.0.clone())
        }
    }
    let database = std::env::var("VECTISPIRE_GRYPE_DB").expect("VECTISPIRE_GRYPE_DB names a Grype cache directory");
    let proxy = SocketProxy::start();
    let runner = runner(&proxy);
    let sbom = vectispire_testkit::read_json("dependencies/sboms/01-polyglot.json");

    let findings =
        dependencies::match_standalone_sbom(runner.as_ref(), &Fixed(database.into()), images::GRYPE, &sbom.to_string())
            .await
            .unwrap()
            .expect("the matcher analysed");

    let reference = dependencies::read_match_output(&vectispire_testkit::read("dependencies/matches/01-polyglot.json"))
        .unwrap()
        .unwrap();
    assert_eq!(findings, reference);
}
