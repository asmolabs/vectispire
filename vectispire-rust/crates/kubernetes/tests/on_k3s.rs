//! The Kubernetes executor against a real cluster — Java's `KubernetesExecutorTest` and `ExecutorChoiceClusterTest`,
//! ported: k3s in a privileged container, the scans' namespace under Pod Security `restricted`, and the executor
//! calling the API server **as the agent's service account under the chart's own Role**, read from the chart's
//! template — so a call the executor makes outside it fails here first.
//!
//! Then the four scanners the Rust agent runs, each as a pod through the same scanner code a scan uses: gitleaks finds
//! its plant and its report comes back through the writable mount, checkov and semgrep their findings, syft its
//! inventory. The matcher (grype) against its real database, whose download is some 3 GB, only in the ignored
//! `the_matcher_on_its_real_database_on_k3s`, run by the nightly's `real-matcher`; elsewhere the cache it is served
//! from is exercised with a generation of the test's own.
//!
//! Needs Docker, and fails without it — a suite that skips itself reports green having checked nothing. One cluster
//! per test function (a minute to start): the executor's runs, the scanners, the choice at start — which the mutation
//! check's cluster-only mutants run alone (`security/mutants/agent-kubernetes.py`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Map, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use vectispire_container::bounded_output::{BoundedOutput, OutputFile};
use vectispire_container::{
    ContainerExecutor, ContainerRun, Executor, Extras, Mount, RegistryLogin, RunnerError, ScannerLimits,
};
use vectispire_domain::secret::Secret;
use vectispire_kubernetes::api::KubernetesApi;
use vectispire_kubernetes::choice::{self, KubernetesConfig};
use vectispire_kubernetes::executor::{HELPER_IMAGE, KubernetesExecutor, MatcherCache, Settings};
use vectispire_kubernetes::{address::ClusterAddress, pods};
use vectispire_scanners::rules::{self, RulePlacement};
use vectispire_scanners::{dependencies, iac, images, sast, secrets};
use vectispire_testkit::docker::Container;
use vectispire_tls::TlsTrust;

const NAMESPACE: &str = "vectispire-scans";
/// A version upstream still supports, as 0045 requires of the target — the Java suite's.
const K3S: &str = "rancher/k3s:v1.34.12-k3s1@sha256:4ea0adb6b0ffedab0c58ffe5c99a49f2f7be871f38636c8baa2692899648d8c5";
/// The chart's Role: these tests run under the very rules an installation gets.
const CHART_ROLE: &str = "../../../deploy/helm/vectispire/templates/agents/scans-role.yaml";

struct K3s {
    container: Container,
    port: u16,
    token: String,
    ca: tempfile::NamedTempFile,
}

impl K3s {
    fn start() -> K3s {
        let container = Container::run(
            "k3s",
            &[
                "--privileged",
                "-p",
                "127.0.0.1::6443",
                K3S,
                "server",
                "--disable=traefik,metrics-server,servicelb",
                "--tls-san=localhost",
            ],
        );
        let cluster = K3s {
            port: container.host_port("6443/tcp"),
            container,
            token: String::new(),
            ca: tempfile::NamedTempFile::new().unwrap(),
        };
        cluster.wait("the API server", &["kubectl", "get", "--raw", "/readyz"]);
        cluster.wait("a ready node", &["kubectl", "wait", "--for=condition=Ready", "node", "--all", "--timeout=5s"]);
        cluster.wait("the default service account", &["kubectl", "get", "serviceaccount", "default", "-n", "default"]);
        cluster.kubectl(&["create", "namespace", NAMESPACE]);
        cluster.kubectl(&[
            "label",
            "namespace",
            NAMESPACE,
            "pod-security.kubernetes.io/enforce=restricted",
            "pod-security.kubernetes.io/enforce-version=latest",
        ]);
        cluster.kubectl(&["create", "serviceaccount", "vectispire-agent", "-n", NAMESPACE]);
        cluster.apply(&format!(
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata: {{name: vectispire-agent, namespace: {NAMESPACE}}}\n{}\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata: {{name: vectispire-agent, namespace: {NAMESPACE}}}\nsubjects: [{{kind: ServiceAccount, name: vectispire-agent, namespace: {NAMESPACE}}}]\nroleRef: {{apiGroup: rbac.authorization.k8s.io, kind: Role, name: vectispire-agent}}\n",
            chart_rules()
        ));
        let token = cluster.kubectl(&["create", "token", "vectispire-agent", "-n", NAMESPACE, "--duration=2h"]);
        let ca = cluster.container.exec(&["cat", "/var/lib/rancher/k3s/server/tls/server-ca.crt"]);
        std::fs::write(cluster.ca.path(), format!("{ca}\n")).unwrap();
        K3s { token, ..cluster }
    }

    /// The API as the agent's service account sees it — not as the cluster's administrator.
    fn api(&self) -> KubernetesApi {
        let trust = TlsTrust::from_bundle(self.ca.path()).unwrap();
        KubernetesApi::with_token(&format!("https://localhost:{}", self.port), Secret::new(self.token.clone()), &trust)
            .unwrap()
    }

    /// As the administrator, for what the test arranges and the agent may not do.
    fn kubectl(&self, arguments: &[&str]) -> String {
        let mut command = vec!["kubectl"];
        command.extend_from_slice(arguments);
        self.container.exec(&command)
    }

    fn apply(&self, manifest: &str) {
        self.container.exec(&["sh", "-c", &format!("cat <<'EOF' | kubectl apply -f -\n{manifest}\nEOF")]);
    }

    fn wait(&self, what: &str, command: &[&str]) {
        let deadline = Instant::now() + Duration::from_secs(180);
        while !self.container.succeeds(command) {
            assert!(Instant::now() < deadline, "k3s never had {what}");
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

/// The Role's rules, read from the template the chart renders; a verb the chart drops fails here (decision 0045 §3).
fn chart_rules() -> String {
    let template = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(CHART_ROLE)).unwrap();
    let role = &template[template.find("kind: Role\n").unwrap()..];
    let rules = &role[role.find("\nrules:\n").unwrap() + 1..role.find("\n---").unwrap()];
    assert!(
        !rules.contains("{{") && rules.contains("pods/exec"),
        "the chart's Role rules are not the static block: {rules}"
    );
    rules.trim_end().to_owned()
}

fn limits(memory_mib: i64) -> ScannerLimits {
    ScannerLimits {
        memory: memory_mib * 1024 * 1024,
        pids: 512,
        timeout: Duration::from_secs(120),
        nano_cpus: 500_000_000,
        output_bytes: 1024 * 1024,
    }
}

fn executor(
    cluster: &K3s,
    memory_mib: i64,
    cache: Option<MatcherCache>,
    cut_off_from: Option<String>,
) -> KubernetesExecutor {
    let settings = Settings::new(
        NAMESPACE,
        "test-agent",
        HELPER_IMAGE,
        "1000:1000",
        Duration::from_secs(180),
        limits(memory_mib),
        Map::new(),
        cache,
        cut_off_from,
    )
    .unwrap();
    KubernetesExecutor::new(cluster.api(), settings)
}

/// A shell "scanner": the image has no entrypoint, so the declared one is empty and the command is whole.
fn shell(script: &str, mounts: Vec<Mount>) -> ContainerRun {
    ContainerRun::new(HELPER_IMAGE, vec!["sh".into(), "-c".into(), script.into()], mounts, "shell test")
        .with_entrypoint(&[])
}

async fn refused(executor: &Executor, run: &ContainerRun) -> RunnerError {
    match executor.run(run).await {
        Ok(result) => panic!(
            "the run returned, exit {}, standard output {:?}, errors {:?}",
            result.exit_code,
            result.stdout.trim(),
            result.stderr.trim()
        ),
        Err(error) => error,
    }
}

fn directory(root: &Path, name: &str) -> PathBuf {
    let path = root.join(name);
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn the_executor_on_k3s() {
    let cluster = K3s::start();
    let api = cluster.api();
    let k8s = executor(&cluster, 256, None, None);
    let run = Executor::new(k8s.clone());
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();

    // Available: the agent's Role lists and creates pods in its namespace.
    assert_eq!(k8s.why_unavailable().await, None, "the executor is available under the chart's Role");
    assert!(run.exports_images(), "image targets are claimed: the copy step of 0045 §8 copies them");

    // Standard output whole, apart from the errors, and the exit code the scanner's.
    let result =
        run.run(&shell("head -c 300000 /dev/zero | tr '\\0' a; echo warned >&2; exit 3", vec![])).await.unwrap();
    assert_eq!(result.stdout.len(), 300_000);
    assert!(result.stdout.bytes().all(|byte| byte == b'a'));
    assert_eq!((result.stderr.as_str(), result.exit_code), ("warned\n", 3));

    // A read-only mount is seen and cannot be written.
    let tree = directory(root, "readonly/source");
    std::fs::write(tree.join("main.py"), "print('hello')\n").unwrap();
    let mounted = Mount::read_only(root.join("readonly").display().to_string(), "/repo");
    let result =
        run.run(&shell("cat /repo/source/main.py && ! touch /repo/planted 2>/dev/null", vec![mounted])).await.unwrap();
    assert_eq!((result.exit_code, result.stdout.as_str()), (0, "print('hello')\n"), "{}", result.stderr);

    // What the scanner writes into a writable mount comes back, and only that: not a link.
    let tree = directory(root, "writable");
    std::fs::write(tree.join("kept.txt"), "kept").unwrap();
    let script = "echo '[]' > /repo/report.json && mkdir -p /repo/deep && echo x > /repo/deep/x.txt && ln -s /etc/passwd /repo/link.json";
    let result = run.run(&shell(script, vec![Mount::writable(tree.display().to_string(), "/repo")])).await.unwrap();
    assert_eq!(result.exit_code, 0, "{}", result.stderr);
    assert_eq!(std::fs::read_to_string(tree.join("report.json")).unwrap(), "[]\n");
    assert_eq!(std::fs::read_to_string(tree.join("deep/x.txt")).unwrap(), "x\n");
    assert_eq!(std::fs::read_to_string(tree.join("kept.txt")).unwrap(), "kept");
    assert!(std::fs::symlink_metadata(tree.join("link.json")).is_err(), "a link is not brought back");

    // A writable mount brings back what it declares, past the output ceiling; undeclared, the same write is refused.
    let declared = directory(root, "declared");
    let write = "head -c 3145728 /dev/zero > /db/database";
    let sized = Mount::writable_sized(declared.display().to_string(), "/db", 8 * 1024 * 1024);
    let result = run.run(&shell(write, vec![sized])).await.unwrap();
    assert_eq!(result.exit_code, 0, "{}", result.stderr);
    assert_eq!(std::fs::metadata(declared.join("database")).unwrap().len(), 3 * 1024 * 1024);
    let undeclared = Mount::writable(directory(root, "undeclared").display().to_string(), "/db");
    let error = refused(&run, &shell(write, vec![undeclared])).await;
    assert!(error.to_string().contains("more than 1048576 bytes into its workspace"), "{error}");

    // A written name with a line break is refused, not listed (review of 2026-10-26, L4).
    let lines = Mount::writable(directory(root, "lines").display().to_string(), "/repo");
    let error = refused(&run, &shell("touch \"/repo/x$(printf '\\ny')\"", vec![lines])).await;
    assert!(error.to_string().contains("line break"), "{error}");

    // An output that cannot be read back is a failure, not an empty report (L5).
    let error = refused(&run, &shell(&format!("rm {}; echo '[]'", pods::STDOUT), vec![])).await;
    assert!(error.to_string().contains("could not be read back"), "{error}");

    // Output past the ceiling is a failure, not a truncation.
    let error = refused(&run, &shell("head -c 2000000 /dev/zero", vec![])).await;
    assert!(error.to_string().contains("more than 1048576 bytes"), "{error}");

    // A scanner past its timeout is stopped.
    let mut slow = shell("sleep 120", vec![]);
    slow.timeout = Some(Duration::from_secs(5));
    let error = refused(&run, &slow).await;
    assert!(matches!(error, RunnerError::TimedOut { seconds: 5, .. }), "{error}");

    // Out of memory is a failure, whichever way the runtime reports it (containerd#12260).
    let small = Executor::new(executor(&cluster, 48, None, None));
    let error = refused(&small, &shell("a=$(head -c 200000000 /dev/zero | tr '\\0' a); echo ${#a}", vec![])).await;
    assert!(error.to_string().contains("(its limit is 48 MiB)"), "{error}");
    // Killed without a reason: exit 137 is evidence too. A child takes the SIGKILL, the shell passes its 137 on.
    let error = refused(&run, &shell("sleep 60 & kill -9 $!; wait $!; exit $?", vec![])).await;
    assert!(error.to_string().contains("was killed (exit 137, SIGKILL)"), "{error}");

    // An image that cannot be pulled is a failure.
    let absent =
        ContainerRun::new(format!("busybox@sha256:{}", "0".repeat(64)), vec!["true".into()], vec![], "absent image")
            .with_entrypoint(&[]);
    let error = refused(&run, &absent).await;
    assert!(error.to_string().contains("could not start"), "{error}");

    // An undeclared entrypoint keeps the image's, and its output is a diagnostic only.
    let plugin = ContainerRun::new(
        HELPER_IMAGE,
        vec!["sh".into(), "-c".into(), "echo to-the-log".into()],
        vec![],
        "plugin test",
    );
    let result = run.run(&plugin).await.unwrap();
    assert_eq!((result.exit_code, result.stdout.as_str()), (0, ""));
    assert!(result.stderr.contains("to-the-log"), "{}", result.stderr);

    // Root is never asked.
    let mut root_run = shell("true", vec![]);
    root_run.user = Some("0:0".into());
    let error = refused(&run, &root_run).await;
    assert!(error.to_string().contains("root"), "{error}");

    // No pod outlives its run.
    run.run(&shell("true", vec![])).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !api.pods(NAMESPACE, "vectispire.dev/agent=test-agent").await.unwrap().is_empty() {
        assert!(Instant::now() < deadline, "pods left behind");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    matcher_generations_are_seeded_once_and_served_from_the_cache(&cluster, root).await;
}

/// Alpine 3.20.3 by its **index** digest — the one the Docker executor's export is tested with — and its amd64 image by
/// its own digest: a reference to a single image, which crane fetches whatever platform is asked. Java's
/// `KubernetesExecutorTest` copies the same two.
const MULTI_ARCH_ALPINE: &str = "alpine@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a";
const ALPINE_AMD64_ONLY: &str = "alpine@sha256:029a752048e32e843bd6defe3841186fb8d19a28dae8ec287f433bb9d6d1ad85";

fn listed(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into())
        .collect();
    names.sort();
    names
}

/// An image target (decision 0045 §8): crane in a pod of its own, the archive brought back for the platform asked and
/// checked, and nothing left beside it — Java's `KubernetesExecutorTest.anImage*`, the same sentences.
#[tokio::test(flavor = "multi_thread")]
async fn the_image_copy_on_k3s() {
    use vectispire_container::image_archive::{self, Exporter};

    let cluster = K3s::start();
    let run = Executor::new(executor(&cluster, 256, None, None));
    let temporary = tempfile::tempdir().unwrap();

    // Both ways round, whatever this machine's own architecture.
    let workspace = directory(temporary.path(), "both");
    for platform in ["linux/amd64", "linux/arm64"] {
        let archive = workspace.join(format!("{}.tar", &platform[6..]));
        run.export_image(MULTI_ARCH_ALPINE, platform, &archive).await.unwrap();
        let other = if platform == "linux/amd64" { "linux/arm64" } else { "linux/amd64" };
        let check = |asked: &str| {
            image_archive::refusal_by(
                Exporter::Copy,
                MULTI_ARCH_ALPINE,
                asked,
                &image_archive::requested(asked).unwrap().unwrap(),
                |name, limit| image_archive::entry(&archive, name, limit),
            )
        };
        assert_eq!(check(platform), None, "the archive is of {platform}");
        let refused = check(other).unwrap();
        assert!(refused.contains(&format!("as {platform} where {other}")), "{refused}");
    }
    // The copy's own directory, and the login's, are gone: the archives alone remain.
    assert_eq!(listed(&workspace), ["amd64.tar", "arm64.tar"]);

    // A single image of another platform: refused with the copy's sentence, and nothing left.
    let workspace = directory(temporary.path(), "other");
    let refused = run.export_image(ALPINE_AMD64_ONLY, "linux/arm64", &workspace.join("image.tar")).await.unwrap_err();
    assert_eq!(
        refused.to_string(),
        format!(
            "The image copy fetched {ALPINE_AMD64_ONLY} as linux/amd64 where linux/arm64 was asked: a reference to a \
             single image is served whatever the platform asked, and another architecture is not scanned in place of \
             the one asked for."
        )
    );
    assert!(listed(&workspace).is_empty(), "{:?}", listed(&workspace));

    // An image the registry does not serve: crane's own words, the image named.
    let workspace = directory(temporary.path(), "absent");
    let absent = format!("alpine@sha256:{}", "0".repeat(64));
    let failed = run.export_image(&absent, "linux/amd64", &workspace.join("image.tar")).await.unwrap_err().to_string();
    assert!(
        failed
            .starts_with(&format!("The image copy could not fetch {absent} for linux/amd64: crane exited 1, saying: "))
            && failed.ends_with(". It is not scanned."),
        "{failed}"
    );
    assert!(listed(&workspace).is_empty(), "{:?}", listed(&workspace));
}

/// Each scanner the Rust agent runs, as a pod, through the scanner code a scan uses.
#[tokio::test(flavor = "multi_thread")]
async fn the_scanners_on_k3s() {
    let cluster = K3s::start();
    // A scanner's own resources: semgrep and checkov are not shells, and their images take a while to pull.
    let limits = ScannerLimits { nano_cpus: 1_500_000_000, timeout: Duration::from_secs(600), ..limits(2048) };
    let settings = Settings::new(
        NAMESPACE,
        "test-agent",
        HELPER_IMAGE,
        "1000:1000",
        Duration::from_secs(600),
        limits,
        Map::new(),
        None,
        None,
    );
    let run = Executor::new(KubernetesExecutor::new(cluster.api(), settings.unwrap()));
    let temporary = tempfile::tempdir().unwrap();
    the_scanners_run_as_pods(&run, temporary.path()).await;
}

/// A plugin's two needs, as Java's `KubernetesExecutorTest` runs them: the registry login reaching the tool redacted and
/// gone after, and the bounded output read back, measured, and refused past its ceiling.
#[tokio::test(flavor = "multi_thread")]
async fn the_plugins_needs_on_k3s() {
    let cluster = K3s::start();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();

    // The login: the plugin's registry's entry alone, read by the tool's own user in its pod, redacted, and gone after.
    let auth = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "robot:s3cret-pull"); // gitleaks:allow — invented
    let mounted = directory(root, "registry");
    std::fs::write(
        mounted.join("config.json"),
        format!(
            "{{\"auths\": {{\"registry.acme.internal\": {{\"auth\": \"{auth}\"}}, \"other.acme.internal\": {{\"auth\": \
             \"b3RoZXI6b3RoZXI=\"}}}}}}"
        ),
    )
    .unwrap();
    let settings = executor(&cluster, 256, None, None).settings().clone().with_registry_credentials(Some(mounted));
    let with_secret = KubernetesExecutor::new(cluster.api(), settings);
    let workspace = directory(root, "workspace");
    let plugin = format!("registry.acme.internal/security/plugin@sha256:{}", "d".repeat(64));
    let login = |reference: &str| Extras {
        output: None,
        login: Some(RegistryLogin { reference: reference.to_owned(), directory: workspace.clone() }),
    };
    let mut cat = shell("cat \"$DOCKER_CONFIG/config.json\"", vec![]);
    cat.user = Some("1000:1000".into());
    let done = with_secret.run_with(&cat, &login(&plugin)).await.unwrap().result;
    assert_eq!(done.exit_code, 0, "{}", done.stderr);
    assert!(done.stdout.contains("registry.acme.internal") && done.stdout.contains("[redacted]"), "{}", done.stdout);
    assert!(!done.stdout.contains(&auth) && !done.stdout.contains("other.acme.internal"), "{}", done.stdout);
    assert_eq!(std::fs::read_dir(&workspace).unwrap().count(), 0, "the login directory outlives the run");
    assert!(with_secret.registry_access_for(&plugin).credentials_held);
    let elsewhere = format!("ghcr.io/acme/plugin@sha256:{}", "e".repeat(64));
    assert!(!with_secret.registry_access_for(&elsewhere).credentials_held);
    // A registry the secret does not name: no login handed, the tool reads anonymously as before.
    let mut anonymous = shell("test -z \"$DOCKER_CONFIG\"", vec![]);
    anonymous.user = Some("1000:1000".into());
    let done = with_secret.run_with(&anonymous, &login(&elsewhere)).await.unwrap().result;
    assert_eq!(done.exit_code, 0, "{}", done.stderr);
    // A failure quoting the secret carries it nowhere: here a timeout naming the run by a label that holds it.
    let mut quoting = shell("sleep 120", vec![]);
    quoting.user = Some("1000:1000".into());
    quoting.label = "plugin s3cret-pull".into(); // gitleaks:allow — invented
    quoting.timeout = Some(Duration::from_secs(5));
    let failed = with_secret.run_with(&quoting, &login(&plugin)).await.unwrap_err().to_string();
    assert!(!failed.contains("s3cret-pull") && failed.contains("[redacted]"), "{failed}");
    assert_eq!(std::fs::read_dir(&workspace).unwrap().count(), 0, "the login directory outlives a failed run");

    // The bounded output: read back and measured, missing when nothing is written, full at the kernel's ENOSPC.
    let run = Executor::new(executor(&cluster, 256, None, None));
    let bounded = |bytes: u64| Extras {
        output: Some(BoundedOutput::new("/output", bytes, HELPER_IMAGE, "report.json").unwrap()),
        login: None,
    };
    let as_user = |script: &str| {
        let mut run = shell(script, vec![]);
        run.user = Some("1000:1000".into());
        run
    };
    let written = run.run_with(&as_user("echo '{\"ok\":true}' > /output/report.json"), &bounded(64 * 1024)).await;
    let written = written.unwrap().output.unwrap();
    assert_eq!(written.file, OutputFile::Read(b"{\"ok\":true}\n".to_vec()));
    assert!(!written.full(), "{written:?}");
    let missing = run.run_with(&as_user("true"), &bounded(64 * 1024)).await.unwrap().output.unwrap();
    assert_eq!(missing.file, OutputFile::Missing);
    let full = run.run_with(&as_user("head -c 200000 /dev/zero > /output/filler; true"), &bounded(64 * 1024)).await;
    assert!(full.unwrap().output.unwrap().full(), "the directory reports itself full");

    // Past the scanner's output ceiling (1 MiB here) though within its directory: refused on its size, never read.
    let writer = as_user("head -c 2097152 /dev/zero > /output/report.json");
    let large = run.run_with(&writer, &bounded(4 * 1024 * 1024)).await.unwrap().output.unwrap();
    assert_eq!(large.file, OutputFile::TooLarge(2 * 1024 * 1024));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_choice_at_start_on_k3s() {
    let cluster = K3s::start();
    the_choice_at_start(&cluster).await;
}

/// The claim in the scans' namespace, as the chart renders it: a generation copied once, read-only after, and the
/// volume following the agent's cache when a generation is retired (decision 0045 §7).
async fn matcher_generations_are_seeded_once_and_served_from_the_cache(cluster: &K3s, root: &Path) {
    cluster.apply(&format!(
        "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {{name: matcher-cache, namespace: {NAMESPACE}}}\nspec: {{accessModes: [ReadWriteOnce], resources: {{requests: {{storage: 1Gi}}}}}}"
    ));
    let generations = directory(root, "db/generations");
    let cached =
        Executor::new(executor(cluster, 256, Some(MatcherCache::new("matcher-cache", &generations, "")), None));

    let first = directory(&generations, "1761400000000-aaaaaaaa");
    std::fs::write(first.join("vulnerability.db"), "first").unwrap();
    let mount = || Mount::read_only(first.display().to_string(), "/cache");
    let result = cached.run(&shell("cat /cache/vulnerability.db", vec![mount()])).await.unwrap();
    assert_eq!(result.stdout, "first", "{}", result.stderr);

    // A generation never changes once published, so it is not copied again: what the pod reads is the volume's.
    std::fs::write(first.join("vulnerability.db"), "changed on the agent").unwrap();
    let script = "cat /cache/vulnerability.db; touch /cache/x 2>/dev/null && echo WROTE";
    let again = cached.run(&shell(script, vec![mount()])).await.unwrap();
    assert_eq!(again.stdout, "first", "served from the volume, read-only");

    // The agent moves to a new generation and retires the old one: the volume follows.
    let second = directory(&generations, "1761500000000-bbbbbbbb");
    std::fs::write(second.join("vulnerability.db"), "second").unwrap();
    std::fs::remove_dir_all(&first).unwrap();
    let mount = Mount::read_only(second.display().to_string(), "/cache");
    let result = cached.run(&shell("cat /cache/vulnerability.db", vec![mount])).await.unwrap();
    assert_eq!(result.stdout, "second");

    // Listed by a pod of the test's own: what a scan pod cannot see.
    cluster.apply(&format!(
        "apiVersion: v1\nkind: Pod\nmetadata: {{name: cache-lister, namespace: {NAMESPACE}}}\nspec:\n  restartPolicy: Never\n  automountServiceAccountToken: false\n  volumes: [{{name: c, persistentVolumeClaim: {{claimName: matcher-cache}}}}]\n  containers:\n  - name: ls\n    image: {HELPER_IMAGE}\n    command: [sh, -c, \"ls -a /c/generations; sleep 300\"]\n    volumeMounts: [{{name: c, mountPath: /c, readOnly: true}}]\n    securityContext: {{runAsNonRoot: true, runAsUser: 1000, allowPrivilegeEscalation: false, capabilities: {{drop: [ALL]}}, seccompProfile: {{type: RuntimeDefault}}}}"
    ));
    let deadline = Instant::now() + Duration::from_secs(120);
    let listed = loop {
        let output = std::process::Command::new("docker")
            .args(["exec", &cluster.container.name, "kubectl", "logs", "cache-lister", "-n", NAMESPACE])
            .output()
            .unwrap();
        let listed = String::from_utf8_lossy(&output.stdout).into_owned();
        if output.status.success() && !listed.trim().is_empty() {
            break listed;
        }
        assert!(Instant::now() < deadline, "the lister ran");
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    cluster.kubectl(&["delete", "pod", "cache-lister", "-n", NAMESPACE, "--grace-period=0"]);
    assert!(listed.contains("1761500000000-bbbbbbbb.complete"), "{listed}");
    assert!(!listed.contains("1761400000000-aaaaaaaa"), "the retired generation is pruned: {listed}");
}

/// A workspace as the agent lays it out — `source/` and the bundled rules placed in `rules/`, 0700 — holding
/// `files`.
fn workspace(root: &Path, name: &str, files: &[(&str, &str)]) -> PathBuf {
    let workspace = directory(root, name);
    std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (file, content) in files {
        let path = workspace.join("source").join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    let bundled = rules::materialise().unwrap();
    RulePlacement::new(bundled.tree()).place_bundled(&workspace.join("rules")).unwrap();
    workspace
}

/// Each scanner the Rust agent runs, as a pod, through the scanner code a scan uses: their declared entrypoints, their
/// mounts copied in, gitleaks' report brought back through its writable mount.
async fn the_scanners_run_as_pods(run: &Executor, root: &Path) {
    // An invented AWS access key id, assembled here so that no file of this repository carries one.
    let key = ["AKIA", "Q7ZR", "4TMX", "2KDW", "B3PN"].concat();
    let secrets_tree = workspace(root, "scan-secrets", &[("deploy/app.env", &format!("AWS_ACCESS_KEY_ID={key}\n"))]);
    let found = secrets::scan(run, &secrets_tree, None, images::GITLEAKS).await.unwrap().expect("a report");
    assert!(
        found.iter().any(|finding| finding.rule == "aws-access-token" && finding.file == "deploy/app.env"),
        "{found:?}"
    );
    assert!(!secrets_tree.join(secrets::REPORT_FILENAME).exists(), "the report of plaintext secrets is gone");

    let bucket =
        "resource \"aws_s3_bucket\" \"reports\" {\n  bucket = \"example-reports\"\n  acl    = \"public-read\"\n}\n";
    let iac_tree = workspace(root, "scan-iac", &[("deploy/main.tf", bucket)]);
    let found = iac::scan(run, &iac_tree, Some("deploy"), images::CHECKOV).await.expect("checkov's report");
    assert!(found.iter().any(|finding| finding.resource.as_deref() == Some("aws_s3_bucket.reports")), "{found:?}");

    let sast_tree =
        workspace(root, "scan-sast", &[("app.py", "def handle(expression):\n    return eval(expression)\n")]);
    let found = sast::scan(run, &sast_tree, None, images::SEMGREP).await.unwrap().expect("semgrep's report");
    assert!(found.iter().any(|finding| finding.rule_id == "vectispire.python.eval-on-input"), "{found:?}");

    let manifest = "{\"name\": \"app\", \"version\": \"1.0.0\", \"dependencies\": {\"left-pad\": \"1.3.0\"}}\n";
    let lock = "{\"name\": \"app\", \"version\": \"1.0.0\", \"lockfileVersion\": 3, \"packages\": {\"\": {\"name\": \"app\", \"version\": \"1.0.0\", \"dependencies\": {\"left-pad\": \"1.3.0\"}}, \"node_modules/left-pad\": {\"version\": \"1.3.0\", \"resolved\": \"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\"}}}\n";
    let tree = workspace(root, "scan-sbom", &[("package.json", manifest), ("package-lock.json", lock)]);
    let sbom =
        dependencies::sbom_of_directory(run, images::SYFT, &tree, None).await.unwrap().expect("syft's inventory");
    assert!(sbom.to_string().contains("left-pad"), "the inventory names the dependency: {sbom}");
}

/// The choice as the agent makes it at start: it sweeps this agent's leftovers, it starts only where the scans'
/// namespace refuses a privileged pod, and only where a probe pod — offline, then online — cannot reach the API server
/// (decision 0045 §3, §5). k3s enforces NetworkPolicy, so the same cluster answers both ways with the policies applied.
async fn the_choice_at_start(cluster: &K3s) {
    let service =
        cluster.kubectl(&["get", "service", "kubernetes", "-n", "default", "-o", "jsonpath={.spec.clusterIP}"]);
    let endpoint = cluster.kubectl(&[
        "get",
        "endpoints",
        "kubernetes",
        "-n",
        "default",
        "-o",
        "jsonpath={.subsets[0].addresses[0].ip}",
    ]);
    let context = choice::Context { matcher_database: "db".into(), own_user: Some("1000:1000".into()) };
    // The pull secret as the chart mounts it: what the executor hands a plugin's cosign.
    let secret = tempfile::tempdir().unwrap();
    std::fs::write(secret.path().join("config.json"), "{\"auths\": {}}").unwrap();
    let config = |require_isolation: bool| KubernetesConfig {
        registry_credentials: secret.path().display().to_string(),
        namespace: NAMESPACE.into(),
        name: "vs-agent".into(),
        user: "1000:1000".into(),
        start_timeout: Duration::from_secs(180),
        require_isolation,
        probe_target: format!("{service}:443"),
        cpu_millis: 250,
        memory_mib: 128,
        ..KubernetesConfig::default()
    };
    let unasked = || -> Result<ClusterAddress, String> { panic!("the probe's target is configured") };
    let start = |require_isolation: bool| {
        let config = config(require_isolation);
        let api = cluster.api();
        let context = context.clone();
        async move { choice::kubernetes(&config, &context, move || Ok(api), unasked).await }
    };
    let api = cluster.api();

    // This agent's leftovers are swept, and no one else's.
    for (pod, agent) in [("left-by-crash", "vs-agent"), ("another-agents", "someone-else")] {
        api.create_pod(
            NAMESPACE,
            &json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": pod, "labels": {"vectispire.dev/agent": agent}},
                "spec": {"restartPolicy": "Never", "automountServiceAccountToken": false,
                    "containers": [{"name": "c", "image": HELPER_IMAGE, "command": ["sleep", "600"],
                        "securityContext": {"runAsNonRoot": true, "runAsUser": 1000, "allowPrivilegeEscalation": false,
                            "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}}]}}),
        )
        .await
        .unwrap();
    }
    let executor = start(false).await.unwrap();
    assert_eq!(executor.settings().registry_credentials.as_deref(), Some(secret.path()), "the pull secret is used");
    assert_eq!(executor.why_unavailable().await, None);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !api.pods(NAMESPACE, "vectispire.dev/agent=vs-agent").await.unwrap().is_empty() {
        assert!(Instant::now() < deadline, "this agent's leftovers swept");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(api.pods(NAMESPACE, "vectispire.dev/agent=someone-else").await.unwrap().len(), 1);
    api.delete_pod(NAMESPACE, "another-agents").await.unwrap();

    // A namespace created outside the chart, without the label: the Role's ceiling is gone (review, M1).
    cluster.kubectl(&["label", "namespace", NAMESPACE, "pod-security.kubernetes.io/enforce-"]);
    let refusal = start(false).await.unwrap_err();
    cluster.kubectl(&["label", "namespace", NAMESPACE, "pod-security.kubernetes.io/enforce=restricted", "--overwrite"]);
    assert!(refusal.contains("would admit a privileged pod"), "{refusal}");

    // Without policies, the start is refused.
    let refusal = start(true).await.unwrap_err();
    assert!(
        refusal.contains("offline scan pod reached the API server") && refusal.contains("does not start"),
        "{refusal}"
    );

    // A scan pod that still reaches the API server never starts its scanner.
    let ungated = Executor::new(self::executor(cluster, 128, None, Some(format!("{service}:443"))));
    let echo = shell("echo scanned", vec![]);
    let error = refused(&ungated, &echo).await.to_string();
    assert!(
        error.contains(&format!("was not cut off from {service}:443")) && error.contains("the scanner was not started"),
        "{error}"
    );

    // The chart's policies, an online rule whose exclusions miss the API server: refused.
    chart_policies(cluster, "169.254.0.0/16");
    let refusal = start(true).await.unwrap_err();
    assert!(refusal.contains("online scan pod reached the API server"), "{refusal}");

    // The chart's policies as rendered: it starts, and its scanners run once their pod is cut off, offline and online.
    cluster.kubectl(&["delete", "networkpolicy", "--all", "-n", NAMESPACE]);
    chart_policies(cluster, &format!("169.254.0.0/16, {service}/32, {endpoint}/32"));
    let executor = Executor::new(start(true).await.unwrap());
    assert_eq!(executor.why_unavailable().await, None);
    assert_eq!(executor.run(&echo).await.unwrap().stdout, "scanned\n");
    let mut online = echo.clone();
    online.network = true;
    assert_eq!(executor.run(&online).await.unwrap().stdout, "scanned\n");
    cluster.kubectl(&["delete", "networkpolicy", "--all", "-n", NAMESPACE]);
}

/// The chart's two policies for the scans' namespace, as `scans-networkpolicy.yaml` renders them.
fn chart_policies(cluster: &K3s, online_except: &str) {
    cluster.apply(&format!(
        "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {{name: scans-offline, namespace: {NAMESPACE}}}\nspec:\n  podSelector: {{}}\n  policyTypes: [Ingress, Egress]\n---\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {{name: scans-online, namespace: {NAMESPACE}}}\nspec:\n  podSelector: {{matchLabels: {{vectispire.dev/network: egress}}}}\n  policyTypes: [Egress]\n  egress:\n  - ports: [{{port: 53, protocol: UDP}}, {{port: 53, protocol: TCP}}]\n  - to: [{{ipBlock: {{cidr: 0.0.0.0/0, except: [{online_except}]}}}}]"
    ));
}

/// **The matcher against its real database, on k3s** — what the rest of this file proves with a generation of its own:
/// the agent's `VulnerabilityDatabase` over the Kubernetes executor, so `db update` runs as a pod with the network, the
/// 3 GB it writes is copied back to the agent's cache through the API server's exec stream, `db status` reads it back
/// from a copy in, and the match of a real tree mounts the generation from the cache claim, seeded once.
///
/// Ignored, not skipped, as `crates/scanners/tests/real_matcher.rs`: it downloads the publisher's database. Run by the
/// nightly's `real-matcher` job after that one, with the same variables: the agent's cache is
/// `$VECTISPIRE_REAL_GRYPE_CACHE-k8s`, and when the Docker run matched against the same archive (`import.json`'s
/// `source`), the findings here must be its findings, in its order.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "downloads the real Grype database (3 GB) into k3s: VECTISPIRE_REAL_GRYPE_CACHE, VECTISPIRE_REAL_MATCHER_OUT"]
async fn the_matcher_on_its_real_database_on_k3s() {
    let docker_cache =
        PathBuf::from(std::env::var("VECTISPIRE_REAL_GRYPE_CACHE").expect("VECTISPIRE_REAL_GRYPE_CACHE"));
    let out = PathBuf::from(std::env::var("VECTISPIRE_REAL_MATCHER_OUT").expect("VECTISPIRE_REAL_MATCHER_OUT"));
    let root = PathBuf::from(format!("{}-k8s", docker_cache.display()));
    std::fs::create_dir_all(&root).unwrap();
    let cluster = K3s::start();
    cluster.apply(&format!(
        "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {{name: matcher-cache, namespace: {NAMESPACE}}}\nspec: {{accessModes: [ReadWriteOnce], resources: {{requests: {{storage: 16Gi}}}}}}"
    ));
    let limits = ScannerLimits { nano_cpus: 1_500_000_000, timeout: Duration::from_secs(900), ..limits(2048) };
    let settings = Settings::new(
        NAMESPACE,
        "test-agent",
        HELPER_IMAGE,
        "1000:1000",
        Duration::from_secs(600),
        limits,
        Map::new(),
        Some(MatcherCache::new("matcher-cache", &root.join("generations"), "")),
        None,
    );
    let run = std::sync::Arc::new(Executor::new(KubernetesExecutor::new(cluster.api(), settings.unwrap())));
    let database = vectispire_scanners::vulnerability_database::VulnerabilityDatabase::with_defaults(
        std::sync::Arc::clone(&run),
        images::GRYPE,
        &root,
        Duration::from_secs(900),
    );

    let started = Instant::now();
    let generation = database.mountable().await.expect("the real database, downloaded through a pod and published");
    eprintln!("real-matcher on k3s: database ready in {:?}: {}", started.elapsed(), generation.display());
    assert!(generation.join("6/vulnerability.db").metadata().unwrap().len() > 1024 * 1024 * 1024);

    let temporary = tempfile::tempdir().unwrap();
    let tree = directory(temporary.path(), "polyglot");
    std::fs::set_permissions(&tree, std::fs::Permissions::from_mode(0o700)).unwrap();
    copy_fixture(&vectispire_testkit::reference_root().join("dependencies/fixtures/polyglot"), &tree.join("source"));
    let started = Instant::now();
    let (step, _) = dependencies::tree_step(run.as_ref(), &database, images::SYFT, images::GRYPE, &tree, None).await;
    let step = step.unwrap_or_else(|failed| panic!("the dependency step on k3s did not complete: {failed}"));
    eprintln!(
        "real-matcher on k3s: polyglot tree matched in {:?}: {} findings",
        started.elapsed(),
        step.dependencies.len()
    );
    assert!(step.dependencies.len() >= 10, "{} findings", step.dependencies.len());
    let findings: Vec<serde_json::Value> =
        step.dependencies.iter().map(|finding| serde_json::to_value(finding).unwrap()).collect();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("rust-k8s-polyglot.json"), serde_json::to_string_pretty(&findings).unwrap()).unwrap();

    let on_docker = std::fs::read_to_string(docker_cache.join("current"))
        .ok()
        .map(|name| docker_cache.join("generations").join(name.trim()));
    let docker_findings = std::fs::read_to_string(out.join("rust-polyglot.json"));
    match (on_docker.as_deref().and_then(archive), archive(&generation), docker_findings) {
        (Some(docker), Some(here), Ok(docker_findings)) if docker == here => {
            let docker_findings: Vec<serde_json::Value> = serde_json::from_str(&docker_findings).unwrap();
            assert_eq!(findings, docker_findings, "the same archive, the same findings on k3s as on Docker");
        }
        other => {
            eprintln!("real-matcher on k3s: not compared with the Docker run (another archive, or none): {other:?}")
        }
    }
}

/// Which archive a generation was unpacked from — `import.json`'s `source`.
fn archive(generation: &Path) -> Option<String> {
    let import = std::fs::read_to_string(generation.join("6/import.json")).ok()?;
    serde_json::from_str::<serde_json::Value>(&import).ok()?.get("source")?.as_str().map(str::to_owned)
}

/// The reference set's fixture tree under its real names (`reference/dependencies/capture.sh`).
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
