//! The Kubernetes executor's pure parts against the Java executor's answers, `reference/kubernetes/` — written by
//! `KubernetesReferenceSetTest` and `ExecutorChoiceReferenceSetTest` (`vectispire-agent`), each file carrying its inputs
//! beside the answers.
//!
//! A pod spec drifting on one side is a scan pod with another security context, another limit or another volume size,
//! which no test of a single side would see; so is a status read as running that Java reads as failed, or an archive
//! entry one side brings back and the other refuses.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;
use vectispire_container::bounded_output::{BoundedOutput, OutputFile};
use vectispire_container::pull_credentials::MountedPullCredentials;
use vectispire_container::{
    ContainerExecutor, ContainerRun, ExtendedError, Extras, Mount, RegistryLogin, ScannerLimits,
};
use vectispire_kubernetes::address::{self, ClusterAddress};
use vectispire_kubernetes::api::KubernetesApi;
use vectispire_kubernetes::channels::ExecChannels;
use vectispire_kubernetes::executor::{self, KubernetesExecutor, MatcherCache, Settings};
use vectispire_kubernetes::{KubernetesError, archives, choice, pods};
use vectispire_testkit::read_json;

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_else(|| panic!("not a string: {value}"))
}

fn int(value: &Value) -> i64 {
    value.as_i64().unwrap_or_else(|| panic!("not an integer: {value}"))
}

fn bytes(value: &Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(text(value)).unwrap()
}

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

fn settings(given: &Value) -> Settings {
    let limits = &given["limits"];
    let limits = ScannerLimits {
        memory: int(&limits["memory"]),
        pids: 512,
        timeout: Duration::from_secs(u64::try_from(int(&limits["timeoutSeconds"])).unwrap()),
        nano_cpus: int(&limits["nanoCpus"]),
        output_bytes: usize::try_from(int(&limits["outputBytes"])).unwrap(),
    };
    let cache = given["cache"]
        .as_object()
        .map(|cache| MatcherCache::new(text(&cache["claim"]), Path::new("/db/generations"), text(&cache["node"])));
    Settings::new(
        text(&given["namespace"]),
        text(&given["agent"]),
        text(&given["helperImage"]),
        text(&given["defaultUser"]),
        Duration::from_secs(u64::try_from(int(&given["startTimeoutSeconds"])).unwrap()),
        limits,
        object(&given["placement"]),
        cache,
        None,
    )
    .unwrap()
}

fn request(given: &Value) -> ContainerRun {
    let mounts = given["mounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|mount| Mount {
            source: text(&mount["source"]).to_owned(),
            target: text(&mount["target"]).to_owned(),
            read_only: mount["readOnly"].as_bool().unwrap(),
            writable_bytes: u64::try_from(int(&mount["writableBytes"])).unwrap(),
        })
        .collect();
    let command = given["command"].as_array().unwrap().iter().map(|part| text(part).to_owned()).collect();
    let mut run = ContainerRun::new(text(&given["image"]), command, mounts, text(&given["label"]));
    run.network = given["network"].as_bool().unwrap();
    run.entrypoint =
        given["entrypoint"].as_array().map(|parts| parts.iter().map(|part| text(part).to_owned()).collect());
    run
}

/// The request's bounded output, as Java's record holds it.
fn output(given: &Value) -> Option<BoundedOutput> {
    given["output"].as_object().map(|output| {
        BoundedOutput::with_inodes(
            text(&output["target"]),
            u64::try_from(int(&output["bytes"])).unwrap(),
            text(&output["holderImage"]),
            text(&output["file"]),
            u32::try_from(int(&output["inodes"])).unwrap(),
        )
        .unwrap()
    })
}

#[test]
fn the_pods_the_runs_become() {
    let cases = read_json("kubernetes/pods.json");
    for case in cases.as_array().unwrap() {
        let name = text(&case["name"]);
        let request = request(&case["request"]);
        let output = output(&case["request"]);
        let settings = settings(&case["settings"]);
        let sources: Vec<pods::MountSource> = case["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|source| pods::MountSource {
                cached: source["cached"].as_bool().unwrap(),
                name: text(&source["name"]).to_owned(),
            })
            .collect();
        let pod_name = executor::pod_name(&request.label, &[1, 2, 3, 4, 5]);
        assert_eq!(pod_name, text(&case["podName"]), "{name}: the pod's name");
        let pod = pods::pod(
            &pod_name,
            &request,
            output.as_ref(),
            &settings,
            u64::try_from(int(&case["uid"])).unwrap(),
            u64::try_from(int(&case["gid"])).unwrap(),
            &sources,
            u64::try_from(int(&case["workBytes"])).unwrap(),
            Duration::from_secs(u64::try_from(int(&case["timeoutSeconds"])).unwrap()),
            Duration::from_secs(u64::try_from(int(&case["transfersSeconds"])).unwrap()),
        );
        assert_eq!(pod, case["pod"], "{name}: the pod differs from Java's");
        // In Java's order too: an operator reading `kubectl get pod -o yaml` from either agent reads one shape.
        assert_eq!(serde_json::to_string(&pod).unwrap(), serde_json::to_string(&case["pod"]).unwrap(), "{name}: order");
    }
}

#[test]
fn labels_names_scripts_and_probes() {
    let file = read_json("kubernetes/names.json");
    for label in file["labels"].as_array().unwrap() {
        let given = text(&label["text"]);
        assert_eq!(pods::label_value(given), text(&label["value"]), "label value of {given:?}");
        assert_eq!(
            executor::pod_name(given, &[0, 0xff, 0x10, 0x7f, 0x80]),
            text(&label["podName"]),
            "pod name of {given:?}"
        );
    }
    for case in file["untilRefused"].as_array().unwrap() {
        let port = u16::try_from(int(&case["port"])).unwrap();
        let seconds = u32::try_from(int(&case["connectSeconds"])).unwrap();
        assert_eq!(executor::until_refused(text(&case["host"]), port, seconds), text(&case["script"]));
    }
    for case in file["probeCommands"].as_array().unwrap() {
        let port = u16::try_from(int(&case["port"])).unwrap();
        assert_eq!(serde_json::json!(executor::probe_command(text(&case["host"]), port)), case["command"]);
    }
    for case in file["copyBack"].as_array().unwrap() {
        assert_eq!(executor::copy_back_script(text(&case["directory"])), text(&case["script"]));
    }
    for case in file["prune"].as_array().unwrap() {
        let held: BTreeSet<String> = case["held"].as_array().unwrap().iter().map(|g| text(g).to_owned()).collect();
        assert_eq!(executor::prune_script(&held), text(&case["script"]));
    }
    let seed = &file["seed"];
    let (root, name, partial) = (text(&seed["root"]), text(&seed["name"]), text(&seed["partial"]));
    assert_eq!(format!("{}/{}", pods::CACHE, pods::GENERATIONS), root);
    assert_eq!(executor::seed_script(root, name, partial), text(&seed["receive"]));
    assert_eq!(executor::complete_script(root, name, partial), text(&seed["complete"]));
    for case in file["transferSeconds"].as_array().unwrap() {
        let bytes = u64::try_from(int(&case["bytes"])).unwrap();
        assert_eq!(executor::transfer_time(bytes).as_secs(), u64::try_from(int(&case["seconds"])).unwrap());
    }
    for case in file["targets"].as_array().unwrap() {
        let target = text(&case["target"]);
        match address::address(target) {
            Ok((host, port)) => {
                assert_eq!(host, text(&case["host"]), "{target}");
                assert_eq!(i64::from(port), int(&case["port"]), "{target}");
            }
            Err(refused) => assert_eq!(refused, text(&case["refused"]), "{target}"),
        }
        if case.get("refused").is_some() {
            assert!(address::address(target).is_err(), "{target} is refused by Java");
        }
    }
    for case in file["owners"].as_array().unwrap() {
        let user = text(&case["user"]);
        match executor::owner(user, "gitleaks") {
            Ok((uid, gid)) => {
                assert_eq!(
                    (i64::try_from(uid).unwrap(), i64::try_from(gid).unwrap()),
                    (int(&case["uid"]), int(&case["gid"])),
                    "{user:?}"
                );
            }
            Err(refused) => assert_eq!(refused.to_string(), text(&case["refused"]), "{user:?}"),
        }
        assert_eq!(executor::owner(user, "gitleaks").is_err(), case.get("refused").is_some(), "{user:?}");
    }
    for case in file["placements"].as_array().unwrap() {
        let refused = Settings::new(
            "ns",
            "a",
            executor::HELPER_IMAGE,
            "1000:1000",
            Duration::from_secs(60),
            ScannerLimits::default_for_this_host(),
            object(&case["placement"]),
            None,
            None,
        )
        .err();
        assert_eq!(refused.as_deref(), case["refused"].as_str(), "{}", case["placement"]);
    }
    for case in file["probePods"].as_array().unwrap() {
        let settings = Settings::new(
            "ns",
            "a",
            executor::HELPER_IMAGE,
            "1000:1000",
            Duration::from_secs(60),
            ScannerLimits::default_for_this_host(),
            object(&case["placement"]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(executor::availability_probe(&settings), case["availability"]);
        assert_eq!(executor::pod_security_probe(&settings), case["podSecurity"]);
        assert_eq!(
            serde_json::to_string(&executor::pod_security_probe(&settings)).unwrap(),
            serde_json::to_string(&case["podSecurity"]).unwrap()
        );
    }
    for case in file["refusals"].as_array().unwrap() {
        let refused = KubernetesError::new(text(&case["message"]), u16::try_from(int(&case["status"])).unwrap());
        assert_eq!(executor::forbidden_by_role(&refused), case["forbiddenByRole"].as_bool().unwrap(), "{refused:?}");
        assert_eq!(executor::pod_security_refused(&refused), case["podSecurityRefused"].as_bool().unwrap());
    }
}

#[test]
fn what_a_pod_s_status_says() {
    let cases = read_json("kubernetes/statuses.json");
    for case in cases.as_array().unwrap() {
        let pod = &case["pod"];
        assert_eq!(pods::failure(pod).as_deref(), case["failure"].as_str(), "failure of {pod}");
        assert_eq!(pods::pending(pod), text(&case["pending"]), "pending of {pod}");
        assert_eq!(pods::receiving(pod), case["receiving"].as_bool().unwrap(), "receiving of {pod}");
        let terminated = pods::scanner_terminated(pod);
        assert_eq!(terminated.clone().unwrap_or(Value::Null), case["scannerTerminated"], "terminated of {pod}");
        if let Some(terminated) = terminated {
            assert_eq!(pods::killed(&terminated), case["killed"].as_bool().unwrap(), "killed of {pod}");
        }
    }
}

#[test]
fn the_api_server_s_address_accepted_or_refused() {
    let cases = read_json("kubernetes/addresses.json");
    for case in cases.as_array().unwrap() {
        let (host, port) = (case["host"].as_str().map(str::to_owned), case["port"].as_str().map(str::to_owned));
        let dns = object(&case["dns"]);
        let resolved = address::of(
            |name| match name {
                "KUBERNETES_SERVICE_HOST" => host.clone(),
                "KUBERNETES_SERVICE_PORT" => port.clone(),
                _ => None,
            },
            |name| {
                dns.get(name).map(|found| {
                    found.as_array().unwrap().iter().map(|literal| text(literal).parse::<IpAddr>().unwrap()).collect()
                })
            },
        );
        match resolved {
            Ok(address) => assert_eq!(address.uri(), text(&case["uri"]), "{case}"),
            Err(refused) => assert_eq!(refused, text(&case["refused"]), "{case}"),
        }
    }
}

#[test]
fn the_exec_stream_sorted_by_channel() {
    let cases = read_json("kubernetes/exec-channels.json");
    for case in cases.as_array().unwrap() {
        let name = text(&case["name"]);
        let ceiling = u64::try_from(int(&case["ceiling"])).unwrap();
        let sunk = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut channels = if case["sink"].as_bool().unwrap() {
            ExecChannels::to_sink(Box::new(Shared(sunk.clone())), ceiling)
        } else {
            ExecChannels::new(ceiling)
        };
        let mut accepted = 0;
        for fragment in case["fragments"].as_array().unwrap() {
            accepted += 1;
            if !channels.accept(&bytes(&fragment["bytes"]), fragment["last"].as_bool().unwrap()).unwrap() {
                break;
            }
        }
        assert_eq!(accepted, int(&case["accepted"]), "{name}: fragments read");
        assert_eq!(channels.stdout(), bytes(&case["stdout"]), "{name}: stdout");
        assert_eq!(*sunk.lock().unwrap(), bytes(&case["sunk"]), "{name}: sunk");
        assert_eq!(channels.stderr(), text(&case["stderr"]), "{name}: stderr");
        assert_eq!(channels.over_ceiling(), case["overCeiling"].as_bool().unwrap(), "{name}: over the ceiling");
        match channels.exit_code() {
            Ok(code) => assert_eq!(code.map(i64::from), case["exitCode"].as_i64(), "{name}: exit code"),
            Err(refused) => {
                assert_eq!(refused.message, text(&case["refused"]["message"]), "{name}: refusal");
                assert_eq!(i64::from(refused.status), int(&case["refused"]["status"]), "{name}: status");
            }
        }
        assert_eq!(channels.exit_code().is_err(), case.get("refused").is_some(), "{name}: refused or not");
    }
}

struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn what_the_holder_sends_back_read_as_files_or_refused() {
    let cases = read_json("kubernetes/archives.json");
    for case in cases.as_array().unwrap() {
        let name = text(&case["name"]);
        let root = tempfile::tempdir().unwrap();
        let mount = root.path().join("mount");
        std::fs::create_dir_all(mount.join("real")).unwrap();
        std::fs::create_dir_all(root.path().join("elsewhere")).unwrap();
        for (path, link) in object(&case["existing"]) {
            let at = mount.join(&path);
            std::fs::create_dir_all(at.parent().unwrap()).unwrap();
            match text(&link) {
                "" => std::fs::write(&at, "old").unwrap(),
                link => std::os::unix::fs::symlink(link, &at).unwrap(),
            }
        }
        let ceiling = u64::try_from(int(&case["ceiling"])).unwrap();
        let archive = bytes(&case["archive"]);
        match archives::extract_written(&archive[..], &mount, ceiling) {
            Ok(written) => {
                let expected: Vec<&str> = case["written"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{name}: Java refused: {}", case["refused"]))
                    .iter()
                    .map(text)
                    .collect();
                assert_eq!(written, expected, "{name}: written");
                let mut files = Map::new();
                collect(&mount, &mount, &mut files);
                assert_eq!(Value::Object(files), case["files"], "{name}: the mount afterwards");
            }
            Err(refused) => {
                assert_eq!(refused.to_string(), case["refused"].as_str().unwrap_or("(Java accepted it)"), "{name}")
            }
        }
    }
}

/// Every regular file under `directory`, relative to `root`, with its text — links not followed.
fn collect(root: &Path, directory: &Path, into: &mut Map<String, Value>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
        if kind.is_dir() {
            collect(root, &path, into);
        } else if kind.is_file() {
            let relative = path.strip_prefix(root).unwrap().display().to_string();
            into.insert(relative, Value::String(std::fs::read_to_string(&path).unwrap()));
        }
    }
}

#[tokio::test]
async fn what_the_choice_refuses_at_start() {
    let file = read_json("kubernetes/choice.json");
    for case in file["probeTargets"].as_array().unwrap() {
        let configured = text(&case["configured"]);
        let cluster = text(&case["cluster"]).strip_prefix("https://").unwrap().to_owned();
        let (host, port) = cluster.rsplit_once(':').unwrap();
        let cluster = ClusterAddress { host: host.to_owned(), port: port.parse().unwrap() };
        match address::probe_target(configured, || Ok(cluster)) {
            Ok(target) => {
                assert_eq!(target, text(&case["target"]), "{configured:?}");
                let (host, port) = address::address(&target).unwrap();
                assert_eq!(
                    (host.as_str(), i64::from(port)),
                    (text(&case["host"]), int(&case["port"])),
                    "{configured:?}"
                );
            }
            Err(refused) => {
                assert_eq!(refused, case["refused"].as_str().unwrap_or("(Java accepted it)"), "{configured:?}")
            }
        }
    }
    for case in file["placements"].as_array().unwrap() {
        let given = vectispire_domain::java::strip(text(&case["text"]));
        match choice::placement(given) {
            Ok(placement) => assert_eq!(Value::Object(placement), case["placement"], "{given:?}"),
            Err(refused) => assert_eq!(refused, case["refused"].as_str().unwrap_or("(Java accepted it)"), "{given:?}"),
        }
    }
    for case in file["kinds"].as_array().unwrap() {
        let kind = choice::kind(text(&case["configured"]));
        assert_eq!(kind, text(&case["kind"]));
        if let Some(refused) = case["refused"].as_str() {
            assert_eq!(choice::unknown_kind(&kind), refused);
        }
    }
    let context = choice::Context { matcher_database: "db".into(), own_user: Some("1000:1000".into()) };
    let never = || -> Result<_, String> { panic!("the cluster is not asked for when the settings are refused") };
    let unasked = || -> Result<ClusterAddress, String> { panic!("the address is not asked for") };
    let config = choice::KubernetesConfig { namespace: String::new(), ..Default::default() };
    let refused = choice::kubernetes(&config, &context, never, unasked).await.unwrap_err();
    assert_eq!(refused, text(&file["noNamespace"]));
    let config = choice::KubernetesConfig {
        namespace: "ns".into(),
        user: "1000:1000".into(),
        placement: "[]".into(),
        ..Default::default()
    };
    let refused = choice::kubernetes(&config, &context, never, unasked).await.unwrap_err();
    assert_eq!(refused, text(&file["placementNotAnObject"]));
    for case in file["resources"].as_array().unwrap() {
        let refused = choice::check_resources(int(&case["cpuMillis"]), int(&case["memoryMiB"])).err();
        assert_eq!(refused.as_deref(), case["refused"].as_str());
    }
}

#[test]
fn the_bounded_output_collected() {
    let file = read_json("kubernetes/collection.json");
    for probe in file["probes"].as_array().unwrap() {
        let bounded = output(&serde_json::json!({ "output": probe })).unwrap();
        assert_eq!(executor::collection_probe(&bounded), text(&probe["script"]), "the probe of {bounded:?}");
    }
    for case in file["answers"].as_array().unwrap() {
        let answer = text(&case["answer"]);
        let ceiling = u64::try_from(int(&case["ceiling"])).unwrap();
        let said = executor::probed(answer, ceiling);
        if case.get("thrown").is_some() {
            assert!(said.is_err(), "{answer:?}: Java throws, and the run fails; this read {said:?}");
            continue;
        }
        let settled = match said.unwrap_or_else(|error| panic!("{answer:?}: {error}")) {
            None => Value::Null,
            Some(OutputFile::Missing) => serde_json::json!({"kind": "missing"}),
            Some(OutputFile::NotRegular) => serde_json::json!({"kind": "notRegular"}),
            Some(OutputFile::TooLarge(size)) => serde_json::json!({"kind": "tooLarge", "size": size}),
            Some(OutputFile::Read(_)) => serde_json::json!({"kind": "read"}),
        };
        assert_eq!(settled, case["settled"], "{answer:?} within {ceiling}");
    }
}

/// An executor whose API server is never reached: what is decided before a pod is created.
fn unreachable_executor(registry_credentials: Option<std::path::PathBuf>) -> KubernetesExecutor {
    let api = KubernetesApi::with_token(
        "https://127.0.0.1:1",
        vectispire_domain::secret::Secret::new("t"),
        &vectispire_tls::TlsTrust::BuiltIn,
    )
    .unwrap();
    let settings = Settings::new(
        "ns",
        "a",
        executor::HELPER_IMAGE,
        "1000:1000",
        Duration::from_secs(60),
        ScannerLimits::default_for_this_host(),
        Map::new(),
        None,
        None,
    )
    .unwrap()
    .with_registry_credentials(registry_credentials);
    KubernetesExecutor::new(api, settings)
}

#[tokio::test]
async fn the_registry_login_mounted() {
    let cases = read_json("kubernetes/registry-login.json");
    let root = tempfile::tempdir().unwrap();
    for (index, case) in cases.as_array().unwrap().iter().enumerate() {
        let name = text(&case["name"]);
        let mounted = case["mounted"].as_bool().unwrap().then(|| {
            let directory = root.path().join(format!("secret-{index}"));
            std::fs::create_dir_all(&directory).unwrap();
            if let Some(config) = case["config"].as_str() {
                std::fs::write(directory.join("config.json"), config).unwrap();
            }
            directory
        });
        let executor = unreachable_executor(mounted.clone());
        for answer in case["references"].as_array().unwrap() {
            let reference = text(&answer["reference"]);
            let access = executor.registry_access_for(reference);
            assert_eq!(
                serde_json::json!({"registry": access.registry, "credentialsHeld": access.credentials_held}),
                answer["access"],
                "{name}: the access to {reference}"
            );
            match MountedPullCredentials::of(mounted.as_deref(), reference) {
                Err(unreadable) => {
                    let path = mounted.as_ref().unwrap().display().to_string();
                    let said = unreadable.to_string().replace(&path, "<configuration>");
                    assert_eq!(said, text(&answer["unreadable"]), "{name}: {reference}");
                    // And the run asking for that login fails with it, before any pod — never anonymously.
                    let mut run = ContainerRun::new(executor::HELPER_IMAGE, vec!["true".into()], vec![], "plugin x");
                    run.user = Some("1000:1000".into());
                    let login =
                        RegistryLogin { reference: reference.to_owned(), directory: root.path().join("logins") };
                    match executor.run_with(&run, &Extras { output: None, login: Some(login) }).await {
                        Err(ExtendedError::Failed { label, message }) => {
                            assert_eq!((label.as_str(), message.replace(&path, "<configuration>")), ("plugin x", said));
                        }
                        other => panic!("{name}: {reference}: {other:?}"),
                    }
                }
                Ok(None) => assert!(
                    answer.get("login").is_some_and(Value::is_null),
                    "{name}: {reference}: Java hands a login, this none"
                ),
                Ok(Some(credentials)) => {
                    let written = credentials.write_under(&root.path().join("written")).unwrap();
                    let file = std::fs::read_to_string(written.join("config.json")).unwrap();
                    vectispire_container::pull_credentials::erase(Some(&written));
                    assert!(!written.exists(), "{name}: erased");
                    let said =
                        format!("cosign said: {file} robot:s3cret-pull s3cret-pull tok-123 b3RoZXI6b3RoZXI= other");
                    assert_eq!(
                        serde_json::json!({
                            "registry": credentials.registry(),
                            "configuration": file,
                            "redacted": credentials.redact(&said),
                        }),
                        answer["login"],
                        "{name}: {reference}"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn a_bounded_output_without_its_user_is_refused_before_any_pod() {
    let output = BoundedOutput::new("/out", 4096, executor::HELPER_IMAGE, "report.json").unwrap();
    let run = ContainerRun::new(executor::HELPER_IMAGE, vec!["true".into()], vec![], "plugin x");
    let refused = unreachable_executor(None).run_with(&run, &Extras { output: Some(output), login: None }).await;
    assert!(
        matches!(&refused, Err(ExtendedError::Refused(message)) if message == "A bounded output needs the user it belongs to."),
        "{refused:?}"
    );
}

/// An image target on Kubernetes (decision 0045 §8), against `KubernetesReferenceSetTest.theImageCopy`: the platform as
/// crane is asked for it or the refusal before any pod, the copy's run, what crane's end becomes, and the copied
/// archive checked against the platform with the copy's own sentence.
#[test]
fn the_image_copy() {
    use vectispire_container::image_archive;
    use vectispire_kubernetes::image_copy;

    let file = read_json("kubernetes/image-copy.json");
    let into = Path::new("/w/.image-copy-1/image");
    let login = Path::new("/w/.image-copy-1/login");
    let requests = file["requests"].as_array().unwrap();
    assert!(requests.len() >= 20, "the requests' cases are read");
    for case in requests {
        let reference = text(&case["reference"]);
        let platform = text(&case["platform"]);
        let normalized = image_archive::normalized(platform);
        if let Some(refused) = case.get("refused") {
            assert_eq!(normalized.as_ref().err().map(String::as_str), Some(text(refused)), "{platform:?}");
            continue;
        }
        let normalized = normalized.unwrap();
        assert_eq!(normalized.as_deref(), case["normalized"].as_str(), "{platform:?}");
        let settings =
            unreachable_executor(None).settings().clone().with_copy_image(case["copyImage"].as_str().unwrap_or(""));
        let (run, extras) = image_copy::request(&settings.copy_image, reference, normalized.as_deref(), into, login);
        let expected = &case["run"];
        assert_eq!(run.image, text(&expected["image"]), "{platform:?}");
        assert_eq!(run.label, text(&expected["label"]));
        assert_eq!(run.network, expected["network"].as_bool().unwrap());
        assert_eq!(run.as_root, expected["asRoot"].as_bool().unwrap());
        assert_eq!(run.user.as_deref(), expected["user"].as_str());
        assert_eq!(run.timeout.map(|timeout| timeout.as_secs()), expected["timeoutSeconds"].as_u64());
        let strings = |value: &Value| -> Vec<String> {
            value.as_array().unwrap().iter().map(|part| text(part).to_owned()).collect()
        };
        assert_eq!(run.entrypoint, Some(strings(&expected["entrypoint"])));
        assert_eq!(run.command, strings(&expected["command"]), "{reference} {platform:?}");
        let mounts: Vec<Mount> = expected["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|mount| Mount {
                source: text(&mount["source"]).to_owned(),
                target: text(&mount["target"]).to_owned(),
                read_only: mount["readOnly"].as_bool().unwrap(),
                writable_bytes: u64::try_from(int(&mount["writableBytes"])).unwrap(),
            })
            .collect();
        assert_eq!(run.mounts, mounts);
        let handed = extras.login.unwrap();
        assert_eq!(handed.reference, text(&expected["login"]["reference"]));
        assert_eq!(handed.directory, Path::new(text(&expected["login"]["directory"])));
        assert!(extras.output.is_none());
    }

    let ends = file["ends"].as_array().unwrap();
    assert!(ends.len() >= 12, "the ends' cases are read");
    for case in ends {
        let failure = image_copy::failure(
            text(&case["reference"]),
            case["platform"].as_str().unwrap_or(""),
            int(&case["exitCode"]),
            text(&case["stderr"]),
            case["written"].as_bool().unwrap(),
        );
        assert_eq!(failure.as_deref(), case["failure"].as_str(), "{case}");
    }

    let archives = file["archives"].as_array().unwrap();
    assert!(archives.len() >= 10, "the archives' cases are read");
    let reference = format!("alpine@sha256:{}", "1".repeat(64));
    for case in archives {
        let platform = text(&case["platform"]);
        let entries = object(&case["entries"]);
        let refusal = image_archive::requested(platform).unwrap().and_then(|asked| {
            image_archive::refusal_by(image_archive::Exporter::Copy, &reference, platform, &asked, |name, limit| {
                match entries.get(name) {
                    None => Ok(None),
                    Some(content) if text(content).len() > limit => Err(format!("{name} is too large")),
                    Some(content) => Ok(Some(text(content).as_bytes().to_vec())),
                }
            })
        });
        assert_eq!(refusal.as_deref(), case["refusal"].as_str(), "{}", text(&case["name"]));
    }
}
