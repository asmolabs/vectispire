//! `ContainerRunner::export_image` — `ImageExportTest` against a stub daemon (what the save asks for, what is done
//! with an archive of another platform: a daemon older than API 1.48 ignores the save's platform, which is what the
//! stub does), and `ContainerRunnerIntegrationTest.theExportHoldsThePlatformAsked` against the real one, through
//! the socket proxy as the composition configures it.
//!
//! The real-daemon test needs Docker, and fails without it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use vectispire_container::{ContainerRunner, ExportError, ScannerLimits, image_archive};
use vectispire_testkit::proxy::SocketProxy;

const REFERENCE: &str =
    "registry.example:5000/team/app@sha256:abababababababababababababababababababababababababababababababab";
const CONFIG: &str = "blobs/sha256/c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";

/// Alpine 3.20.3 by its **index** digest — a multi-architecture image, as `ContainerRunnerIntegrationTest` exports.
const MULTI_ARCH_ALPINE: &str = "alpine@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a";

#[derive(Default)]
struct Stub {
    pulls: Vec<String>,
    saves: Vec<String>,
    save_status: u16,
    save_answer: Vec<u8>,
}

/// A daemon on a loopback port that answers a pull, and a save with whatever archive the test gave it.
fn stub_daemon(save_status: u16, save_answer: Vec<u8>) -> (String, Arc<Mutex<Stub>>) {
    let stub = Arc::new(Mutex::new(Stub { save_status, save_answer, ..Stub::default() }));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("tcp://{}", listener.local_addr().unwrap());
    let shared = Arc::clone(&stub);
    std::thread::spawn(move || {
        for connection in listener.incoming() {
            let Ok(mut connection) = connection else { return };
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") && connection.read(&mut byte).unwrap_or(0) == 1 {
                request.push(byte[0]);
            }
            let request = String::from_utf8_lossy(&request).into_owned();
            let target = request.split(' ').nth(1).unwrap_or_default().to_owned();
            let (path, query) = target.split_once('?').unwrap_or((&target, ""));
            // bollard's own calls may carry an API version; the save does not.
            let path = match path.strip_prefix("/v1.") {
                Some(versioned) => &versioned[versioned.find('/').unwrap()..],
                None => path,
            };
            let query = percent_encoding::percent_decode_str(query).decode_utf8_lossy().into_owned();
            let mut stub = shared.lock().unwrap();
            let (status, body) = match path {
                "/images/create" => {
                    stub.pulls.push(query);
                    (200, b"{\"status\":\"Status: Downloaded newer image for app\"}\n".to_vec())
                }
                "/images/get" => {
                    stub.saves.push(query);
                    (stub.save_status, stub.save_answer.clone())
                }
                _ => (404, b"{\"message\":\"not stubbed\"}".to_vec()),
            };
            drop(stub);
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = connection.write_all(head.as_bytes());
            let _ = connection.write_all(&body);
        }
    });
    (address, stub)
}

/// A ustar archive of `entries`, closed — the shape `TarBuilder` writes on the Java side.
fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, content) in entries {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
        header[156] = b'0';
        header[257..265].copy_from_slice(b"ustar\x0000");
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(content);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

fn archive_of(architecture: &str) -> Vec<u8> {
    let config = format!("{{\"architecture\":\"{architecture}\",\"os\":\"linux\"}}");
    let manifest = format!("[{{\"Config\":\"{CONFIG}\",\"RepoTags\":null,\"Layers\":[]}}]");
    tar(&[(CONFIG, config.as_bytes()), ("manifest.json", manifest.as_bytes())])
}

fn runner(address: &str) -> ContainerRunner {
    ContainerRunner::connect(Some(address), ScannerLimits::default_for_this_host()).unwrap()
}

#[tokio::test]
async fn the_save_names_the_platform_the_pull_named_as_an_oci_platform() {
    let (address, stub) = stub_daemon(200, archive_of("amd64"));
    let workspace = tempfile::tempdir().unwrap();
    let destination = workspace.path().join("image.tar");

    runner(&address).export_image(REFERENCE, "linux/amd64", &destination).await.unwrap();

    let stub = stub.lock().unwrap();
    assert!(stub.pulls.len() == 1 && stub.pulls[0].contains("platform=linux/amd64"), "{:?}", stub.pulls);
    assert_eq!(stub.saves, [format!("names={REFERENCE}&platform={{\"os\":\"linux\",\"architecture\":\"amd64\"}}")]);
    assert_eq!(std::fs::read(&destination).unwrap(), stub.save_answer);
}

#[tokio::test]
async fn an_archive_of_another_architecture_fails_the_export_and_is_not_left_behind() {
    let (address, _stub) = stub_daemon(200, archive_of("arm64"));
    let workspace = tempfile::tempdir().unwrap();
    let destination = workspace.path().join("image.tar");

    let error = runner(&address).export_image(REFERENCE, "linux/amd64", &destination).await.unwrap_err();

    assert!(matches!(error, ExportError::Platform(_)), "{error:?}");
    assert_eq!(
        error.to_string(),
        format!(
            "The Docker daemon exported {REFERENCE} as linux/arm64 where linux/amd64 was asked: a daemon selects the \
             platform of a save from API 1.48 on, and another architecture is not scanned in place of the one asked \
             for."
        )
    );
    assert!(!destination.exists());
}

#[tokio::test]
async fn an_archive_that_cannot_be_read_fails_the_export_rather_than_passing_unchecked() {
    let (address, _stub) = stub_daemon(200, "not a tar archive at all".repeat(40).into_bytes());
    let workspace = tempfile::tempdir().unwrap();
    let destination = workspace.path().join("image.tar");

    let error = runner(&address).export_image(REFERENCE, "linux/amd64", &destination).await.unwrap_err();

    assert_eq!(
        error.to_string(),
        format!(
            "The archive exported for {REFERENCE} could not be checked for linux/amd64: it is not a tar archive. It is \
             not scanned unchecked."
        )
    );
    assert!(!destination.exists());
}

#[tokio::test]
async fn without_a_platform_the_daemon_chooses_at_the_save_as_at_the_pull_and_nothing_is_checked() {
    let (address, stub) = stub_daemon(200, archive_of("arm64"));
    let workspace = tempfile::tempdir().unwrap();
    let destination = workspace.path().join("image.tar");

    runner(&address).export_image(REFERENCE, "", &destination).await.unwrap();

    assert_eq!(stub.lock().unwrap().saves, [format!("names={REFERENCE}")]);
    assert!(destination.exists());
}

#[tokio::test]
async fn a_malformed_platform_is_refused_before_the_daemon_is_asked_anything() {
    let (address, stub) = stub_daemon(200, archive_of("amd64"));
    let workspace = tempfile::tempdir().unwrap();

    let error = runner(&address)
        .export_image(REFERENCE, "linux/amd64/v1/x", &workspace.path().join("image.tar"))
        .await
        .unwrap_err();

    assert!(error.to_string().starts_with("The image platform \"linux/amd64/v1/x\" is not of the form"), "{error}");
    let stub = stub.lock().unwrap();
    assert!(stub.pulls.is_empty() && stub.saves.is_empty());
}

#[tokio::test]
async fn a_save_the_daemon_refuses_carries_the_daemon_s_own_sentence() {
    let (address, _stub) = stub_daemon(404, b"{\"message\":\"no suitable export target found\"}".to_vec());
    let workspace = tempfile::tempdir().unwrap();

    let error =
        runner(&address).export_image(REFERENCE, "linux/amd64", &workspace.path().join("image.tar")).await.unwrap_err();

    assert_eq!(error.to_string(), format!("could not export {REFERENCE}: no suitable export target found"));
}

/// The architecture of the one image the archive holds, read as the daemon wrote it.
fn architecture_of(archive: &std::path::Path) -> String {
    let manifest: serde_json::Value = serde_json::from_slice(
        &image_archive::entry(archive, "manifest.json", image_archive::MANIFEST_LIMIT).unwrap().unwrap(),
    )
    .unwrap();
    let images = manifest.as_array().unwrap();
    assert_eq!(images.len(), 1, "{manifest}");
    let config = images[0]["Config"].as_str().unwrap();
    let config: serde_json::Value =
        serde_json::from_slice(&image_archive::entry(archive, config, image_archive::CONFIG_LIMIT).unwrap().unwrap())
            .unwrap();
    config["architecture"].as_str().unwrap().to_owned()
}

/// On Docker Desktop's containerd image store, an arm64 host's save without a platform exported the arm64 variant
/// once both were pulled, and failed on "content digest … not found" while only amd64 was. Both variants are pulled
/// here, so a save without one would answer the host's for one of the two.
#[tokio::test(flavor = "multi_thread")]
async fn an_image_is_exported_for_the_platform_asked_whatever_the_host_s_both_ways_round() {
    let proxy = SocketProxy::start();
    let runner = runner(&proxy.address);
    assert!(
        runner.is_available().await,
        "this suite needs a Docker daemon; it does not skip itself when there is none"
    );
    let workspace = tempfile::tempdir().unwrap();
    for (platform, architecture) in [("linux/amd64", "amd64"), ("linux/arm64", "arm64")] {
        let archive = workspace.path().join(format!("{architecture}.tar"));
        runner.export_image(MULTI_ARCH_ALPINE, platform, &archive).await.unwrap();
        assert_eq!(architecture_of(&archive), architecture, "the configuration exported for {platform}");
    }
    // And on the socket itself, as an agent beside its daemon reaches it.
    let socket = runner_on_the_socket();
    let archive = workspace.path().join("socket.tar");
    socket.export_image(MULTI_ARCH_ALPINE, "linux/amd64", &archive).await.unwrap();
    assert_eq!(architecture_of(&archive), "amd64");
}

fn runner_on_the_socket() -> ContainerRunner {
    ContainerRunner::connect(Some("unix:///var/run/docker.sock"), ScannerLimits::default_for_this_host()).unwrap()
}
