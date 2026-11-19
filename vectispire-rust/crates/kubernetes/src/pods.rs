//! The pod one [`ContainerRun`] becomes (decision 0045), and what its status says went wrong — `ScanPods`.
//!
//! **Three containers.** `receive`, an init container, installs a static busybox for the wrapper and waits for the
//! workspace, so the scanner never starts on a half-copied tree. `scanner` is the request, in the closed shape.
//! `holder` outlives it so its output can be read over `exec`: an ordinary container, since a native sidecar is
//! stopped with the pod — the spike's correction.
//!
//! **Standard output goes to a file, never to the log.** The kubelet rotates logs, and a report cut by a rotation and
//! read leniently is the absent-versus-empty defect (0007). So the scanner runs through the busybox shell,
//! `exec "$@" >stdout 2>stderr`, which needs the program named — the declared entrypoint. A run that declares none
//! keeps its image's entrypoint, and its output goes to the log, read as a diagnostic and nothing more.
//!
//! Held to Java's `ScanPods` by `reference/kubernetes/pods.json` and `statuses.json`.

use crate::executor::Settings;
use crate::json;
use serde_json::{Map, Value, json};
use std::time::Duration;
use vectispire_container::{ContainerRun, Mount, SCANNER_ENVIRONMENT, SCRATCH_HOME, SCRATCH_MEGABYTES, STDERR_BYTES};

pub const RECEIVE: &str = "receive";
pub const SCANNER: &str = "scanner";
pub const HOLDER: &str = "holder";

/// The workspace, each mount a subdirectory `m<i>` of it.
pub const WORK: &str = "/work";
/// Written by the agent once every mount is copied in: the scanner starts after it.
pub const RECEIVED: &str = "/work/.received";
/// The wrapper's busybox and the scanner's two streams.
pub const TOOLS: &str = "/vectispire";
pub const BUSYBOX: &str = "/vectispire/busybox";
pub const STDOUT: &str = "/vectispire/out/stdout";
pub const STDERR: &str = "/vectispire/out/stderr";

pub const LABEL_AGENT: &str = "vectispire.dev/agent";
pub const LABEL_NETWORK: &str = "vectispire.dev/network";
pub const LABEL_SCANNER: &str = "vectispire.dev/scanner";
/// The value a NetworkPolicy denies all traffic to; `egress` is the one allowed out (0045 §5).
pub const OFFLINE: &str = "none";
pub const ONLINE: &str = "egress";

/// Where the receiving container sees the cache volume, read-write, to seed it.
pub const CACHE: &str = "/matcher-cache";
/// The cache volume's directory of generations, as the volume's sub-path and under [`CACHE`].
pub const GENERATIONS: &str = "generations";

/// Where a run asking for a registry's login finds it — `ContainerRunner.REGISTRY_LOGIN_MOUNT`: a mount there names
/// itself to the tool through `DOCKER_CONFIG`, as on Docker. Registry logins (plugins, cosign) are not ported to the
/// Rust agent yet; the pod is shaped for them already, so that it is held to Java's whole.
pub const REGISTRY_LOGIN_MOUNT: &str = "/trust/registry";

/// Waiting reasons that will not resolve themselves: the run fails now rather than at its timeout.
const CANNOT_START: [&str; 7] = [
    "ErrImagePull",
    "ImagePullBackOff",
    "InvalidImageName",
    "ErrImageNeverPull",
    "CreateContainerConfigError",
    "CreateContainerError",
    "RunContainerError",
];

/// How long the pod outlives what the agent waits for, if the agent dies with it: a backstop, not a timeout.
const BACKSTOP: Duration = Duration::from_secs(10 * 60);

const MIB: u64 = 1024 * 1024;
/// The work volume's margin over what it holds and what the scanner may write.
const WORK_MARGIN: u64 = 256 * MIB;
/// The tools volume's margin over the busybox and the two streams.
const TOOLS_MARGIN: u64 = 64 * MIB;

/// The exit code of a process ended by `SIGKILL`: 128 plus the signal's number.
pub const KILLED: i32 = 137;

/// Where one mount's content comes from in the pod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountSource {
    /// A generation of the matcher's database, mounted from the cache volume rather than copied.
    pub cached: bool,
    /// For a copied mount, the name its content has under its subdirectory — empty for a directory, the file's name
    /// for a file; for a cached one, the generation's name.
    pub name: String,
}

/// How much a writable mount may hold, and so what its copy back accepts.
pub fn ceiling(mount: &Mount, output_bytes: u64) -> u64 {
    if mount.writable_bytes > 0 { mount.writable_bytes } else { output_bytes }
}

/// What the scanner may write into the work volume: each writable mount's declared size, or the output ceiling for
/// one that declares none — and the output ceiling at least, as before sizes were declared.
pub fn writable(request: &ContainerRun, output_bytes: u64) -> u64 {
    let total = request
        .mounts
        .iter()
        .filter(|mount| !mount.read_only)
        .fold(0u64, |total, mount| total.saturating_add(ceiling(mount, output_bytes)));
    total.max(output_bytes)
}

/// The pod `request` becomes.
///
/// `work_bytes` is what the copied mounts hold: the work volume's size is that, plus what the scanner may write into
/// its writable ones ([`writable`]) and a margin — past it the pod is evicted, a failure (review of 2026-10-26, L3).
/// `transfers` is what copying the mounts in and back may take, on top of the start: the pod's deadline has to
/// outlast it, or a large mount is killed by the backstop while the agent still waits for it.
#[allow(clippy::too_many_arguments)] // Java's signature, kept so the reference set reads it one to one.
pub fn pod(
    name: &str,
    request: &ContainerRun,
    settings: &Settings,
    uid: u64,
    gid: u64,
    mounts: &[MountSource],
    work_bytes: u64,
    timeout: Duration,
    transfers: Duration,
) -> Value {
    let lifetime = settings.start_timeout.saturating_add(transfers).saturating_add(timeout).saturating_add(BACKSTOP);
    let lifetime = lifetime.as_secs();
    let cached = mounts.iter().any(|mount| mount.cached);
    let output_bytes = u64::try_from(settings.limits.output_bytes).unwrap_or(u64::MAX);
    let memory = u64::try_from(settings.limits.memory).unwrap_or(0);

    let mut pod_security = json!({
        "runAsNonRoot": true,
        "runAsUser": uid,
        "runAsGroup": gid,
        "seccompProfile": {"type": "RuntimeDefault"},
    });
    let mut spec = Map::new();
    spec.insert("restartPolicy".into(), json!("Never"));
    // The scan pod reaches nothing of the API: the agent's token stays in the agent's pod.
    spec.insert("automountServiceAccountToken".into(), json!(false));
    spec.insert("enableServiceLinks".into(), json!(false));
    spec.insert("activeDeadlineSeconds".into(), json!(lifetime));
    spec.insert("terminationGracePeriodSeconds".into(), json!(0));
    spec.insert("securityContext".into(), Value::Null);
    for (field, value) in &settings.placement {
        spec.insert(field.clone(), value.clone());
    }
    if cached {
        // Writable by the scan user whatever the volume's driver created it as, and relabelled only when its root does
        // not match already: a recursive change over gigabytes at every pod would cost a minute.
        if let Some(security) = pod_security.as_object_mut() {
            security.insert("fsGroup".into(), json!(gid));
            security.insert("fsGroupChangePolicy".into(), json!("OnRootMismatch"));
        }
        if let Some(cache) = &settings.cache {
            on_node(&mut spec, &cache.node);
        }
    }
    spec.insert("securityContext".into(), pod_security);

    let mut volumes = vec![
        json!({"name": "work", "emptyDir": {"sizeLimit": work_bytes
            .saturating_add(writable(request, output_bytes))
            .saturating_add(WORK_MARGIN)
            .to_string()}}),
        // The busybox, the standard output up to its ceiling and the error stream: past it the pod is evicted, a
        // failure, never a truncation.
        json!({"name": "tools", "emptyDir": {"sizeLimit": output_bytes
            .saturating_add(STDERR_BYTES as u64)
            .saturating_add(TOOLS_MARGIN)
            .to_string()}}),
        memory_volume("tmp", &format!("{SCRATCH_MEGABYTES}Mi")),
        memory_volume("home", &format!("{SCRATCH_MEGABYTES}Mi")),
    ];
    if cached && let Some(cache) = &settings.cache {
        volumes.push(json!({"name": "matcher-cache", "persistentVolumeClaim": {"claimName": cache.claim}}));
    }
    spec.insert("volumes".into(), Value::Array(volumes));

    // **The scanner's memory, not a helper's**: it writes every mount to disk, and the kernel charges the page cache
    // of those writes to it. At 64 MiB it was OOMKilled a few seconds into the matcher's 3 GB database, and at 256 MiB
    // a minute in (measured, k3s on Docker Desktop's kernel); the scanner's limit carried it in 21 s. It costs the pod
    // nothing: an init container's request is counted against the containers' as a maximum, not added to them.
    let mut receive =
        container(RECEIVE, &settings.helper_image, uid, gid, memory.checked_div(MIB).unwrap_or(0).max(64));
    command(
        &mut receive,
        &[
            "sh",
            "-c",
            &format!(
                "mkdir -p {TOOLS}/out && cp /bin/busybox {BUSYBOX} && until [ -f {RECEIVED} ]; do sleep 0.2; done"
            ),
        ],
    );
    mount(&mut receive, "work", WORK, false, None);
    mount(&mut receive, "tools", TOOLS, false, None);
    if cached {
        mount(&mut receive, "matcher-cache", CACHE, false, None);
    }
    spec.insert("initContainers".into(), json!([receive]));

    let mut scanner = Map::new();
    scanner.insert("name".into(), json!(SCANNER));
    scanner.insert("image".into(), json!(request.image));
    scanner.insert("imagePullPolicy".into(), json!("IfNotPresent"));
    match &request.entrypoint {
        Some(entrypoint) => {
            let wrapper = format!("exec \"$@\" >{STDOUT} 2>{STDERR}");
            let wrapped: Vec<&str> = [BUSYBOX, "sh", "-c", wrapper.as_str(), "scanner"]
                .into_iter()
                .chain(entrypoint.iter().map(String::as_str))
                .chain(request.command.iter().map(String::as_str))
                .collect();
            command(&mut scanner, &wrapped);
        }
        None => {
            scanner.insert("args".into(), json!(request.command));
        }
    }
    let mut environment: Vec<Value> =
        SCANNER_ENVIRONMENT.iter().map(|(name, value)| json!({"name": name, "value": value})).collect();
    // Named by the mount itself, as the Docker executor names it beside its bind: one constant, both sides.
    if request.mounts.iter().any(|mount| mount.target == REGISTRY_LOGIN_MOUNT) {
        environment.push(json!({"name": "DOCKER_CONFIG", "value": REGISTRY_LOGIN_MOUNT}));
    }
    scanner.insert("env".into(), Value::Array(environment));
    let memory_text = settings.limits.memory.to_string();
    let cpu = format!("{}m", settings.limits.nano_cpus.checked_div(1_000_000).unwrap_or(0).max(1));
    // Requests equal to limits: what the scanner is promised is what it may take.
    scanner.insert(
        "resources".into(),
        json!({"limits": {"memory": memory_text, "cpu": cpu}, "requests": {"memory": memory_text, "cpu": cpu}}),
    );
    scanner.insert("securityContext".into(), closed_shape(uid, gid));
    for (index, (requested, source)) in request.mounts.iter().zip(mounts).enumerate() {
        if source.cached {
            let sub_path = format!("{GENERATIONS}/{}", source.name);
            mount(&mut scanner, "matcher-cache", &requested.target, true, Some(&sub_path));
        } else {
            let sub_path =
                if source.name.is_empty() { format!("m{index}") } else { format!("m{index}/{}", source.name) };
            mount(&mut scanner, "work", &requested.target, requested.read_only, Some(&sub_path));
        }
    }
    mount(&mut scanner, "tools", TOOLS, false, None);
    mount(&mut scanner, "tmp", "/tmp", false, None);
    mount(&mut scanner, "home", SCRATCH_HOME, false, None);

    let mut holder = container(HOLDER, &settings.helper_image, uid, gid, 32);
    command(&mut holder, &["sleep", &lifetime.to_string()]);
    mount(&mut holder, "work", WORK, true, None);
    mount(&mut holder, "tools", TOOLS, true, None);
    spec.insert("containers".into(), json!([scanner, holder]));

    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "labels": {
                "app.kubernetes.io/managed-by": "vectispire-agent",
                LABEL_AGENT: settings.agent,
                LABEL_NETWORK: if request.network { ONLINE } else { OFFLINE },
                LABEL_SCANNER: label_value(&request.label),
            },
        },
        "spec": spec,
    })
}

/// What makes the pod's run hopeless, while it is still going: an image that cannot be pulled, a container that
/// cannot be created, a pod failed or evicted. `None` while it may still succeed.
pub fn failure(pod: &Value) -> Option<String> {
    let status = json::path(Some(pod), "status");
    if json::text(json::path(status, "phase")) == "Failed" {
        return Some(format!(
            "the pod failed ({}): {}",
            json::text_or(json::path(status, "reason"), "no reason"),
            json::text_or(json::path(status, "message"), "no message")
        ));
    }
    for kind in ["initContainerStatuses", "containerStatuses"] {
        for container in json::children(json::path(status, kind)) {
            let state = json::path(Some(container), "state");
            let waiting = json::path(state, "waiting");
            let reason = json::text_or(json::path(waiting, "reason"), "");
            if CANNOT_START.contains(&reason.as_str()) {
                return Some(format!(
                    "its {} container could not start ({reason}): {}",
                    json::text(json::path(Some(container), "name")),
                    json::text_or(json::path(waiting, "message"), "no message")
                ));
            }
            let terminated = json::path(state, "terminated");
            if kind == "initContainerStatuses"
                && terminated.is_some()
                && json::int(json::path(terminated, "exitCode")) != 0
            {
                return Some(format!(
                    "its {} container exited {}: {}",
                    json::text(json::path(Some(container), "name")),
                    json::int(json::path(terminated, "exitCode")),
                    json::text_or(json::path(terminated, "reason"), "")
                ));
            }
        }
    }
    None
}

/// Why the pod is not scheduled yet, for a timeout's message: the scheduler's own words.
pub fn pending(pod: &Value) -> String {
    let status = json::path(Some(pod), "status");
    for condition in json::children(json::path(status, "conditions")) {
        let condition = Some(condition);
        if json::text(json::path(condition, "type")) == "PodScheduled"
            && json::text(json::path(condition, "status")) == "False"
        {
            let reason = json::text(json::path(condition, "reason"));
            return format!("not scheduled: {}", json::text_or(json::path(condition, "message"), &reason));
        }
    }
    format!("phase {}", json::text_or(json::path(status, "phase"), "unknown"))
}

/// Is the receiving init container running, ready for the workspace?
pub fn receiving(pod: &Value) -> bool {
    let status = json::path(Some(pod), "status");
    json::children(json::path(status, "initContainerStatuses")).into_iter().any(|container| {
        json::text(json::path(Some(container), "name")) == RECEIVE
            && json::has(json::path(Some(container), "state"), "running")
    })
}

/// The scanner's end, once it has ended: its exit code and the reason the runtime gives.
pub fn scanner_terminated(pod: &Value) -> Option<Value> {
    let status = json::path(Some(pod), "status");
    json::children(json::path(status, "containerStatuses")).into_iter().find_map(|container| {
        let state = json::path(Some(container), "state");
        (json::text(json::path(Some(container), "name")) == SCANNER && json::has(state, "terminated"))
            .then(|| json::path(state, "terminated").cloned().unwrap_or(Value::Null))
    })
}

/// Was the scanner killed rather than left to exit? `OOMKilled` when the runtime says so — but it does not always:
/// containerd learns of the kill from the cgroup's `memory.events` and of the exit from the reaped process, two
/// events on two paths, and a status the kubelet reads between them says `Error`, exit 137, and is not revised
/// (containerd#12260, closed unfixed). So the exit code is evidence too: nothing in the pod sends the scanner
/// `SIGKILL` but the kernel at its memory limit, or the kubelet stopping a pod that is failing anyway.
pub fn killed(terminated: &Value) -> bool {
    json::text(json::path(Some(terminated), "reason")) == "OOMKilled"
        || json::int(json::path(Some(terminated), "exitCode")) == KILLED
}

/// A label value: 63 characters of `[a-z0-9-._]`, starting and ending with an alphanumeric.
pub fn label_value(text: &str) -> String {
    let lowered = vectispire_domain::java::to_lower_root(text);
    // `[^a-z0-9._-]+` → `-`: a run of anything else is one dash.
    let mut value = String::with_capacity(lowered.len());
    let mut in_run = false;
    for c in lowered.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
            value.push(c);
            in_run = false;
        } else if !in_run {
            value.push('-');
            in_run = true;
        }
    }
    let alphanumeric = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    let trimmed: String = value.trim_start_matches(|c: char| !alphanumeric(c)).chars().take(63).collect();
    let trimmed = trimmed.trim_end_matches(|c: char| !alphanumeric(c));
    if trimmed.is_empty() { "scan".to_owned() } else { trimmed.to_owned() }
}

/// Requires `node`, the agent's, for a pod that mounts the cache volume: a ReadWriteOnce volume attaches to one node,
/// and a pod scheduled elsewhere waits on it until its start times out. Added to each of the operator's required
/// terms, which are ORed, so every one of them now also names the node — by its name, a field, since the hostname
/// label is not the node's name everywhere.
fn on_node(spec: &mut Map<String, Value>, node: &str) {
    if vectispire_domain::java::is_blank(node) {
        return;
    }
    let Some(affinity) = object_member(spec, "affinity") else { return };
    let Some(node_affinity) = object_member(affinity, "nodeAffinity") else { return };
    let Some(required) = object_member(node_affinity, "requiredDuringSchedulingIgnoredDuringExecution") else {
        return;
    };
    let terms = required.entry("nodeSelectorTerms").or_insert_with(|| Value::Array(Vec::new()));
    if !terms.is_array() {
        *terms = Value::Array(Vec::new());
    }
    let Some(terms) = terms.as_array_mut() else { return };
    if terms.is_empty() {
        terms.push(json!({}));
    }
    for term in terms.iter_mut() {
        if let Some(term) = term.as_object_mut() {
            let fields = term.entry("matchFields").or_insert_with(|| Value::Array(Vec::new()));
            if let Some(fields) = fields.as_array_mut() {
                fields.push(json!({"key": "metadata.name", "operator": "In", "values": [node]}));
            }
        }
    }
}

/// `object.has(name) ? object.get(name) : object.putObject(name)` — a member that is not an object (an operator's
/// placement written wrong, which Java's cast would refuse with an exception) is replaced by one.
fn object_member<'a>(object: &'a mut Map<String, Value>, name: &str) -> Option<&'a mut Map<String, Value>> {
    let member = object.entry(name).or_insert_with(|| Value::Object(Map::new()));
    if !member.is_object() {
        *member = Value::Object(Map::new());
    }
    member.as_object_mut()
}

fn container(name: &str, image: &str, uid: u64, gid: u64, memory_mib: u64) -> Map<String, Value> {
    let memory = format!("{memory_mib}Mi");
    let mut container = Map::new();
    container.insert("name".into(), json!(name));
    container.insert("image".into(), json!(image));
    container.insert("imagePullPolicy".into(), json!("IfNotPresent"));
    container.insert(
        "resources".into(),
        json!({"limits": {"memory": memory, "cpu": "100m"}, "requests": {"memory": memory, "cpu": "100m"}}),
    );
    container.insert("securityContext".into(), closed_shape(uid, gid));
    container
}

/// The closed shape's properties that Kubernetes expresses per container (0045 §2).
fn closed_shape(uid: u64, gid: u64) -> Value {
    json!({
        "runAsNonRoot": true,
        "runAsUser": uid,
        "runAsGroup": gid,
        "allowPrivilegeEscalation": false,
        "readOnlyRootFilesystem": true,
        "privileged": false,
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"},
    })
}

fn command(container: &mut Map<String, Value>, command: &[&str]) {
    container.insert("command".into(), json!(command));
}

fn mount(container: &mut Map<String, Value>, volume: &str, path: &str, read_only: bool, sub_path: Option<&str>) {
    let mut mount = json!({"name": volume, "mountPath": path, "readOnly": read_only});
    if let (Some(sub_path), Some(object)) = (sub_path, mount.as_object_mut()) {
        object.insert("subPath".into(), json!(sub_path));
    }
    if let Some(mounts) = container.entry("volumeMounts").or_insert_with(|| Value::Array(Vec::new())).as_array_mut() {
        mounts.push(mount);
    }
}

fn memory_volume(name: &str, size: &str) -> Value {
    json!({"name": name, "emptyDir": {"medium": "Memory", "sizeLimit": size}})
}
