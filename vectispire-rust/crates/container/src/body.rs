//! The closed shape every scanner container is created in — `ContainerRunner.closedHostConfig` and
//! `create`.

use crate::{ContainerRun, ScannerLimits};
use bollard::models::{ContainerCreateBody, HostConfig};
use std::collections::HashMap;

/// The label every container Vectispire starts carries: the machine that scans is not necessarily
/// ours, and an operator or an orphan sweep has to tell what Vectispire launched from the rest.
pub const SCANNER_LABEL: &str = "dev.vectispire.scanner";

/// Where a scanner may write: the root is read-only, so this is all of it — a tmpfs, counted against
/// the memory limit, so one budget rather than two.
const SCRATCH_MEGABYTES: u32 = 512;

/// A writable `HOME`: several scanner images set none, and a cache written under `/` against a
/// read-only root fails the scan outright.
const SCRATCH_HOME: &str = "/home/scanner";

/// Where the vulnerability database is mounted, for the one scanner that has one.
pub const DATABASE_CACHE_MOUNT: &str = "/cache";

/// Every capability the Java runner drops, in its order: `ALL`, then docker-java's
/// `Capability.values()` one by one. The daemon reads `ALL` alone the same way; the list is kept
/// whole because the reference set compares what the daemon is sent, and a daemon that one day
/// reads `ALL` differently still finds each capability named.
const CAPABILITIES: [&str; 42] = [
    "ALL",
    "AUDIT_CONTROL",
    "AUDIT_READ",
    "AUDIT_WRITE",
    "BLOCK_SUSPEND",
    "BPF",
    "CHECKPOINT_RESTORE",
    "CHOWN",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "FOWNER",
    "FSETID",
    "IPC_LOCK",
    "IPC_OWNER",
    "KILL",
    "LEASE",
    "LINUX_IMMUTABLE",
    "MAC_ADMIN",
    "MAC_OVERRIDE",
    "MKNOD",
    "NET_ADMIN",
    "NET_BIND_SERVICE",
    "NET_BROADCAST",
    "NET_RAW",
    "PERFMON",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_ADMIN",
    "SYS_BOOT",
    "SYS_CHROOT",
    "SYSLOG",
    "SYS_MODULE",
    "SYS_NICE",
    "SYS_PACCT",
    "SYS_PTRACE",
    "SYS_RAWIO",
    "SYS_RESOURCE",
    "SYS_TIME",
    "SYS_TTY_CONFIG",
    "WAKE_ALARM",
];

/// The create request for `run` under `limits` — already clamped to the daemon's cores.
pub fn create_body(run: &ContainerRun, limits: &ScannerLimits) -> ContainerCreateBody {
    let scratch = format!("rw,noexec,nosuid,mode=1777,size={SCRATCH_MEGABYTES}m");
    let host_config = HostConfig {
        binds: Some(run.mounts.iter().map(|mount| mount.to_bind()).collect()),
        network_mode: Some(if run.network { "bridge" } else { "none" }.to_owned()),
        memory: Some(limits.memory),
        nano_cpus: Some(limits.nano_cpus),
        pids_limit: Some(limits.pids),
        cap_drop: Some(CAPABILITIES.iter().map(|capability| (*capability).to_owned()).collect()),
        security_opt: Some(vec!["no-new-privileges".to_owned()]),
        // The image's filesystem is not the scanner's to modify: a tool compromised mid-scan cannot
        // drop a binary in it and keep it for the life of the container.
        readonly_rootfs: Some(true),
        // What read-only takes away and these tools need back, `noexec` so that scratch space is not
        // somewhere to stage a payload. `mode=1777` because the daemon copies the image's own mode
        // onto the tmpfs, and the matcher's image ships a `/tmp` only root may write.
        tmpfs: Some(HashMap::from([("/tmp".to_owned(), scratch.clone()), (SCRATCH_HOME.to_owned(), scratch)])),
        // Removed explicitly, not by the daemon: an interrupted scan must not leave dead containers.
        auto_remove: Some(false),
        ..Default::default()
    };
    let user = match (&run.user, run.as_root) {
        (Some(user), _) => Some(user.clone()),
        (None, true) => Some("0:0".to_owned()),
        (None, false) => None,
    };
    ContainerCreateBody {
        image: Some(run.image.clone()),
        cmd: Some(run.command.clone()),
        labels: Some(HashMap::from([(SCANNER_LABEL.to_owned(), run.label.clone())])),
        env: Some(
            [
                format!("HOME={SCRATCH_HOME}"),
                "TMPDIR=/tmp".to_owned(),
                format!("XDG_CACHE_HOME={SCRATCH_HOME}/.cache"),
                // Set for every container although only the matcher reads them: the next image added
                // will not announce what it caches where.
                format!("GRYPE_DB_CACHE_DIR={DATABASE_CACHE_MOUNT}"),
                "GRYPE_DB_AUTO_UPDATE=false".to_owned(),
                "GRYPE_CHECK_FOR_APP_UPDATE=false".to_owned(),
            ]
            .into(),
        ),
        // docker-java sends both as empty objects; the daemon reads them as absent.
        exposed_ports: Some(HashMap::new()),
        volumes: Some(HashMap::new()),
        user,
        host_config: Some(host_config),
        ..Default::default()
    }
}
