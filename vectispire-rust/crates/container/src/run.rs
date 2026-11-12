//! One scanner run, as a scanner describes it — `ContainerRun`.

use std::path::Path;
use std::time::Duration;

/// A directory of the agent's host handed to the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub source: String,
    pub target: String,
    /// Explicit, and true wherever it can be.
    pub read_only: bool,
}

impl Mount {
    pub fn read_only(source: impl Into<String>, target: impl Into<String>) -> Mount {
        Mount { source: source.into(), target: target.into(), read_only: true }
    }

    pub fn writable(source: impl Into<String>, target: impl Into<String>) -> Mount {
        Mount { source: source.into(), target: target.into(), read_only: false }
    }

    /// As a bind: `:rw` written out, as docker-java writes it — the daemon reads both the same, and
    /// the reference set compares the bytes.
    pub fn to_bind(&self) -> String {
        format!("{}:{}:{}", self.source, self.target, if self.read_only { "ro" } else { "rw" })
    }
}

/// What to run, with what, as whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRun {
    /// Pinned by digest: a scanner image is never a moving tag.
    pub image: String,
    pub command: Vec<String>,
    pub mounts: Vec<Mount>,
    /// What the label says: the tool, for an operator looking at the host's containers.
    pub label: String,
    /// Off unless the tool must fetch something; most read a tree and print.
    pub network: bool,
    pub as_root: bool,
    /// The limits' own when `None`.
    pub timeout: Option<Duration>,
    /// `uid:gid` to run as — set for a tool that writes into a mount, so that what it writes is the
    /// agent's to delete.
    pub user: Option<String>,
}

impl ContainerRun {
    pub fn new(
        image: impl Into<String>,
        command: Vec<String>,
        mounts: Vec<Mount>,
        label: impl Into<String>,
    ) -> ContainerRun {
        ContainerRun {
            image: image.into(),
            command,
            mounts,
            label: label.into(),
            network: false,
            as_root: false,
            timeout: None,
            user: None,
        }
    }

    /// As the owner of `directory` — `runningAsOwnerOf`: the workspace is 0700 and owned by the
    /// agent's user; its owner reads it and writes the report, a capability-less root does neither.
    /// Root when the file system reports no owner, as on the Java side.
    pub fn running_as_owner_of(self, directory: &Path) -> ContainerRun {
        match owner_of(directory) {
            Some(owner) => ContainerRun { user: Some(owner), as_root: false, ..self },
            None => ContainerRun { user: None, as_root: true, ..self },
        }
    }
}

/// `uid:gid` of a directory, without following a link.
pub fn owner_of(directory: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(directory).ok()?;
        Some(format!("{}:{}", metadata.uid(), metadata.gid()))
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        None
    }
}
