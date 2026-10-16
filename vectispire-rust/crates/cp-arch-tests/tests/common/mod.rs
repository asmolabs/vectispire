//! Synthetic workspaces: the rules are proven on a workspace built to be clean, then broken one way at a time.
//!
//! A rule that has never failed has never been shown to fail. Each test in this directory starts from
//! [`Fixture::clean`], asserts that every rule is silent on it, applies one change and asserts the rule that
//! should notice does, naming the cause. The crates are path-only (`sqlx` and `axum` are empty crates of those
//! names), so `cargo metadata --offline` resolves them without a registry.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use tempfile::TempDir;
use vectispire_cp_arch_tests::graph::Workspace;
use vectispire_cp_arch_tests::model::Config;

/// A smaller edge list than the real one, with every feature of it: interfaces, an open module, infrastructure
/// the modules may and may not use, a pure crate, the one `unsafe` exception.
pub const CONFIG: &str = r#"
[settings]
module_prefix = "vectispire-cp-"
shared = ["vectispire-domain", "vectispire-git"]
pure = ["vectispire-domain"]
unsafe_allowed = [{ crate = "vectispire-git", file = "src/init.rs", max = 2 }]

[infrastructure.db]
crate = "vectispire-cp-db"
uses_modules = []
used_by_modules = true

[infrastructure.runtime]
crate = "vectispire-cp-runtime"
uses_modules = []
used_by_modules = false

[infrastructure.app]
crate = "vectispire-cp-app"
uses_modules = "all"
used_by_modules = false

[module.access]
status = "pending"
allowed = []
interfaces = ["security"]

[module.targets]
status = "pending"
allowed = ["access", "access::security"]

[module.scanning]
status = "pending"
allowed = ["access::security", "targets"]
interfaces = ["queries"]

[module.issues]
status = "pending"
allowed = ["access::security", "scanning", "scanning::queries", "targets"]

[module.inventory]
status = "pending"
allowed = ["access::security", "targets"]

[module.platform]
status = "pending"
open = true
allowed = []
"#;

pub fn config() -> Config {
    Config::parse(CONFIG).unwrap()
}

pub struct Fixture {
    pub dir: TempDir,
    members: Vec<String>,
    /// Crates that stand for the registry's: outside the workspace directory, so that they are not members.
    externals: Vec<String>,
}

impl Fixture {
    pub fn empty() -> Self {
        Self { dir: tempfile::tempdir().unwrap(), members: Vec::new(), externals: Vec::new() }
    }

    /// The workspace directory.
    pub fn root(&self) -> PathBuf {
        self.dir.path().join("ws")
    }

    pub fn crate_dir(&self, name: &str) -> PathBuf {
        if self.externals.iter().any(|external| external == name) {
            self.dir.path().join("ext").join(name)
        } else {
            self.root().join("crates").join(name)
        }
    }

    /// A stand-in for a registry crate: an empty crate of that name, outside the workspace, as a registry crate is.
    pub fn external(&mut self, name: &str) {
        self.externals.push(name.to_owned());
        self.write(
            name,
            "Cargo.toml",
            &format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n"),
        );
        self.write(name, "src/lib.rs", "pub fn query(_: &str) {}\n");
    }

    fn dependency_line(&self, dep: &str) -> String {
        if self.externals.iter().any(|external| external == dep) {
            format!("{dep} = {{ path = \"../../../ext/{dep}\" }}\n")
        } else {
            format!("{dep} = {{ path = \"../{dep}\" }}\n")
        }
    }

    /// Writes a file of a crate, creating its directories.
    pub fn write(&self, krate: &str, rel: &str, text: &str) {
        let path = self.crate_dir(krate).join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    pub fn read(&self, krate: &str, rel: &str) -> String {
        std::fs::read_to_string(self.crate_dir(krate).join(rel)).unwrap()
    }

    /// Replaces text in a file of a crate; the replacement must change something, or the test is not testing.
    pub fn replace(&self, krate: &str, rel: &str, from: &str, to: &str) {
        let text = self.read(krate, rel);
        assert!(text.contains(from), "{krate}/{rel} does not contain {from:?}");
        self.write(krate, rel, &text.replacen(from, to, 1));
    }

    pub fn append(&self, krate: &str, rel: &str, text: &str) {
        let mut current = self.read(krate, rel);
        current.push_str(text);
        self.write(krate, rel, &current);
    }

    /// A crate with a manifest: `deps` are the crates it depends on, by name (path dependencies).
    pub fn krate(&mut self, name: &str, deps: &[&str], dev_deps: &[&str], binary: bool) {
        let mut manifest =
            format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n");
        if binary {
            // A library as well: Cargo records no dependency on a package that has only a binary, so a crate that
            // wrongly depends on the application's binary would be invisible in the graph. Ours has a library.
            manifest.push_str("[lib]\npath = \"src/lib.rs\"\n\n[[bin]]\nname = \"main\"\npath = \"src/main.rs\"\n\n");
        }
        manifest.push_str("[dependencies]\n");
        for dep in deps {
            manifest.push_str(&self.dependency_line(dep));
        }
        manifest.push_str("\n[dev-dependencies]\n");
        for dep in dev_deps {
            manifest.push_str(&self.dependency_line(dep));
        }
        self.write(name, "Cargo.toml", &manifest);
        if binary {
            self.write(name, "src/main.rs", "#![forbid(unsafe_code)]\nfn main() {}\n");
            if !self.crate_dir(name).join("src/lib.rs").exists() {
                self.write(name, "src/lib.rs", "#![forbid(unsafe_code)]\n");
            }
        } else if !self.crate_dir(name).join("src/lib.rs").exists() {
            self.write(name, "src/lib.rs", "#![forbid(unsafe_code)]\n");
        }
        if !self.members.iter().any(|member| member == name) {
            self.members.push(name.to_owned());
        }
    }

    /// Changes a crate's dependencies by rewriting its manifest.
    pub fn depends(&mut self, name: &str, deps: &[&str]) {
        let binary = self.crate_dir(name).join("src/main.rs").exists();
        self.krate(name, deps, &[], binary);
    }

    /// A module crate in the layout the layering rules expect.
    pub fn module(&mut self, module: &str, deps: &[&str]) {
        let name = format!("vectispire-cp-{module}");
        self.krate(&name, deps, &[], false);
        self.write(
            &name,
            "src/lib.rs",
            "#![forbid(unsafe_code)]\n\
             mod internal;\nmod persistence;\nmod web;\n\
             pub struct View;\n\
             pub fn routes() { web::routes() }\n",
        );
        self.write(&name, "src/web/mod.rs", "pub(crate) fn routes() { crate::internal::list(); }\n");
        self.write(&name, "src/internal/mod.rs", "pub(crate) fn list() { crate::persistence::rows(); }\n");
        self.write(&name, "src/persistence/mod.rs", "pub(crate) fn rows() {}\n");
    }

    /// Adds a named interface directory to a module crate and declares it in the root.
    pub fn interface(&mut self, module: &str, interface: &str) {
        let name = format!("vectispire-cp-{module}");
        self.write(&name, &format!("src/{interface}/mod.rs"), "pub struct Guard;\n");
        self.append(&name, "src/lib.rs", &format!("pub mod {interface};\n"));
    }

    /// The clean workspace: a pure domain crate, the agent, two module chains, the infrastructure and the binary.
    pub fn clean() -> Self {
        let mut fixture = Self::empty();
        // Stand-ins for the registry crates whose names the rules look for.
        fixture.external("sqlx");
        fixture.external("axum");
        fixture.krate("vectispire-domain", &[], &[], false);
        fixture.krate("vectispire-git", &[], &[], false);
        fixture.krate("vectispire-agent", &["vectispire-domain", "vectispire-git"], &[], true);
        fixture.krate("vectispire-cp-db", &["sqlx"], &[], false);
        fixture.krate("vectispire-cp-runtime", &[], &[], false);
        fixture.module("access", &["vectispire-domain"]);
        fixture.interface("access", "security");
        fixture.module("targets", &["vectispire-cp-access", "vectispire-cp-db", "sqlx", "vectispire-domain"]);
        fixture.module("scanning", &["vectispire-cp-access", "vectispire-cp-targets", "vectispire-cp-db"]);
        fixture.interface("scanning", "queries");
        fixture.module("issues", &["vectispire-cp-access", "vectispire-cp-scanning", "vectispire-cp-targets"]);
        fixture.krate(
            "vectispire-cp-app",
            &[
                "vectispire-cp-access",
                "vectispire-cp-targets",
                "vectispire-cp-scanning",
                "vectispire-cp-issues",
                "vectispire-cp-db",
            ],
            &[],
            true,
        );
        // targets' persistence holds a statement over its own table: the clean state of the SQL rule.
        fixture.write(
            "vectispire-cp-targets",
            "src/persistence/mod.rs",
            "pub(crate) fn rows() { sqlx_query(\"select id from t_repository where id = 1\"); }\nfn sqlx_query(_: &str) {}\n",
        );
        fixture
    }

    /// Resolves the fixture's graph: writes the workspace manifest and asks Cargo.
    pub fn workspace(&self) -> Workspace {
        let members: Vec<String> = self.members.iter().map(|member| format!("\"crates/{member}\"")).collect();
        std::fs::create_dir_all(self.root()).unwrap();
        std::fs::write(
            self.root().join("Cargo.toml"),
            format!("[workspace]\nresolver = \"3\"\nmembers = [{}]\n", members.join(", ")),
        )
        .unwrap();
        Workspace::load(&self.root().join("Cargo.toml"), false).unwrap()
    }
}
