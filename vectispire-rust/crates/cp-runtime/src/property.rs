//! Where a setting's value comes from — the environment, the files under `/run/secrets`, and the
//! defaults — under the rules Spring applies, which are not the rules a mechanical mapping from key to
//! variable name would give.
//!
//! **Why this is not `figment`'s environment provider.** A property's variable is not derived from its
//! key: `vectispire.worker.max-concurrent` is read from `VECTISPIRE_SCAN_MAX_CONCURRENT`, the brand name
//! from the first set of **three** variables (an earlier spelling kept working for deployments that
//! already set it), and a secret may be a *file* named after the variable it replaces. Those rules are
//! the substance of the configuration, and a provider that maps `A_B_C` to `a.b.c` cannot say them. What
//! `figment` would add — layering into a serde struct — is the part that is simple here.
//!
//! **Precedence, as Boot has it:** a variable (or a file named as the property) that sets the property
//! *directly* wins; then the placeholder chain `application.yaml` gives the property, each name tried as a
//! variable and then as a file; then the default. A variable that is set **and empty** counts as set: the
//! compose file's `VECTISPIRE_MAIL_HOST: ""` is a host, and an empty one at that.
//!
//! **Secrets as files** (`spring.config.import: optional:configtree:/run/secrets/`): every regular file
//! under the directory is a property named by its path, `/` as `.`; `ENCRYPTION_KEY` answers
//! `${ENCRYPTION_KEY}` exactly as the variable would. A single trailing newline is trimmed from a
//! single-line value, and not from one that has several lines — a PEM keeps its own.

use std::collections::HashMap;
use std::path::Path;

/// Where the Java side declares a property, for the test that keeps the table honest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `application.yaml`: the placeholder chain and the default are read from the file by a test.
    Yaml,
    /// `@Value("${key:default}")`: the expression is looked up in the Java source by a test.
    Value,
    /// A record's `@DefaultValue` or an `Optional`: no text to compare, so none is compared.
    Record,
}

/// A property of the control plane.
#[derive(Clone, Copy, Debug)]
pub struct Property {
    pub key: &'static str,
    /// The variables `application.yaml` reads it from, in the order it tries them.
    pub names: &'static [&'static str],
    /// `None` when there is no default: the property is then simply absent, or required where it is used.
    pub default: Option<&'static str>,
    pub source: Source,
    /// A value that never reaches a log line, a message or a debug dump.
    pub secret: bool,
}

const fn yaml(key: &'static str, names: &'static [&'static str], default: &'static str) -> Property {
    Property { key, names, default: Some(default), source: Source::Yaml, secret: false }
}

const fn value(key: &'static str, default: Option<&'static str>) -> Property {
    Property { key, names: &[], default, source: Source::Value, secret: false }
}

const fn record(key: &'static str, default: Option<&'static str>) -> Property {
    Property { key, names: &[], default, source: Source::Record, secret: false }
}

const fn secret(property: Property) -> Property {
    Property { secret: true, ..property }
}

/// Every property the control plane reads, with the names and defaults the Java side gives it.
pub const PROPERTIES: &[Property] = &[
    // The server and the database.
    yaml("server.port", &["VECTISPIRE_PORT"], "3180"),
    yaml("spring.datasource.url", &["VECTISPIRE_DB_URL"], "jdbc:mysql://localhost:3306/vectispire"),
    yaml("spring.datasource.username", &["VECTISPIRE_DB_USER"], "vectispire"),
    secret(yaml("spring.datasource.password", &["VECTISPIRE_DB_PASSWORD"], "")),
    // Scanning.
    yaml("vectispire.scanning.image-platform", &["VECTISPIRE_IMAGE_SCAN_PLATFORM"], ""),
    yaml("vectispire.scanning.host-ssh", &["VECTISPIRE_HOST_SSH"], "true"),
    yaml("vectispire.scanning.vulnerability-db-dir", &["VECTISPIRE_VULNERABILITY_DB_DIR"], ""),
    yaml("vectispire.scanning.images.syft", &["VECTISPIRE_IMAGE_SYFT"], ""),
    yaml("vectispire.scanning.images.grype", &["VECTISPIRE_IMAGE_GRYPE"], ""),
    yaml("vectispire.scanning.images.gitleaks", &["VECTISPIRE_IMAGE_GITLEAKS"], ""),
    yaml("vectispire.scanning.images.checkov", &["VECTISPIRE_IMAGE_CHECKOV"], ""),
    yaml("vectispire.scanning.images.semgrep", &["VECTISPIRE_IMAGE_SEMGREP"], ""),
    yaml("vectispire.scanning.plugin-registry", &["VECTISPIRE_PLUGIN_REGISTRY"], ""),
    yaml("vectispire.scanning.plugin-signature-required", &["VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED"], "true"),
    value("vectispire.scanning.bundled-rules", Some("")),
    // Threat intelligence.
    yaml("vectispire.threat-intel.kev-url", &["VECTISPIRE_KEV_URL"], ""),
    yaml("vectispire.threat-intel.kev-allow-private", &["VECTISPIRE_KEV_ALLOW_PRIVATE"], "false"),
    yaml("vectispire.threat-intel.epss-url", &["VECTISPIRE_EPSS_URL"], ""),
    yaml("vectispire.threat-intel.epss-allow-private", &["VECTISPIRE_EPSS_ALLOW_PRIVATE"], "false"),
    // Branding and exports.
    yaml(
        "vectispire.branding.name",
        &["VECTISPIRE_BRAND_NAME", "VECTISPIRE_BRANDING_NAME", "VECTISPIRE_INSTANCE_NAME"],
        "Vectispire",
    ),
    yaml("vectispire.branding.gitlab-url", &["VECTISPIRE_GITLAB_URL"], "https://github.com/asmolabs/vectispire"),
    yaml("vectispire.exports.public-url", &["VECTISPIRE_PUBLIC_URL"], ""),
    yaml(
        "vectispire.exports.vex-author",
        &["VECTISPIRE_VEX_AUTHOR", "VECTISPIRE_BRAND_NAME", "VECTISPIRE_BRANDING_NAME"],
        "Vectispire",
    ),
    yaml("vectispire.exports.tool-version", &["VECTISPIRE_VERSION"], ""),
    // The first administrator.
    yaml("vectispire.bootstrap.username", &["VECTISPIRE_BOOTSTRAP_USERNAME"], ""),
    secret(yaml("vectispire.bootstrap.password", &["VECTISPIRE_BOOTSTRAP_PASSWORD"], "")),
    // Security: addresses, throttles, body sizes, sessions.
    yaml("vectispire.security.trusted-proxies", &["VECTISPIRE_TRUSTED_PROXIES"], ""),
    yaml("vectispire.security.anonymous-api-docs", &["VECTISPIRE_ANONYMOUS_API_DOCS"], "false"),
    yaml("vectispire.security.bearer-failures-per-window", &["VECTISPIRE_BEARER_FAILURES_PER_WINDOW"], "60"),
    yaml("vectispire.security.bearer-failure-window", &["VECTISPIRE_BEARER_FAILURE_WINDOW"], "PT5M"),
    yaml("vectispire.security.api-key-requests-per-minute", &["VECTISPIRE_API_KEY_REQUESTS_PER_MINUTE"], "600"),
    yaml("vectispire.security.webhook-requests-per-window", &["VECTISPIRE_WEBHOOK_REQUESTS_PER_WINDOW"], "300"),
    yaml("vectispire.security.webhook-request-window", &["VECTISPIRE_WEBHOOK_REQUEST_WINDOW"], "PT1M"),
    value("vectispire.security.login-attempts-per-window", Some("10")),
    value("vectispire.security.login-attempt-window", Some("PT1M")),
    yaml("vectispire.http.max-body.default", &["VECTISPIRE_MAX_BODY_DEFAULT"], "1MB"),
    yaml("vectispire.http.max-body.rule-set-upload", &["VECTISPIRE_MAX_BODY_RULE_SET_UPLOAD"], "64MB"),
    yaml("vectispire.http.max-body.ticket-webhook", &["VECTISPIRE_MAX_BODY_TICKET_WEBHOOK"], "1MB"),
    yaml("vectispire.http.max-body.vex-ingest", &["VECTISPIRE_MAX_BODY_VEX_INGEST"], "16MB"),
    yaml("vectispire.http.max-body.agent-result", &["VECTISPIRE_MAX_BODY_AGENT_RESULT"], "256MB"),
    yaml("vectispire.http.max-body.sign-in", &["VECTISPIRE_MAX_BODY_SIGN_IN"], "16KB"),
    yaml("vectispire.http.max-body.sarif-import", &["VECTISPIRE_MAX_BODY_SARIF_IMPORT"], "32MB"),
    yaml("vectispire.http.max-body.coverage-import", &["VECTISPIRE_MAX_BODY_COVERAGE_IMPORT"], "16MB"),
    yaml("vectispire.http.max-body.test-report-import", &["VECTISPIRE_MAX_BODY_TEST_REPORT_IMPORT"], "32MB"),
    yaml("vectispire.http.max-body.sbom-import", &["VECTISPIRE_MAX_BODY_SBOM_IMPORT"], "32MB"),
    yaml(
        "vectispire.http.max-body.checklist-template-import",
        &["VECTISPIRE_MAX_BODY_CHECKLIST_TEMPLATE_IMPORT"],
        "10MB",
    ),
    value("vectispire.http.max-body.checklist-evidence", Some("25MB")),
    yaml("vectispire.session.absolute-lifetime", &["VECTISPIRE_SESSION_LIFETIME"], "12h"),
    yaml("vectispire.session.idle-lifetime", &["VECTISPIRE_SESSION_IDLE"], "60m"),
    // Single sign-on.
    yaml("vectispire.oidc.password-login", &["VECTISPIRE_PASSWORD_LOGIN"], "true"),
    yaml("vectispire.oidc.link-privileged-accounts", &["VECTISPIRE_OIDC_LINK_PRIVILEGED_ACCOUNTS"], "false"),
    yaml("vectispire.oidc.require-mfa", &["VECTISPIRE_OIDC_REQUIRE_MFA"], "false"),
    yaml("vectispire.oidc.mfa-amr", &["VECTISPIRE_OIDC_MFA_AMR"], "mfa,otp,hwk,fido"),
    yaml("vectispire.oidc.mfa-acr", &["VECTISPIRE_OIDC_MFA_ACR"], ""),
    value("vectispire.oidc.issuer", None),
    value("vectispire.oidc.client-id", None),
    secret(value("vectispire.oidc.client-secret", Some(""))),
    value("vectispire.oidc.name", Some("Single sign-on")),
    // Git, audit.
    yaml("vectispire.git.allowed-hosts", &["VECTISPIRE_GIT_ALLOWED_HOSTS"], ""),
    yaml("vectispire.audit.mirror-path", &["VECTISPIRE_AUDIT_MIRROR"], ""),
    // Encryption at rest.
    secret(yaml("vectispire.encryption.key", &["ENCRYPTION_KEY"], "")),
    yaml("vectispire.encryption.key-file", &["ENCRYPTION_KEY_FILE"], ""),
    secret(yaml("vectispire.encryption.previous-keys", &["VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS"], "")),
    yaml("vectispire.encryption.previous-keys-file", &["VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE"], ""),
    record("vectispire.encryption.kms-type", None),
    record("vectispire.encryption.vault-endpoint", None),
    secret(record("vectispire.encryption.vault-token", None)),
    record("vectispire.encryption.vault-token-file", None),
    record("vectispire.encryption.vault-key-name", None),
    record("vectispire.encryption.vault-mount-path", None),
    secret(value("vectispire.signing.key", Some(""))),
    // SCIM.
    record("vectispire.scim.enabled", Some("false")),
    secret(record("vectispire.scim.token", None)),
    record("vectispire.scim.token-file", None),
    // Queue, leader, worker, reports, forges, jobs.
    yaml("vectispire.queue.retry-delays", &["VECTISPIRE_SCAN_RETRY_DELAYS"], "1m,5m,15m"),
    record("vectispire.queue.lease", Some("20m")),
    record("vectispire.queue.max-attempts", Some("3")),
    record("vectispire.queue.claim-attempts", Some("12")),
    record("vectispire.leader.lease", Some("180s")),
    yaml("vectispire.worker.enabled", &["VECTISPIRE_EMBEDDED_WORKER"], "true"),
    yaml("vectispire.worker.max-concurrent", &["VECTISPIRE_SCAN_MAX_CONCURRENT"], "2"),
    yaml("vectispire.worker.labels", &["VECTISPIRE_WORKER_LABELS"], ""),
    yaml("vectispire.worker.interval", &["VECTISPIRE_WORKER_INTERVAL"], "15s"),
    yaml("vectispire.reports.concurrency", &["VECTISPIRE_REPORT_CONCURRENCY"], "2"),
    yaml("vectispire.reports.interval", &["VECTISPIRE_REPORT_INTERVAL"], "10s"),
    value("vectispire.reports.lease", None),
    yaml("vectispire.forges.discovery.concurrency", &["VECTISPIRE_DISCOVERY_CONCURRENCY"], "2"),
    yaml("vectispire.forges.discovery.interval", &["VECTISPIRE_DISCOVERY_INTERVAL"], "5s"),
    value("vectispire.forges.discovery.max-repositories", Some("20000")),
    value("vectispire.forges.discovery.max-rate-limit-wait", Some("60s")),
    value("vectispire.forges.discovery.max-duration", Some("30m")),
    value("vectispire.forges.reviews.turn-duration", Some("5m")),
    value("vectispire.forges.reviews.refresh", Some("6h")),
    value("vectispire.forges.reviews.reading-duration", Some("2m")),
    value("vectispire.forges.reviews.max-readings", Some("200")),
    value("vectispire.forges.reviews.max-rate-limit-wait", Some("60s")),
    value("vectispire.forges.reviews.max-changes", Some("500")),
    value("vectispire.forges.reviews.claim", Some("15m")),
    yaml("vectispire.jobs.relay-interval", &["VECTISPIRE_RELAY_INTERVAL"], "60s"),
    yaml("vectispire.jobs.scheduler-interval", &["VECTISPIRE_SCHEDULER_INTERVAL"], "60s"),
    yaml("vectispire.jobs.maintenance-interval", &["VECTISPIRE_MAINTENANCE_INTERVAL"], "1h"),
    // Mail, when a host is named.
    value("vectispire.mail.host", None),
    value("vectispire.mail.port", Some("587")),
    value("vectispire.mail.username", Some("")),
    secret(value("vectispire.mail.password", Some(""))),
    value("vectispire.mail.starttls", Some("true")),
    // The API's own map.
    yaml("springdoc.swagger-ui.enabled", &["VECTISPIRE_SWAGGER_UI_ENABLED"], "false"),
    yaml("springdoc.api-docs.enabled", &["VECTISPIRE_API_DOCS_ENABLED"], "false"),
];

/// The table's entry for `key`.
pub fn property(key: &str) -> Option<&'static Property> {
    PROPERTIES.iter().find(|property| property.key == key)
}

/// The variables, and the files, a property is read from.
#[derive(Clone, Debug, Default)]
pub struct Environment {
    variables: HashMap<String, String>,
    tree: HashMap<String, String>,
}

impl Environment {
    /// The process's own, and the config tree under `/run/secrets`.
    pub fn process() -> Environment {
        Environment::with_config_tree(Path::new("/run/secrets"))
    }

    /// The process's variables, and the config tree under `directory` — a directory that does not exist
    /// is a deployment without file secrets, not a broken one (`optional:`).
    pub fn with_config_tree(directory: &Path) -> Environment {
        Environment { variables: std::env::vars().collect(), tree: read_config_tree(directory) }
    }

    /// Exactly these variables and files, for a test.
    pub fn of<'a>(
        variables: impl IntoIterator<Item = (&'a str, &'a str)>,
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Environment {
        Environment {
            variables: variables.into_iter().map(|(k, v)| (k.to_owned(), v.to_owned())).collect(),
            tree: files.into_iter().map(|(k, v)| (k.to_owned(), v.to_owned())).collect(),
        }
    }

    /// A variable, exactly as set.
    pub fn variable(&self, name: &str) -> Option<&str> {
        self.variables.get(name).map(String::as_str)
    }

    /// A property file of the config tree, by its name.
    pub fn file(&self, name: &str) -> Option<&str> {
        self.tree.get(name).map(String::as_str)
    }

    /// A name a placeholder asks for: the variable, then the file of that name.
    fn named(&self, name: &str) -> Option<&str> {
        self.variable(name).or_else(|| self.file(name))
    }

    /// The variables Boot's relaxed binding derives from a key: the key itself, then with dots and
    /// dashes as underscores, then with the dashes removed — each upper-cased.
    fn relaxed(key: &str) -> Vec<String> {
        let underscored = key.replace(['.', '-'], "_").to_uppercase();
        let joined = key.replace('.', "_").replace('-', "").to_uppercase();
        let mut names = vec![key.to_owned(), underscored];
        if !names.contains(&joined) {
            names.push(joined);
        }
        names
    }

    /// The value of `property` and where it came from, or `None` when nothing sets it and it has no default.
    pub fn resolve(&self, property: &Property) -> Option<(String, Origin)> {
        for name in Environment::relaxed(property.key) {
            if let Some(found) = self.variable(&name) {
                return Some((found.to_owned(), Origin::Variable(name)));
            }
        }
        if let Some(found) = self.file(property.key) {
            return Some((found.to_owned(), Origin::File(property.key.to_owned())));
        }
        for name in property.names {
            if let Some(found) = self.variable(name) {
                return Some((found.to_owned(), Origin::Variable((*name).to_owned())));
            }
            if let Some(found) = self.file(name) {
                return Some((found.to_owned(), Origin::File((*name).to_owned())));
            }
        }
        // A relaxed file name, as a config tree would hold `vectispire.mail.password` and nothing else.
        property.default.map(|default| (default.to_owned(), Origin::Default))
    }

    /// Whether a name — a variable or a file — is set at all.
    pub fn is_set(&self, name: &str) -> bool {
        self.named(name).is_some()
    }
}

/// Where a resolved value came from — shown by `--check-config`, never the value of a secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    Variable(String),
    File(String),
    Default,
}

impl std::fmt::Display for Origin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Origin::Variable(name) => write!(formatter, "variable {name}"),
            Origin::File(name) => write!(formatter, "file {name}"),
            Origin::Default => formatter.write_str("default"),
        }
    }
}

/// Every regular file under `directory`, as a property named by its path, `/` as `.`. A path with a
/// component starting `..` is skipped: that is where a Kubernetes secret volume keeps its own
/// bookkeeping, and the files it points at are read under their own names.
fn read_config_tree(directory: &Path) -> HashMap<String, String> {
    let mut found = HashMap::new();
    read_tree_into(directory, "", &mut found);
    found
}

fn read_tree_into(directory: &Path, prefix: &str, found: &mut HashMap<String, String>) {
    let Ok(entries) = std::fs::read_dir(directory) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("..") {
            continue;
        }
        let path = entry.path();
        let qualified = if prefix.is_empty() { name } else { format!("{prefix}.{name}") };
        // `metadata` follows the symlinks a secret volume is made of.
        let Ok(metadata) = std::fs::metadata(&path) else { continue };
        if metadata.is_dir() {
            read_tree_into(&path, &qualified, found);
        } else if metadata.is_file()
            && let Ok(bytes) = std::fs::read(&path)
        {
            found.insert(qualified, auto_trim_trailing_new_line(String::from_utf8_lossy(&bytes).into_owned()));
        }
    }
}

/// `AUTO_TRIM_TRAILING_NEW_LINE`: one trailing `\n` or `\r\n` goes, but only from a value of a single
/// line — a value that holds more keeps its trailing newline, as a PEM or a key list should.
fn auto_trim_trailing_new_line(content: String) -> String {
    if !content.ends_with('\n') || content.matches('\n').count() > 1 {
        return content;
    }
    let cut = if content.ends_with("\r\n") { 2 } else { 1 };
    content[..content.len() - cut].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(environment: &Environment, key: &str) -> Option<(String, Origin)> {
        environment.resolve(property(key).unwrap())
    }

    #[test]
    fn a_default_answers_when_nothing_else_does() {
        let environment = Environment::of([], []);
        assert_eq!(resolve(&environment, "server.port"), Some(("3180".to_owned(), Origin::Default)));
        assert_eq!(resolve(&environment, "vectispire.oidc.issuer"), None);
    }

    #[test]
    fn the_named_variable_answers_and_a_set_empty_one_is_set() {
        let environment = Environment::of([("VECTISPIRE_PORT", "8080"), ("VECTISPIRE_DB_USER", "")], []);
        assert_eq!(resolve(&environment, "server.port").unwrap().0, "8080");
        assert_eq!(resolve(&environment, "spring.datasource.username").unwrap().0, "", "set and empty is not unset");
    }

    #[test]
    fn the_brand_name_follows_the_chain_but_the_relaxed_name_of_the_property_itself_wins() {
        let key = "vectispire.branding.name";
        assert_eq!(resolve(&Environment::of([("VECTISPIRE_INSTANCE_NAME", "old")], []), key).unwrap().0, "old");
        let chain = Environment::of([("VECTISPIRE_INSTANCE_NAME", "old"), ("VECTISPIRE_BRAND_NAME", "new")], []);
        assert_eq!(resolve(&chain, key).unwrap().0, "new", "the newest spelling of the chain beats the older ones");
        // **A quirk the Java control plane has, kept.** `VECTISPIRE_BRANDING_NAME` is the second spelling of
        // the chain *and* the variable relaxed binding derives from the property `vectispire.branding.name`
        // itself — which reads it before `application.yaml`'s placeholder is consulted. So where both it and
        // `VECTISPIRE_BRAND_NAME` are set, the older one answers, in spite of "newest first". A deployment
        // that has both sees the name it sees today; changing that would rename it.
        let both = Environment::of([("VECTISPIRE_BRANDING_NAME", "mid"), ("VECTISPIRE_BRAND_NAME", "new")], []);
        assert_eq!(
            resolve(&both, key).unwrap(),
            ("mid".to_owned(), Origin::Variable("VECTISPIRE_BRANDING_NAME".to_owned()))
        );
    }

    #[test]
    fn a_file_named_after_the_variable_answers_and_the_variable_wins() {
        let files = Environment::of([], [("ENCRYPTION_KEY", "from-the-file")]);
        assert_eq!(
            resolve(&files, "vectispire.encryption.key").unwrap(),
            ("from-the-file".to_owned(), Origin::File("ENCRYPTION_KEY".to_owned()))
        );
        let both = Environment::of([("ENCRYPTION_KEY", "from-the-variable")], [("ENCRYPTION_KEY", "from-the-file")]);
        assert_eq!(resolve(&both, "vectispire.encryption.key").unwrap().0, "from-the-variable");
    }

    #[test]
    fn relaxed_binding_reaches_a_property_that_names_no_variable() {
        let spelled =
            Environment::of([("VECTISPIRE_MAIL_HOST", "smtp.example.org"), ("VECTISPIRE_OIDC_CLIENT_ID", "c")], []);
        assert_eq!(resolve(&spelled, "vectispire.mail.host").unwrap().0, "smtp.example.org");
        assert_eq!(resolve(&spelled, "vectispire.oidc.client-id").unwrap().0, "c");
        let dashes_removed = Environment::of([("VECTISPIRE_WORKER_MAXCONCURRENT", "7")], []);
        assert_eq!(resolve(&dashes_removed, "vectispire.worker.max-concurrent").unwrap().0, "7");
        // A direct setting beats the placeholder chain's variable.
        let both =
            Environment::of([("VECTISPIRE_WORKER_MAXCONCURRENT", "7"), ("VECTISPIRE_SCAN_MAX_CONCURRENT", "3")], []);
        assert_eq!(resolve(&both, "vectispire.worker.max-concurrent").unwrap().0, "7");
    }

    #[test]
    fn a_file_named_as_the_property_answers() {
        // `vectispire.mail.password` as the shipped compose mounts it.
        let environment = Environment::of([], [("vectispire.mail.password", "p")]);
        assert_eq!(resolve(&environment, "vectispire.mail.password").unwrap().0, "p");
    }

    #[test]
    fn the_config_tree_reads_files_by_path_and_trims_one_trailing_newline_of_a_single_line() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("ENCRYPTION_KEY"), "k3y\n").unwrap();
        std::fs::write(directory.path().join("CRLF"), "v\r\n").unwrap();
        std::fs::write(directory.path().join("PEM"), "-----BEGIN-----\nabc\n-----END-----\n").unwrap();
        std::fs::write(directory.path().join("TWO"), "a\n\n").unwrap();
        std::fs::create_dir(directory.path().join("vectispire")).unwrap();
        std::fs::write(directory.path().join("vectispire").join("signing"), "nested").unwrap();
        std::fs::create_dir(directory.path().join("..data")).unwrap();
        std::fs::write(directory.path().join("..data").join("hidden"), "bookkeeping").unwrap();
        let environment = Environment::with_config_tree(directory.path());
        assert_eq!(environment.file("ENCRYPTION_KEY"), Some("k3y"));
        assert_eq!(environment.file("CRLF"), Some("v"));
        assert_eq!(environment.file("PEM"), Some("-----BEGIN-----\nabc\n-----END-----\n"));
        assert_eq!(environment.file("TWO"), Some("a\n\n"));
        assert_eq!(environment.file("vectispire.signing"), Some("nested"));
        assert_eq!(environment.file("..data.hidden"), None);
        assert_eq!(environment.file("hidden"), None);
    }

    #[test]
    fn a_missing_config_tree_is_a_deployment_without_file_secrets() {
        let environment = Environment::with_config_tree(Path::new("/nonexistent/vectispire/secrets"));
        assert_eq!(environment.file("ENCRYPTION_KEY"), None);
    }
}
