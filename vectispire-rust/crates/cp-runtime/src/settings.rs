//! The control plane's configuration, typed — every property under the name and the default the Java
//! side gives it (`property::PROPERTIES`), read from the environment and `/run/secrets` under Spring's
//! rules.
//!
//! **Every problem at once.** A value that does not read — a duration that is not one, a port that is
//! not a number — is not a reason to show the operator one error, fix it, restart, and meet the next: the
//! loader collects them all, and refuses to start naming each. A secret never appears in what it says.
//!
//! **What the Java side reads from outside Spring** is here too: the Docker host (`VECTISPIRE_DOCKER_HOST`
//! then `DOCKER_HOST`) and the Kubernetes service address, which only the outbound guard's reserved
//! endpoints use. The Java probing of a developer's own socket paths (`~/.orbstack/…`) is not ported: the
//! control plane here runs in a container, where the variable is the way.

use std::time::Duration;

use vectispire_domain::secret::Secret;

use crate::property::{Environment, Origin, Property, property};
use crate::secret_file;
use crate::spring::{parse_bool, parse_data_size, parse_duration};

/// What could not be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("The configuration cannot be read:\n  - {}", .problems.join("\n  - "))]
pub struct ConfigError {
    pub problems: Vec<String>,
}

/// One line of the `--check-config` report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportLine {
    pub key: &'static str,
    /// The value, or `(set)` / `(not set)` for a secret.
    pub shown: String,
    pub origin: Origin,
}

/// The settings of the control plane.
#[derive(Clone, Debug)]
pub struct Settings {
    pub server_port: u16,
    pub datasource: Datasource,
    pub scanning: Scanning,
    pub threat_intel: ThreatIntel,
    pub branding: Branding,
    pub exports: Exports,
    pub bootstrap: Bootstrap,
    pub security: Security,
    pub max_body: MaxBody,
    pub session: Session,
    pub oidc: Oidc,
    pub git_allowed_hosts: String,
    pub audit_mirror_path: Option<String>,
    pub encryption: Encryption,
    pub signing_key: Option<Secret>,
    pub scim: Scim,
    pub queue: Queue,
    pub leader_lease: Duration,
    pub worker: Worker,
    pub reports: Reports,
    pub forges: Forges,
    pub jobs: Jobs,
    pub mail: Option<Mail>,
    pub api_docs: ApiDocs,
    pub environment: Surroundings,
}

#[derive(Clone, Debug)]
pub struct Datasource {
    pub url: String,
    pub username: String,
    pub password: Secret,
}

#[derive(Clone, Debug)]
pub struct Scanning {
    pub image_platform: Option<String>,
    pub host_ssh: bool,
    pub vulnerability_db_dir: Option<String>,
    pub images: ScannerImages,
    pub plugin_registry: Option<String>,
    pub plugin_signature_required: bool,
    pub bundled_rules: Option<String>,
}

/// The scanner images, each blank for the digest Vectispire ships with.
#[derive(Clone, Debug)]
pub struct ScannerImages {
    pub syft: Option<String>,
    pub grype: Option<String>,
    pub gitleaks: Option<String>,
    pub checkov: Option<String>,
    pub semgrep: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ThreatIntel {
    pub kev_url: Option<String>,
    pub kev_allow_private: bool,
    pub epss_url: Option<String>,
    pub epss_allow_private: bool,
}

#[derive(Clone, Debug)]
pub struct Branding {
    pub name: String,
    pub gitlab_url: String,
}

#[derive(Clone, Debug)]
pub struct Exports {
    pub public_url: Option<String>,
    pub vex_author: String,
    /// Empty means the build's own version.
    pub tool_version: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Bootstrap {
    pub username: Option<String>,
    pub password: Option<Secret>,
}

#[derive(Clone, Debug)]
pub struct Security {
    pub trusted_proxies: String,
    pub anonymous_api_docs: bool,
    pub bearer_failures_per_window: u32,
    pub bearer_failure_window: Duration,
    pub api_key_requests_per_minute: u32,
    pub webhook_requests_per_window: u32,
    pub webhook_request_window: Duration,
    pub login_attempts_per_window: u32,
    pub login_attempt_window: Duration,
}

/// The ceilings on a request body, in bytes, per route class.
#[derive(Clone, Debug)]
pub struct MaxBody {
    pub default: u64,
    pub rule_set_upload: u64,
    pub ticket_webhook: u64,
    pub vex_ingest: u64,
    pub agent_result: u64,
    pub sign_in: u64,
    pub sarif_import: u64,
    pub coverage_import: u64,
    pub test_report_import: u64,
    pub sbom_import: u64,
    pub checklist_template_import: u64,
    pub checklist_evidence: u64,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub absolute_lifetime: Duration,
    pub idle_lifetime: Duration,
}

#[derive(Clone, Debug)]
pub struct Oidc {
    pub password_login: bool,
    pub link_privileged_accounts: bool,
    pub require_mfa: bool,
    pub mfa_amr: Vec<String>,
    pub mfa_acr: Option<String>,
    /// Present only when an issuer is named — as `@ConditionalOnProperty("vectispire.oidc.issuer")`.
    pub provider: Option<OidcProvider>,
}

#[derive(Clone, Debug)]
pub struct OidcProvider {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Secret,
    pub name: String,
}

/// The key material as the file variables resolved it: `resolved()` in Java.
#[derive(Clone, Debug)]
pub struct Encryption {
    pub key: Option<Secret>,
    pub previous_keys: Vec<Secret>,
    pub kms_type: Option<String>,
    pub vault_endpoint: Option<String>,
    pub vault_token: Option<Secret>,
    pub vault_key_name: Option<String>,
    pub vault_mount_path: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Scim {
    pub enabled: bool,
    pub token: Option<Secret>,
}

#[derive(Clone, Debug)]
pub struct Queue {
    pub retry_delays: Vec<Duration>,
    pub lease: Duration,
    pub max_attempts: u32,
    pub claim_attempts: u32,
}

#[derive(Clone, Debug)]
pub struct Worker {
    pub enabled: bool,
    pub max_concurrent: u32,
    pub labels: String,
    pub interval: Duration,
}

#[derive(Clone, Debug)]
pub struct Reports {
    pub concurrency: u32,
    pub interval: Duration,
    pub lease: Option<Duration>,
}

#[derive(Clone, Debug)]
pub struct Forges {
    pub discovery: Discovery,
    pub reviews: Reviews,
}

#[derive(Clone, Debug)]
pub struct Discovery {
    pub concurrency: u32,
    pub interval: Duration,
    pub max_repositories: u32,
    pub max_rate_limit_wait: Duration,
    pub max_duration: Duration,
}

#[derive(Clone, Debug)]
pub struct Reviews {
    pub turn_duration: Duration,
    pub refresh: Duration,
    pub reading_duration: Duration,
    pub max_readings: u32,
    pub max_rate_limit_wait: Duration,
    pub max_changes: u32,
    pub claim: Duration,
}

#[derive(Clone, Debug)]
pub struct Jobs {
    pub relay_interval: Duration,
    pub scheduler_interval: Duration,
    pub maintenance_interval: Duration,
}

/// A mail relay: created only when a host is named, **even an empty one** — Spring counts a variable set to
/// the empty string as present, so a deployment that names no relay must leave the variable unset.
#[derive(Clone, Debug)]
pub struct Mail {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Secret,
    pub starttls: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ApiDocs {
    pub swagger_ui: bool,
    pub api_docs: bool,
}

/// What the process is told that is not a property.
#[derive(Clone, Debug)]
pub struct Surroundings {
    /// `VECTISPIRE_DOCKER_HOST`, else `DOCKER_HOST`, trimmed; `None` when neither names one.
    pub docker_host: Option<String>,
    pub kubernetes_service_host: Option<String>,
    pub kubernetes_service_port: Option<String>,
}

struct Reader<'a> {
    environment: &'a Environment,
    problems: Vec<String>,
    report: Vec<ReportLine>,
}

impl Reader<'_> {
    fn raw(&mut self, key: &str) -> Option<String> {
        let Some(table) = property(key) else {
            self.problems.push(format!("{key} is read but not declared (a bug: add it to property::PROPERTIES)"));
            return None;
        };
        let resolved = self.environment.resolve(table);
        self.record(table, resolved.as_ref());
        resolved.map(|(value, _)| value)
    }

    fn record(&mut self, table: &'static Property, resolved: Option<&(String, Origin)>) {
        let (shown, origin) = match resolved {
            Some((value, origin)) if table.secret => {
                (if value.is_empty() { "(not set)".to_owned() } else { "(set)".to_owned() }, origin.clone())
            }
            Some((value, origin)) => (value.clone(), origin.clone()),
            None => ("(not set)".to_owned(), Origin::Default),
        };
        self.report.push(ReportLine { key: table.key, shown, origin });
    }

    fn string(&mut self, key: &str) -> String {
        self.raw(key).unwrap_or_default()
    }

    /// A string that is absent when blank — `filter(value -> !value.isBlank())`.
    fn present(&mut self, key: &str) -> Option<String> {
        self.raw(key).filter(|value| !value.chars().all(char::is_whitespace))
    }

    /// A secret that is absent when blank.
    fn secret(&mut self, key: &str) -> Option<Secret> {
        self.present(key).map(Secret::new)
    }

    fn boolean(&mut self, key: &str) -> bool {
        match self.raw(key).as_deref().map(parse_bool) {
            Some(Ok(value)) => value.unwrap_or(false),
            Some(Err(message)) => {
                self.problems.push(format!("{key}: {message}"));
                false
            }
            None => false,
        }
    }

    fn number<T: std::str::FromStr + Default>(&mut self, key: &str) -> T {
        match self.raw(key) {
            Some(text) => text.trim().parse().unwrap_or_else(|_| {
                self.problems.push(format!("{key}: '{}' is not a number", text.trim()));
                T::default()
            }),
            None => T::default(),
        }
    }

    fn duration(&mut self, key: &str) -> Duration {
        self.optional_duration(key).unwrap_or_default()
    }

    fn optional_duration(&mut self, key: &str) -> Option<Duration> {
        let text = self.raw(key)?;
        match parse_duration(&text) {
            Ok(duration) => Some(duration),
            Err(message) => {
                self.problems.push(format!("{key}: {message}"));
                None
            }
        }
    }

    fn size(&mut self, key: &str) -> u64 {
        let Some(text) = self.raw(key) else { return 0 };
        parse_data_size(&text).unwrap_or_else(|message| {
            self.problems.push(format!("{key}: {message}"));
            0
        })
    }
}

fn variable_present(environment: &Environment, name: &str) -> Option<String> {
    environment
        .variable(name)
        .map(|value| value.trim_matches(|c: char| c <= ' '))
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

impl Settings {
    /// The settings of this process: its variables and `/run/secrets`.
    pub fn from_process() -> Result<(Settings, Vec<ReportLine>), ConfigError> {
        Settings::load(&Environment::process())
    }

    /// Reads every property, or says every one that cannot be read — and the report of where each value came from.
    pub fn load(environment: &Environment) -> Result<(Settings, Vec<ReportLine>), ConfigError> {
        let mut r = Reader { environment, problems: Vec::new(), report: Vec::new() };

        let server_port = r.number::<u16>("server.port");
        let datasource = Datasource {
            url: r.string("spring.datasource.url"),
            username: r.string("spring.datasource.username"),
            password: Secret::new(r.string("spring.datasource.password")),
        };
        let scanning = Scanning {
            image_platform: r.present("vectispire.scanning.image-platform"),
            host_ssh: r.boolean("vectispire.scanning.host-ssh"),
            vulnerability_db_dir: r.present("vectispire.scanning.vulnerability-db-dir"),
            images: ScannerImages {
                syft: r.present("vectispire.scanning.images.syft"),
                grype: r.present("vectispire.scanning.images.grype"),
                gitleaks: r.present("vectispire.scanning.images.gitleaks"),
                checkov: r.present("vectispire.scanning.images.checkov"),
                semgrep: r.present("vectispire.scanning.images.semgrep"),
            },
            plugin_registry: r.present("vectispire.scanning.plugin-registry"),
            plugin_signature_required: r.boolean("vectispire.scanning.plugin-signature-required"),
            bundled_rules: r.present("vectispire.scanning.bundled-rules"),
        };
        let threat_intel = ThreatIntel {
            kev_url: r.present("vectispire.threat-intel.kev-url"),
            kev_allow_private: r.boolean("vectispire.threat-intel.kev-allow-private"),
            epss_url: r.present("vectispire.threat-intel.epss-url"),
            epss_allow_private: r.boolean("vectispire.threat-intel.epss-allow-private"),
        };
        let branding = Branding {
            name: r.string("vectispire.branding.name"),
            gitlab_url: r.string("vectispire.branding.gitlab-url"),
        };
        let exports = Exports {
            public_url: r.present("vectispire.exports.public-url"),
            vex_author: r.string("vectispire.exports.vex-author"),
            tool_version: r.present("vectispire.exports.tool-version"),
        };
        let bootstrap = Bootstrap {
            username: r.present("vectispire.bootstrap.username"),
            password: r.secret("vectispire.bootstrap.password"),
        };
        let security = Security {
            trusted_proxies: r.string("vectispire.security.trusted-proxies"),
            anonymous_api_docs: r.boolean("vectispire.security.anonymous-api-docs"),
            bearer_failures_per_window: r.number("vectispire.security.bearer-failures-per-window"),
            bearer_failure_window: r.duration("vectispire.security.bearer-failure-window"),
            api_key_requests_per_minute: r.number("vectispire.security.api-key-requests-per-minute"),
            webhook_requests_per_window: r.number("vectispire.security.webhook-requests-per-window"),
            webhook_request_window: r.duration("vectispire.security.webhook-request-window"),
            login_attempts_per_window: r.number("vectispire.security.login-attempts-per-window"),
            login_attempt_window: r.duration("vectispire.security.login-attempt-window"),
        };
        let max_body = MaxBody {
            default: r.size("vectispire.http.max-body.default"),
            rule_set_upload: r.size("vectispire.http.max-body.rule-set-upload"),
            ticket_webhook: r.size("vectispire.http.max-body.ticket-webhook"),
            vex_ingest: r.size("vectispire.http.max-body.vex-ingest"),
            agent_result: r.size("vectispire.http.max-body.agent-result"),
            sign_in: r.size("vectispire.http.max-body.sign-in"),
            sarif_import: r.size("vectispire.http.max-body.sarif-import"),
            coverage_import: r.size("vectispire.http.max-body.coverage-import"),
            test_report_import: r.size("vectispire.http.max-body.test-report-import"),
            sbom_import: r.size("vectispire.http.max-body.sbom-import"),
            checklist_template_import: r.size("vectispire.http.max-body.checklist-template-import"),
            checklist_evidence: r.size("vectispire.http.max-body.checklist-evidence"),
        };
        let session = Session {
            absolute_lifetime: r.duration("vectispire.session.absolute-lifetime"),
            idle_lifetime: r.duration("vectispire.session.idle-lifetime"),
        };
        let oidc = Settings::oidc(&mut r);
        let git_allowed_hosts = r.string("vectispire.git.allowed-hosts");
        let audit_mirror_path =
            r.present("vectispire.audit.mirror-path").map(|path| path.trim_matches(|c: char| c <= ' ').to_owned());
        let encryption = Settings::encryption(&mut r);
        let signing_key = r.secret("vectispire.signing.key");
        let scim = Settings::scim(&mut r);
        let queue = Queue {
            retry_delays: Settings::retry_delays(&mut r),
            lease: r.duration("vectispire.queue.lease"),
            max_attempts: r.number("vectispire.queue.max-attempts"),
            claim_attempts: r.number("vectispire.queue.claim-attempts"),
        };
        let leader_lease = r.duration("vectispire.leader.lease");
        let worker = Worker {
            enabled: r.boolean("vectispire.worker.enabled"),
            max_concurrent: r.number("vectispire.worker.max-concurrent"),
            labels: r.string("vectispire.worker.labels"),
            interval: r.duration("vectispire.worker.interval"),
        };
        let reports = Reports {
            concurrency: r.number("vectispire.reports.concurrency"),
            interval: r.duration("vectispire.reports.interval"),
            lease: r.optional_duration("vectispire.reports.lease"),
        };
        let forges = Forges {
            discovery: Discovery {
                concurrency: r.number("vectispire.forges.discovery.concurrency"),
                interval: r.duration("vectispire.forges.discovery.interval"),
                max_repositories: r.number("vectispire.forges.discovery.max-repositories"),
                max_rate_limit_wait: r.duration("vectispire.forges.discovery.max-rate-limit-wait"),
                max_duration: r.duration("vectispire.forges.discovery.max-duration"),
            },
            reviews: Reviews {
                turn_duration: r.duration("vectispire.forges.reviews.turn-duration"),
                refresh: r.duration("vectispire.forges.reviews.refresh"),
                reading_duration: r.duration("vectispire.forges.reviews.reading-duration"),
                max_readings: r.number("vectispire.forges.reviews.max-readings"),
                max_rate_limit_wait: r.duration("vectispire.forges.reviews.max-rate-limit-wait"),
                max_changes: r.number("vectispire.forges.reviews.max-changes"),
                claim: r.duration("vectispire.forges.reviews.claim"),
            },
        };
        let jobs = Jobs {
            relay_interval: r.duration("vectispire.jobs.relay-interval"),
            scheduler_interval: r.duration("vectispire.jobs.scheduler-interval"),
            maintenance_interval: r.duration("vectispire.jobs.maintenance-interval"),
        };
        let mail = Settings::mail(&mut r);
        let api_docs = ApiDocs {
            swagger_ui: r.boolean("springdoc.swagger-ui.enabled"),
            api_docs: r.boolean("springdoc.api-docs.enabled"),
        };

        let surroundings = Surroundings {
            docker_host: variable_present(environment, "VECTISPIRE_DOCKER_HOST")
                .or_else(|| variable_present(environment, "DOCKER_HOST")),
            kubernetes_service_host: environment.variable("KUBERNETES_SERVICE_HOST").map(str::to_owned),
            kubernetes_service_port: environment.variable("KUBERNETES_SERVICE_PORT").map(str::to_owned),
        };

        if !r.problems.is_empty() {
            return Err(ConfigError { problems: r.problems });
        }
        let settings = Settings {
            server_port,
            datasource,
            scanning,
            threat_intel,
            branding,
            exports,
            bootstrap,
            security,
            max_body,
            session,
            oidc,
            git_allowed_hosts,
            audit_mirror_path,
            encryption,
            signing_key,
            scim,
            queue,
            leader_lease,
            worker,
            reports,
            forges,
            jobs,
            mail,
            api_docs,
            environment: surroundings,
        };
        Ok((settings, r.report))
    }

    fn oidc(r: &mut Reader<'_>) -> Oidc {
        let issuer = r.present("vectispire.oidc.issuer");
        let provider = issuer.map(|issuer| {
            let client_id = r.present("vectispire.oidc.client-id");
            if client_id.is_none() {
                r.problems.push(
                    "vectispire.oidc.client-id: a provider is named (vectispire.oidc.issuer) and no client id is"
                        .to_owned(),
                );
            }
            OidcProvider {
                issuer,
                client_id: client_id.unwrap_or_default(),
                client_secret: Secret::new(r.string("vectispire.oidc.client-secret")),
                name: r.string("vectispire.oidc.name"),
            }
        });
        Oidc {
            password_login: r.boolean("vectispire.oidc.password-login"),
            link_privileged_accounts: r.boolean("vectispire.oidc.link-privileged-accounts"),
            require_mfa: r.boolean("vectispire.oidc.require-mfa"),
            mfa_amr: r
                .string("vectispire.oidc.mfa-amr")
                .split(',')
                .map(|item| item.trim_matches(|c: char| c <= ' ').to_owned())
                .filter(|item| !item.is_empty())
                .collect(),
            mfa_acr: r.present("vectispire.oidc.mfa-acr"),
            provider,
        }
    }

    /// `EncryptionProperties.resolved()`: a key given as a file is read from it, and a value and a file
    /// for the same secret are refused rather than one chosen.
    fn encryption(r: &mut Reader<'_>) -> Encryption {
        let key = r.present("vectispire.encryption.key");
        let key_file =
            r.present("vectispire.encryption.key-file").map(|path| path.trim_matches(|c: char| c <= ' ').to_owned());
        let previous_raw = r.string("vectispire.encryption.previous-keys");
        let previous: Vec<String> = split_keys(&previous_raw, |c| c == ',');
        let previous_file = r
            .present("vectispire.encryption.previous-keys-file")
            .map(|path| path.trim_matches(|c: char| c <= ' ').to_owned());
        let vault_token = r.secret("vectispire.encryption.vault-token");
        let vault_token_file = r
            .present("vectispire.encryption.vault-token-file")
            .map(|path| path.trim_matches(|c: char| c <= ' ').to_owned());
        let kms_type =
            r.present("vectispire.encryption.kms-type").map(|v| v.trim_matches(|c: char| c <= ' ').to_owned());
        let vault_endpoint =
            r.present("vectispire.encryption.vault-endpoint").map(|v| v.trim_matches(|c: char| c <= ' ').to_owned());
        let vault_key_name =
            r.present("vectispire.encryption.vault-key-name").map(|v| v.trim_matches(|c: char| c <= ' ').to_owned());
        let vault_mount_path =
            r.present("vectispire.encryption.vault-mount-path").map(|v| v.trim_matches(|c: char| c <= ' ').to_owned());

        let mut resolved_key: Option<String> = key.clone();
        let mut resolved_previous: Vec<String> = previous.clone();
        let mut resolved_token = vault_token.clone();
        if key_file.is_some() || previous_file.is_some() || vault_token_file.is_some() {
            let mut check = |has_value: bool, has_file: bool, value: &str, file: &str| {
                if let Err(message) = secret_file::refuse_both(has_value, has_file, value, file) {
                    r.problems.push(message);
                }
            };
            check(key.is_some(), key_file.is_some(), "ENCRYPTION_KEY", "ENCRYPTION_KEY_FILE");
            check(
                !previous.is_empty(),
                previous_file.is_some(),
                "VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS",
                "VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE",
            );
            check(
                vault_token.is_some(),
                vault_token_file.is_some(),
                "VECTISPIRE_ENCRYPTION_VAULT_TOKEN",
                "VECTISPIRE_ENCRYPTION_VAULT_TOKEN_FILE",
            );
            let mut read = |path: &Option<String>, what: &str| {
                path.as_deref().and_then(|path| match secret_file::read(path, what) {
                    Ok(secret) => Some(secret),
                    Err(message) => {
                        r.problems.push(message);
                        None
                    }
                })
            };
            if let Some(secret) = read(&key_file, "ENCRYPTION_KEY_FILE") {
                resolved_key = Some(secret);
            }
            if let Some(content) = read(&previous_file, "VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE") {
                resolved_previous = split_keys(&content, |c| c == ',' || c == '\r' || c == '\n');
            }
            if let Some(secret) = read(&vault_token_file, "VECTISPIRE_ENCRYPTION_VAULT_TOKEN_FILE") {
                resolved_token = Some(Secret::new(secret));
            }
        }
        Encryption {
            key: resolved_key.map(Secret::new),
            previous_keys: resolved_previous.into_iter().map(Secret::new).collect(),
            kms_type,
            vault_endpoint,
            vault_token: resolved_token,
            vault_key_name,
            vault_mount_path,
        }
    }

    fn scim(r: &mut Reader<'_>) -> Scim {
        let enabled = r.boolean("vectispire.scim.enabled");
        let token = r.secret("vectispire.scim.token");
        let token_file =
            r.present("vectispire.scim.token-file").map(|path| path.trim_matches(|c: char| c <= ' ').to_owned());
        let resolved = match token_file.as_deref() {
            None => token,
            Some(path) => match secret_file::read(path, "VECTISPIRE_SCIM_TOKEN_FILE") {
                Ok(secret) => Some(Secret::new(secret)),
                Err(message) => {
                    r.problems.push(message);
                    token
                }
            },
        };
        Scim { enabled, token: resolved }
    }

    fn retry_delays(r: &mut Reader<'_>) -> Vec<Duration> {
        let text = r.string("vectispire.queue.retry-delays");
        let mut delays = Vec::new();
        for item in text.split(',').map(|item| item.trim_matches(|c: char| c <= ' ')).filter(|item| !item.is_empty()) {
            match parse_duration(item) {
                Ok(delay) => delays.push(delay),
                Err(message) => r.problems.push(format!("vectispire.queue.retry-delays: {message}")),
            }
        }
        delays
    }

    /// A relay exists only when a host is named — and an empty host is named.
    fn mail(r: &mut Reader<'_>) -> Option<Mail> {
        let host = r.raw("vectispire.mail.host")?;
        // `@ConditionalOnProperty` with no value to have: present, and not `false`.
        if host.eq_ignore_ascii_case("false") {
            return None;
        }
        Some(Mail {
            host,
            port: r.number("vectispire.mail.port"),
            username: r.string("vectispire.mail.username"),
            password: Secret::new(r.string("vectispire.mail.password")),
            starttls: r.boolean("vectispire.mail.starttls"),
        })
    }
}

/// `previousKeys.stream().map(String::trim).filter(!empty)`, split on the given separators.
fn split_keys(text: &str, separator: impl Fn(char) -> bool) -> Vec<String> {
    text.split(separator)
        .map(|item| item.trim_matches(|c: char| c <= ' ').to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}
