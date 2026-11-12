//! The settings as an operator meets them: what a deployment sets, and what comes out.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use vectispire_cp_runtime::property::{Environment, Origin};
use vectispire_cp_runtime::settings::Settings;

fn load(variables: &[(&str, &str)]) -> Settings {
    Settings::load(&Environment::of(variables.iter().copied(), [])).unwrap().0
}

fn problems(variables: &[(&str, &str)], files: &[(&str, &str)]) -> Vec<String> {
    Settings::load(&Environment::of(variables.iter().copied(), files.iter().copied())).unwrap_err().problems
}

#[test]
fn an_empty_environment_is_the_defaults_of_a_single_instance_deployment() {
    let settings = load(&[]);
    assert_eq!(settings.server_port, 3180);
    assert_eq!(settings.datasource.url, "jdbc:mysql://localhost:3306/vectispire");
    assert_eq!(settings.datasource.username, "vectispire");
    assert_eq!(settings.session.absolute_lifetime, Duration::from_secs(12 * 3_600));
    assert_eq!(settings.session.idle_lifetime, Duration::from_secs(3_600));
    assert_eq!(settings.queue.retry_delays, [60, 300, 900].map(Duration::from_secs));
    assert_eq!(
        (settings.queue.lease, settings.queue.max_attempts, settings.queue.claim_attempts),
        (Duration::from_secs(1_200), 3, 12)
    );
    assert_eq!(settings.leader_lease, Duration::from_secs(180));
    assert!(settings.worker.enabled);
    assert_eq!(settings.worker.max_concurrent, 2);
    assert_eq!(settings.worker.interval, Duration::from_secs(15));
    assert_eq!(settings.reports.interval, Duration::from_secs(10));
    assert_eq!(settings.reports.lease, None);
    assert_eq!(settings.forges.discovery.max_repositories, 20_000);
    assert_eq!(settings.forges.discovery.max_duration, Duration::from_secs(1_800));
    assert_eq!(settings.forges.reviews.max_readings, 200);
    assert_eq!(settings.jobs.maintenance_interval, Duration::from_secs(3_600));
    assert_eq!(settings.max_body.default, 1 << 20);
    assert_eq!(settings.max_body.agent_result, 256 << 20);
    assert_eq!(settings.max_body.sign_in, 16 << 10);
    assert_eq!(settings.max_body.checklist_evidence, 25 << 20);
    assert_eq!(settings.security.bearer_failure_window, Duration::from_secs(300));
    assert_eq!(
        (settings.security.login_attempts_per_window, settings.security.login_attempt_window),
        (10, Duration::from_secs(60))
    );
    assert_eq!(settings.branding.name, "Vectispire");
    assert_eq!(settings.exports.vex_author, "Vectispire");
    assert!(settings.oidc.password_login && !settings.oidc.require_mfa && !settings.oidc.link_privileged_accounts);
    assert_eq!(settings.oidc.mfa_amr, ["mfa", "otp", "hwk", "fido"]);
    assert!(settings.oidc.provider.is_none() && settings.mail.is_none());
    assert!(settings.scanning.host_ssh && settings.scanning.plugin_signature_required);
    assert!(!settings.api_docs.swagger_ui && !settings.api_docs.api_docs);
    assert!(!settings.scim.enabled);
    assert!(settings.audit_mirror_path.is_none() && settings.signing_key.is_none());
}

#[test]
fn what_a_deployment_sets_under_the_names_it_always_used_is_read() {
    let settings = load(&[
        ("VECTISPIRE_PORT", "8443"),
        ("VECTISPIRE_DB_URL", "jdbc:postgresql://pg:5432/v"),
        ("VECTISPIRE_SESSION_LIFETIME", "PT8H"),
        ("VECTISPIRE_SCAN_RETRY_DELAYS", "30s, 2m"),
        ("VECTISPIRE_EMBEDDED_WORKER", "false"),
        ("VECTISPIRE_MAX_BODY_AGENT_RESULT", "512MB"),
        ("VECTISPIRE_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.0.1"),
        ("VECTISPIRE_INSTANCE_NAME", "Acme"),
        ("VECTISPIRE_AUDIT_MIRROR", " /var/log/vectispire/audit.ndjson "),
        ("VECTISPIRE_OIDC_MFA_AMR", "mfa, ,otp"),
    ]);
    assert_eq!(settings.server_port, 8443);
    assert_eq!(settings.datasource.url, "jdbc:postgresql://pg:5432/v");
    assert_eq!(settings.session.absolute_lifetime, Duration::from_secs(8 * 3_600));
    assert_eq!(settings.queue.retry_delays, [30, 120].map(Duration::from_secs));
    assert!(!settings.worker.enabled);
    assert_eq!(settings.max_body.agent_result, 512 << 20);
    assert_eq!(settings.security.trusted_proxies, "10.0.0.0/8, 192.168.0.1");
    assert_eq!(settings.branding.name, "Acme");
    assert_eq!(
        settings.exports.vex_author, "Vectispire",
        "the VEX author follows its own chain, not the brand's instance name"
    );
    assert_eq!(settings.audit_mirror_path.as_deref(), Some("/var/log/vectispire/audit.ndjson"));
    assert_eq!(settings.oidc.mfa_amr, ["mfa", "otp"]);
}

#[test]
fn every_problem_is_named_at_once_and_none_shows_a_secret() {
    let problems = problems(
        &[
            ("VECTISPIRE_PORT", "abc"),
            ("VECTISPIRE_SESSION_LIFETIME", "twelve"),
            ("VECTISPIRE_MAX_BODY_DEFAULT", "1mb"),
            ("VECTISPIRE_EMBEDDED_WORKER", "maybe"),
            ("VECTISPIRE_DB_PASSWORD", "hunter2"),
        ],
        &[],
    );
    assert_eq!(problems.len(), 4, "{problems:#?}");
    assert!(problems.iter().any(|p| p.starts_with("server.port: ") && p.contains("'abc'")));
    assert!(
        problems
            .iter()
            .any(|p| p.starts_with("vectispire.session.absolute-lifetime: 'twelve' is not a valid duration"))
    );
    assert!(problems.iter().any(|p| p.starts_with("vectispire.http.max-body.default: '1mb' is not a valid data size")));
    assert!(problems.iter().any(|p| p.starts_with("vectispire.worker.enabled: Invalid boolean value 'maybe'")));
    assert!(problems.iter().all(|p| !p.contains("hunter2")));
}

#[test]
fn a_secret_is_never_in_a_debug_dump_or_the_report() {
    let environment = Environment::of(
        [
            ("VECTISPIRE_DB_PASSWORD", "hunter2"),
            ("ENCRYPTION_KEY", "k3y-material"),
            ("VECTISPIRE_BOOTSTRAP_PASSWORD", "boot-pw"),
            ("VECTISPIRE_MAIL_HOST", "smtp.example.org"),
            ("VECTISPIRE_MAIL_PASSWORD", "mail-pw"),
        ],
        [],
    );
    let (settings, report) = Settings::load(&environment).unwrap();
    let dump = format!("{settings:?}");
    for secret in ["hunter2", "k3y-material", "boot-pw", "mail-pw"] {
        assert!(!dump.contains(secret), "{secret} is in the debug dump");
        assert!(report.iter().all(|line| !line.shown.contains(secret)), "{secret} is in the report");
    }
    let line = |key: &str| report.iter().find(|line| line.key == key).unwrap();
    assert_eq!(line("spring.datasource.password").shown, "(set)");
    assert_eq!(line("vectispire.encryption.key").shown, "(set)");
    assert_eq!(line("vectispire.encryption.key").origin, Origin::Variable("ENCRYPTION_KEY".to_owned()));
    assert_eq!(line("vectispire.signing.key").shown, "(not set)");
    assert_eq!(line("server.port").shown, "3180");
    assert_eq!(line("server.port").origin, Origin::Default);
}

#[test]
fn a_secret_given_as_a_file_is_read_from_it_and_a_value_beside_it_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("key");
    std::fs::write(&key, "  file-key\n").unwrap();
    let previous = directory.path().join("previous");
    std::fs::write(&previous, "old-1, old-2\nold-3\r\n").unwrap();
    let token = directory.path().join("token");
    std::fs::write(&token, "scim-token\n").unwrap();

    let environment = Environment::of(
        [
            ("ENCRYPTION_KEY_FILE", key.to_str().unwrap()),
            ("VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE", previous.to_str().unwrap()),
            ("VECTISPIRE_SCIM_TOKEN_FILE", token.to_str().unwrap()),
        ],
        [],
    );
    let (settings, _) = Settings::load(&environment).unwrap();
    assert_eq!(settings.encryption.key.as_ref().map(|k| k.expose()), Some("file-key"));
    let previous: Vec<&str> = settings.encryption.previous_keys.iter().map(|k| k.expose()).collect();
    assert_eq!(previous, ["old-1", "old-2", "old-3"]);
    assert_eq!(settings.scim.token.as_ref().map(|t| t.expose()), Some("scim-token"));

    let both = problems(&[("ENCRYPTION_KEY", "from-variable"), ("ENCRYPTION_KEY_FILE", key.to_str().unwrap())], &[]);
    assert_eq!(both.len(), 1);
    assert!(both[0].starts_with("ENCRYPTION_KEY and ENCRYPTION_KEY_FILE are both set."), "{}", both[0]);

    let empty = directory.path().join("empty");
    std::fs::write(&empty, "\n").unwrap();
    let refused = problems(&[("ENCRYPTION_KEY_FILE", empty.to_str().unwrap())], &[]);
    assert!(
        refused[0].starts_with("ENCRYPTION_KEY_FILE points at ") && refused[0].contains("which is empty."),
        "{}",
        refused[0]
    );
}

#[test]
fn a_secret_as_a_config_tree_file_answers_as_the_variable_would() {
    // The shipped compose hands the secrets over this way, and nothing else changes.
    let environment = Environment::of([], [("ENCRYPTION_KEY", "from-the-tree"), ("VECTISPIRE_DB_PASSWORD", "tree-pw")]);
    let (settings, report) = Settings::load(&environment).unwrap();
    assert_eq!(settings.encryption.key.as_ref().map(|k| k.expose()), Some("from-the-tree"));
    assert_eq!(settings.datasource.password.expose(), "tree-pw");
    let line = report.iter().find(|line| line.key == "vectispire.encryption.key").unwrap();
    assert_eq!(line.origin, Origin::File("ENCRYPTION_KEY".to_owned()));
}

#[test]
fn a_mail_relay_exists_when_a_host_is_named_even_an_empty_one() {
    assert!(load(&[]).mail.is_none());
    let empty = load(&[("VECTISPIRE_MAIL_HOST", "")])
        .mail
        .expect("an empty host is a host: Spring counts a variable set to nothing as present");
    assert_eq!((empty.host.as_str(), empty.port, empty.starttls), ("", 587, true));
    assert!(load(&[("VECTISPIRE_MAIL_HOST", "false")]).mail.is_none(), "ConditionalOnProperty: present and not false");
    let full = load(&[
        ("VECTISPIRE_MAIL_HOST", "smtp.example.org"),
        ("VECTISPIRE_MAIL_PORT", "2525"),
        ("VECTISPIRE_MAIL_STARTTLS", "false"),
        ("VECTISPIRE_MAIL_USERNAME", "u"),
    ])
    .mail
    .unwrap();
    assert_eq!(
        (full.host.as_str(), full.port, full.starttls, full.username.as_str()),
        ("smtp.example.org", 2525, false, "u")
    );
}

#[test]
fn a_provider_needs_its_client_id_and_exists_only_when_an_issuer_is_named() {
    let named = load(&[
        ("VECTISPIRE_OIDC_ISSUER", "https://sso.example.org/realms/x"),
        ("VECTISPIRE_OIDC_CLIENT_ID", "vectispire"),
        ("VECTISPIRE_OIDC_CLIENT_SECRET", "s"),
    ]);
    let provider = named.oidc.provider.unwrap();
    assert_eq!(
        (provider.issuer.as_str(), provider.client_id.as_str(), provider.name.as_str()),
        ("https://sso.example.org/realms/x", "vectispire", "Single sign-on")
    );
    assert_eq!(provider.client_secret.expose(), "s");
    let missing = problems(&[("VECTISPIRE_OIDC_ISSUER", "https://sso.example.org")], &[]);
    assert!(missing[0].starts_with("vectispire.oidc.client-id: a provider is named"), "{}", missing[0]);
}

#[test]
fn the_docker_host_is_the_vectispire_variable_then_docker_s_and_blank_is_none() {
    assert_eq!(load(&[]).environment.docker_host, None);
    assert_eq!(load(&[("DOCKER_HOST", " tcp://d:2375 ")]).environment.docker_host.as_deref(), Some("tcp://d:2375"));
    assert_eq!(
        load(&[("DOCKER_HOST", "tcp://d:2375"), ("VECTISPIRE_DOCKER_HOST", "tcp://proxy:2375")])
            .environment
            .docker_host
            .as_deref(),
        Some("tcp://proxy:2375")
    );
    assert_eq!(
        load(&[("VECTISPIRE_DOCKER_HOST", "  "), ("DOCKER_HOST", "tcp://d:1")]).environment.docker_host.as_deref(),
        Some("tcp://d:1")
    );
}
