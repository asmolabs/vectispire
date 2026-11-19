//! The agent's configuration — `AgentProperties` and `application.yaml`: **the same variable names**,
//! so a deployment moving from the Java agent to this one changes its image and nothing else.

use std::time::Duration;
use vectispire_domain::secret::Secret;
use vectispire_kubernetes::choice::{self, KubernetesConfig};

/// What a variable holds, read once at start.
#[derive(Debug)]
pub struct Config {
    /// `VECTISPIRE_URL`, trailing slashes removed.
    pub url: String,
    /// `VECTISPIRE_AGENT_TOKEN`: the API key shown once when the agent was created.
    pub token: Secret,
    /// `VECTISPIRE_AGENT_WAIT`, 1 s to 5 min, default 30 s: how long a claim waits on the server.
    pub claim_wait: Duration,
    /// `VECTISPIRE_AGENT_RETRY`, 1 s to 5 min, default 10 s: the pause after a failed call.
    pub retry_delay: Duration,
    /// `VECTISPIRE_AGENT_HEARTBEAT`, 5 s to 10 min, default 60 s: how often a running scan says it is.
    pub heartbeat: Duration,
    /// `VECTISPIRE_AGENT_SIGNING_KEY`: the Ed25519 seed an administrator pinned, or none.
    pub signing_key: Option<Secret>,
    /// `VECTISPIRE_VULNERABILITY_DB_DIR`: where the matcher's database is kept for every scan; none is a
    /// directory beside the workspaces.
    pub vulnerability_db_dir: Option<std::path::PathBuf>,
    /// `VECTISPIRE_AGENT_EXECUTOR`: what runs the scanners — `docker`, or `kubernetes`, a pod per run in a namespace of
    /// its own (decision 0045). Lower-cased; blank is `docker`; anything else stops the start, at the choice.
    pub executor: String,
    /// The Kubernetes executor's settings, read whatever the kind, used only when it is `kubernetes`.
    pub kubernetes: KubernetesConfig,
}

/// A configuration the agent cannot start with — the Java agent's sentences, with the variable
/// names an operator sets.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("VECTISPIRE_URL is required: the control plane's address.")]
    MissingUrl,
    #[error("VECTISPIRE_AGENT_TOKEN is required: the API key shown once when the agent was created.")]
    MissingToken,
    #[error("{variable} is not a duration: {value:?}. Write it as 30s, 500ms, 2m or PT30S.")]
    Duration { variable: &'static str, value: String },
    #[error("{variable} is not true or false: {value:?}.")]
    Boolean { variable: &'static str, value: String },
    #[error("{variable} is not a whole number: {value:?}.")]
    Number { variable: &'static str, value: String },
    #[error("{0}")]
    Executor(String),
}

impl Config {
    /// From the process environment, then from the configuration trees `SPRING_CONFIG_IMPORT` names —
    /// how the composition and the chart hand the token and the signing key over: as files under
    /// `/run/secrets/`, never as variables, which any client of the daemon can read.
    pub fn from_environment() -> Result<Config, ConfigError> {
        let trees = config_trees(std::env::var("SPRING_CONFIG_IMPORT").ok().as_deref());
        Config::from_lookup(|name| std::env::var(name).ok().or_else(|| from_trees(&trees, name)))
    }

    /// From any lookup — the tests' own.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Config, ConfigError> {
        let text = |name: &str| lookup(name).map(|value| value.trim().to_owned()).filter(|value| !value.is_empty());
        let url = text("VECTISPIRE_URL").ok_or(ConfigError::MissingUrl)?.trim_end_matches('/').to_owned();
        let token = Secret::new(text("VECTISPIRE_AGENT_TOKEN").ok_or(ConfigError::MissingToken)?);
        let duration = |variable: &'static str,
                        default: Duration,
                        min: Duration,
                        max: Duration|
         -> Result<Duration, ConfigError> {
            let value = match text(variable) {
                None => default,
                Some(value) => spring_duration(&value).ok_or(ConfigError::Duration { variable, value })?,
            };
            Ok(value.clamp(min, max))
        };
        Ok(Config {
            url,
            token,
            claim_wait: duration("VECTISPIRE_AGENT_WAIT", secs(30), secs(1), secs(300))?,
            retry_delay: duration("VECTISPIRE_AGENT_RETRY", secs(10), secs(1), secs(300))?,
            heartbeat: duration("VECTISPIRE_AGENT_HEARTBEAT", secs(60), secs(5), secs(600))?,
            signing_key: text("VECTISPIRE_AGENT_SIGNING_KEY").map(Secret::new),
            vulnerability_db_dir: text("VECTISPIRE_VULNERABILITY_DB_DIR").map(std::path::PathBuf::from),
            executor: choice::kind(&lookup("VECTISPIRE_AGENT_EXECUTOR").unwrap_or_default()),
            kubernetes: kubernetes(&lookup)?,
        })
    }
}

/// `vectispire.agent.executor.kubernetes.*`, from the variables the chart sets (`agents/deployment.yaml`) — and the
/// probe's target from the one Spring binds it from, which the chart does not set. Strings trimmed, as the Java
/// properties trim them; a resource that is not positive refused here, as Java's binding refuses it.
fn kubernetes(lookup: &impl Fn(&str) -> Option<String>) -> Result<KubernetesConfig, ConfigError> {
    let defaults = KubernetesConfig::default();
    let text =
        |name: &str| lookup(name).map(|value| vectispire_domain::java::trim(&value).to_owned()).unwrap_or_default();
    let or = |name: &str, default: &str| {
        Some(text(name)).filter(|value| !value.is_empty()).unwrap_or_else(|| default.to_owned())
    };
    let number = |variable: &'static str, default: i64| -> Result<i64, ConfigError> {
        match text(variable) {
            value if value.is_empty() => Ok(default),
            value => value.parse().map_err(|_| ConfigError::Number { variable, value }),
        }
    };
    let start_timeout = match text("VECTISPIRE_KUBERNETES_START_TIMEOUT") {
        value if value.is_empty() => defaults.start_timeout,
        value => spring_duration(&value)
            .ok_or(ConfigError::Duration { variable: "VECTISPIRE_KUBERNETES_START_TIMEOUT", value })?,
    };
    // Spring's boolean conversion: true, on, yes, 1 and their opposites, in any case.
    let require_isolation = match text("VECTISPIRE_KUBERNETES_REQUIRE_ISOLATION").to_lowercase().as_str() {
        "" | "true" | "on" | "yes" | "1" => true,
        "false" | "off" | "no" | "0" => false,
        _ => {
            return Err(ConfigError::Boolean {
                variable: "VECTISPIRE_KUBERNETES_REQUIRE_ISOLATION",
                value: text("VECTISPIRE_KUBERNETES_REQUIRE_ISOLATION"),
            });
        }
    };
    let config = KubernetesConfig {
        namespace: text("VECTISPIRE_SCANS_NAMESPACE"),
        name: or("VECTISPIRE_AGENT_NAME", &defaults.name),
        helper_image: text("VECTISPIRE_KUBERNETES_HELPER_IMAGE"),
        user: text("VECTISPIRE_KUBERNETES_SCAN_USER"),
        start_timeout,
        placement: text("VECTISPIRE_KUBERNETES_PLACEMENT"),
        require_isolation,
        probe_target: text("VECTISPIRE_AGENT_EXECUTOR_KUBERNETES_PROBETARGET"),
        cpu_millis: number("VECTISPIRE_KUBERNETES_SCAN_CPU_MILLIS", defaults.cpu_millis)?,
        memory_mib: number("VECTISPIRE_KUBERNETES_SCAN_MEMORY_MIB", defaults.memory_mib)?,
        matcher_cache_claim: text("VECTISPIRE_KUBERNETES_MATCHER_CACHE_CLAIM"),
        node_name: text("VECTISPIRE_KUBERNETES_NODE_NAME"),
        registry_credentials: text("VECTISPIRE_KUBERNETES_REGISTRY_CREDENTIALS"),
    };
    choice::check_resources(config.cpu_millis, config.memory_mib).map_err(ConfigError::Executor)?;
    Ok(config)
}

/// The directories of `spring.config.import`'s `configtree:` entries (`optional:` or not), in order.
pub fn config_trees(import: Option<&str>) -> Vec<std::path::PathBuf> {
    import
        .unwrap_or("")
        .split([',', ';'])
        .map(str::trim)
        .filter_map(|entry| entry.strip_prefix("optional:").unwrap_or(entry).strip_prefix("configtree:"))
        .filter(|directory| !directory.is_empty())
        .map(std::path::PathBuf::from)
        .collect()
}

/// A property's file in the first tree holding one — its whole content, as Spring reads it.
fn from_trees(trees: &[std::path::PathBuf], name: &str) -> Option<String> {
    // A name is a plain file name: one that is not cannot reach outside the tree.
    if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') {
        return None;
    }
    trees.iter().find_map(|tree| std::fs::read_to_string(tree.join(name)).ok())
}

fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

/// A duration as Spring Boot binds one: `30s`, `500ms`, `2m`, `1h`, `1d`, `100us`, `5ns`, ISO-8601
/// (`PT30S`), or a bare number of milliseconds.
pub fn spring_duration(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Some(iso) = value.strip_prefix("PT").or_else(|| value.strip_prefix("pt")) {
        return iso_time(iso);
    }
    let digits_end = value.find(|c: char| !(c.is_ascii_digit() || c == '-' || c == '+')).unwrap_or(value.len());
    let (number, unit) = value.split_at(digits_end);
    let amount: u64 = number.trim_start_matches('+').parse().ok()?;
    let nanos_per = match unit.trim().to_lowercase().as_str() {
        "" | "ms" => 1_000_000,
        "ns" => 1,
        "us" => 1_000,
        "s" => 1_000_000_000,
        "m" => 60_000_000_000,
        "h" => 3_600_000_000_000,
        "d" => 86_400_000_000_000,
        _ => return None,
    };
    Some(Duration::from_nanos(amount.checked_mul(nanos_per)?))
}

/// The time part of an ISO-8601 duration: `1H2M3.5S`.
fn iso_time(text: &str) -> Option<Duration> {
    let mut total = 0f64;
    let mut number = String::new();
    for c in text.to_uppercase().chars() {
        match c {
            '0'..='9' | '.' => number.push(c),
            'H' | 'M' | 'S' => {
                let amount: f64 = number.parse().ok()?;
                number.clear();
                total += amount
                    * match c {
                        'H' => 3600.0,
                        'M' => 60.0,
                        _ => 1.0,
                    };
            }
            _ => return None,
        }
    }
    (number.is_empty() && total >= 0.0).then(|| Duration::from_secs_f64(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_as_spring_reads_them_and_are_clamped_as_the_java_agent_clamps_them() {
        assert_eq!(spring_duration("30s"), Some(secs(30)));
        assert_eq!(spring_duration("1500"), Some(Duration::from_millis(1500)));
        assert_eq!(spring_duration("PT1M30S"), Some(secs(90)));
        assert_eq!(spring_duration("2m"), Some(secs(120)));
        assert_eq!(spring_duration("thirty"), None);
        let config = Config::from_lookup(|name| match name {
            "VECTISPIRE_URL" => Some("https://vectispire.example.org//".into()),
            "VECTISPIRE_AGENT_TOKEN" => Some(" invented ".into()),
            "VECTISPIRE_AGENT_WAIT" => Some("1h".into()),
            "VECTISPIRE_AGENT_HEARTBEAT" => Some("1s".into()),
            _ => None,
        })
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(config.url, "https://vectispire.example.org");
        assert_eq!(config.token.expose(), "invented");
        assert_eq!((config.claim_wait, config.retry_delay, config.heartbeat), (secs(300), secs(10), secs(5)));
        assert!(format!("{config:?}").contains("Secret(***)"), "the API key is not in a debug dump");
    }

    /// The chart's variables, under the names it renders them (`agents/deployment.yaml`), and Java's defaults.
    #[test]
    fn the_kubernetes_executor_is_configured_by_the_chart_s_variables() {
        let base = |name: &str| match name {
            "VECTISPIRE_URL" => Some("https://cp".to_owned()),
            "VECTISPIRE_AGENT_TOKEN" => Some("vsk".to_owned()),
            _ => None,
        };
        let docker = Config::from_lookup(base).unwrap();
        assert_eq!(docker.executor, "docker");
        assert_eq!(docker.kubernetes, KubernetesConfig::default());
        assert!(docker.kubernetes.require_isolation, "isolation is required unless said otherwise");

        let configured = Config::from_lookup(|name| {
            base(name).or(match name {
                "VECTISPIRE_AGENT_EXECUTOR" => Some(" Kubernetes ".into()),
                "VECTISPIRE_SCANS_NAMESPACE" => Some(" release-scans ".into()),
                "VECTISPIRE_AGENT_NAME" => Some("release".into()),
                "VECTISPIRE_KUBERNETES_START_TIMEOUT" => Some("3m".into()),
                "VECTISPIRE_KUBERNETES_PLACEMENT" => Some("{\"nodeSelector\":{}}".into()),
                "VECTISPIRE_KUBERNETES_REQUIRE_ISOLATION" => Some("FALSE".into()),
                "VECTISPIRE_KUBERNETES_SCAN_CPU_MILLIS" => Some("250".into()),
                "VECTISPIRE_KUBERNETES_SCAN_MEMORY_MIB" => Some("128".into()),
                "VECTISPIRE_KUBERNETES_MATCHER_CACHE_CLAIM" => Some("release-matcher-cache".into()),
                "VECTISPIRE_KUBERNETES_NODE_NAME" => Some("node-a".into()),
                "VECTISPIRE_AGENT_EXECUTOR_KUBERNETES_PROBETARGET" => Some("10.43.0.1:443".into()),
                _ => None,
            })
        })
        .unwrap();
        assert_eq!(configured.executor, "kubernetes");
        let kubernetes = configured.kubernetes;
        assert_eq!((kubernetes.namespace.as_str(), kubernetes.name.as_str()), ("release-scans", "release"));
        assert_eq!(kubernetes.start_timeout, secs(180));
        assert!(!kubernetes.require_isolation);
        assert_eq!((kubernetes.cpu_millis, kubernetes.memory_mib), (250, 128));
        assert_eq!(kubernetes.placement, "{\"nodeSelector\":{}}");
        assert_eq!(kubernetes.probe_target, "10.43.0.1:443");
        assert_eq!(
            (kubernetes.matcher_cache_claim.as_str(), kubernetes.node_name.as_str()),
            ("release-matcher-cache", "node-a")
        );

        for (variable, value, said) in [
            ("VECTISPIRE_KUBERNETES_SCAN_CPU_MILLIS", "0", "cpu-millis and memory-mib are positive"),
            ("VECTISPIRE_KUBERNETES_SCAN_MEMORY_MIB", "lots", "is not a whole number"),
            ("VECTISPIRE_KUBERNETES_REQUIRE_ISOLATION", "maybe", "is not true or false"),
            ("VECTISPIRE_KUBERNETES_START_TIMEOUT", "soon", "is not a duration"),
        ] {
            let refused = Config::from_lookup(|name| base(name).or((name == variable).then(|| value.to_owned())));
            assert!(refused.unwrap_err().to_string().contains(said), "{variable}={value}");
        }
    }

    #[test]
    fn a_missing_token_is_refused_with_what_it_is() {
        let refused =
            Config::from_lookup(|name| (name == "VECTISPIRE_URL").then(|| "https://x".to_owned())).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "VECTISPIRE_AGENT_TOKEN is required: the API key shown once when the agent was created."
        );
    }

    #[test]
    fn the_secrets_are_read_from_the_configuration_tree_the_composition_names() {
        assert_eq!(
            config_trees(Some("optional:configtree:/run/secrets/, configtree:/other/")),
            vec![std::path::PathBuf::from("/run/secrets/"), std::path::PathBuf::from("/other/")]
        );
        assert!(config_trees(Some("classpath:x.yaml")).is_empty());
        assert!(config_trees(None).is_empty());

        let tree = tempfile::tempdir().unwrap();
        std::fs::write(tree.path().join("VECTISPIRE_AGENT_TOKEN"), "vsk_test\n").unwrap();
        let trees = vec![tree.path().to_owned()];
        assert_eq!(from_trees(&trees, "VECTISPIRE_AGENT_TOKEN").as_deref(), Some("vsk_test\n"));
        assert_eq!(from_trees(&trees, "../VECTISPIRE_AGENT_TOKEN"), None);
        let config = Config::from_lookup(|name| {
            (name == "VECTISPIRE_URL").then(|| "https://cp.example/".to_owned()).or_else(|| from_trees(&trees, name))
        })
        .unwrap();
        assert_eq!(config.token.expose(), "vsk_test", "trimmed as every variable is");
    }
}
