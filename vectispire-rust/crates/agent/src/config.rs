//! The agent's configuration — `AgentProperties` and `application.yaml`: **the same variable names**,
//! so a deployment moving from the Java agent to this one changes its image and nothing else.

use std::time::Duration;
use vectispire_domain::secret::Secret;

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
}

impl Config {
    /// From the process environment.
    pub fn from_environment() -> Result<Config, ConfigError> {
        Config::from_lookup(|name| std::env::var(name).ok())
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
        })
    }
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

    #[test]
    fn a_missing_token_is_refused_with_what_it_is() {
        let refused =
            Config::from_lookup(|name| (name == "VECTISPIRE_URL").then(|| "https://x".to_owned())).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "VECTISPIRE_AGENT_TOKEN is required: the API key shown once when the agent was created."
        );
    }
}
