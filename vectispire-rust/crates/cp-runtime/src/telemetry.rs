//! The logs — Spring Boot's console format, or JSON.
//!
//! **Plain is the Java control plane's own format**, so that what an operator greps for and what a
//! collector's parser was written against keep meaning the same:
//!
//! ```text
//! 2026-10-15T07:30:10.527Z  INFO 3278 --- [vectispire] [ionShutdownHook] j.LocalContainerEntityManagerFactoryBean : Closing JPA…
//! ```
//!
//! — an ISO-8601 instant with milliseconds, the level right-aligned to five, the process id, the
//! application, the thread cut to its last fifteen characters, the logger abbreviated to thirty-nine
//! (`com.asmolabs.vectispire.core.audit` becomes `c.a.v.core.audit`) and padded, a colon, the message. **The
//! instant is UTC**: a container's zone is UTC, and the offset a Java process would print on a host set to
//! another zone is not ported.
//!
//! **JSON is new**, for a collector that would rather not parse the plain line (`VECTISPIRE_LOG_FORMAT=json`);
//! the Java control plane has none by default. The level is `RUST_LOG`'s, or `LOGGING_LEVEL_ROOT`'s — Spring's
//! variable for the root logger — or `info`.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// How a log line is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    Plain,
    Json,
}

impl LogFormat {
    /// `VECTISPIRE_LOG_FORMAT`: `plain` (the default) or `json`.
    pub fn from_variable(value: Option<&str>) -> Result<LogFormat, String> {
        match value.map(|value| value.trim().to_lowercase()).as_deref() {
            None | Some("") | Some("plain") => Ok(LogFormat::Plain),
            Some("json") => Ok(LogFormat::Json),
            Some(other) => Err(format!("VECTISPIRE_LOG_FORMAT: '{other}' is neither plain nor json")),
        }
    }
}

/// Installs the global subscriber. A second call, or a test that already did, is an error the caller may ignore.
pub fn init(format: LogFormat, application: &str) -> Result<(), String> {
    let level = std::env::var("RUST_LOG")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("LOGGING_LEVEL_ROOT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(|level| level.trim().to_lowercase())
        })
        .unwrap_or_else(|| "info".to_owned());
    let filter = tracing_subscriber::EnvFilter::try_new(&level)
        .map_err(|error| format!("The log level '{level}' is not usable: {error}"))?;
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stdout);
    let outcome = match format {
        LogFormat::Plain => {
            builder.event_format(Spring { application: application.to_owned(), pid: std::process::id() }).try_init()
        }
        LogFormat::Json => builder.json().try_init(),
    };
    outcome.map_err(|error| error.to_string())
}

/// Spring Boot's console pattern: `%d{yyyy-MM-dd'T'HH:mm:ss.SSSXXX} %5p ${PID} --- [app] [%15.15t] %-40.40logger{39} : %m%n`.
#[derive(Debug)]
pub struct Spring {
    pub application: String,
    pub pid: u32,
}

impl<S, N> FormatEvent<S, N> for Spring
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(&self, context: &FmtContext<'_, S, N>, mut writer: Writer<'_>, event: &Event<'_>) -> fmt::Result {
        let metadata = event.metadata();
        let thread = std::thread::current();
        let thread = thread.name().map_or_else(|| format!("{:?}", std::thread::current().id()), str::to_owned);
        write!(
            writer,
            "{} {:>5} {} --- [{}] [{}] {} : ",
            timestamp(SystemTime::now()),
            metadata.level(),
            self.pid,
            self.application,
            pad_left_cut_start(&thread, 15),
            pad_right_cut_start(&logger(metadata.target()), 40),
        )?;
        context.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// `2026-10-15T07:30:10.527Z`.
pub fn timestamp(now: SystemTime) -> String {
    let since = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    let (seconds, millis) = (since.as_secs() as i64, since.subsec_millis());
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z", rest / 3_600, rest % 3_600 / 60, rest % 60)
}

/// Days since 1970-01-01 as a civil date — Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 { month_prime + 3 } else { month_prime - 9 } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `%15.15t`: at least fifteen and at most fifteen characters, padded on the left and cut from the start.
fn pad_left_cut_start(text: &str, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let kept: String = chars[chars.len().saturating_sub(width)..].iter().collect();
    format!("{kept:>width$}")
}

/// `%-40.40logger`: padded on the right, cut from the start when longer.
fn pad_right_cut_start(text: &str, width: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let kept: String = chars[chars.len().saturating_sub(width)..].iter().collect();
    format!("{kept:<width$}")
}

/// A Rust target as a Java logger name, abbreviated to 39 characters as Logback's `%logger{39}` does:
/// leading segments shrink to their first letter, left to right, until it fits; the last never does.
pub fn logger(target: &str) -> String {
    let dotted = target.replace("::", ".");
    let mut segments: Vec<String> = dotted.split('.').map(str::to_owned).collect();
    let last = segments.len().saturating_sub(1);
    for index in 0..last {
        if segments.join(".").chars().count() <= 39 {
            break;
        }
        segments[index] = segments[index].chars().take(1).collect();
    }
    segments.join(".")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_instant_is_iso_8601_in_utc_with_milliseconds() {
        assert_eq!(timestamp(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(timestamp(UNIX_EPOCH + Duration::from_millis(1_791_714_610_527)), "2026-10-11T10:30:10.527Z");
        // A leap day, and the end of a century that is not a leap year.
        assert_eq!(timestamp(UNIX_EPOCH + Duration::from_secs(951_782_400)), "2000-02-29T00:00:00.000Z");
        assert_eq!(timestamp(UNIX_EPOCH + Duration::from_secs(4_107_542_400)), "2100-03-01T00:00:00.000Z");
    }

    #[test]
    fn the_thread_and_the_logger_are_cut_and_padded_as_logback_does() {
        assert_eq!(pad_left_cut_start("main", 15), "           main");
        assert_eq!(pad_left_cut_start("SpringApplicationShutdownHook", 15), "ionShutdownHook");
        assert_eq!(pad_right_cut_start("a.b", 8), "a.b     ");
        assert_eq!(logger("vectispire_cp_runtime::audit_mirror"), "vectispire_cp_runtime.audit_mirror");
        assert_eq!(
            logger("com::asmolabs::vectispire::core::audit::internal::FileAuditMirror"),
            "c.a.v.c.audit.internal.FileAuditMirror"
        );
        assert_eq!(logger("short"), "short");
    }

    #[test]
    fn the_format_variable_is_plain_by_default_and_json_on_request() {
        assert_eq!(LogFormat::from_variable(None), Ok(LogFormat::Plain));
        assert_eq!(LogFormat::from_variable(Some(" JSON ")), Ok(LogFormat::Json));
        assert!(LogFormat::from_variable(Some("xml")).is_err());
    }
}
