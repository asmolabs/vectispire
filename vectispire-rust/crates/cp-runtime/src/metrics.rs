//! The meters, and what `/actuator/metrics` says of them — Micrometer's shape, which dashboards were
//! written against: the same names, descriptions and tags, a `name` first and the measurements as
//! `statistic`/`value` pairs.
//!
//! **Every series says which instance produced it** (`application`): without it a fleet's numbers are
//! summed into one line, and "the queue is draining" can be true of the fleet while one instance has
//! stopped claiming anything at all.
//!
//! **The JVM's own meters are not here** (`jvm.memory.used`, `jvm.gc.pause`, `process.cpu.usage`…): they
//! describe a runtime this binary does not have. The meters Vectispire defines — the queue, the outbox,
//! the agents — are the ones an operator asks about, and they are the same, on `/actuator/metrics` and on
//! `/actuator/prometheus` ([`Metrics::prometheus`]), which Java 1.0 exposes for a scraper.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::json;

type Tags = Vec<(String, String)>;

enum Kind {
    /// A value read when asked, and its base unit when it has one (`seconds` for Micrometer's `TimeGauge`).
    Gauge(Arc<dyn Fn() -> f64 + Send + Sync>, Option<&'static str>),
    Counter(Arc<AtomicU64>),
    Timer(Arc<TimerState>),
}

#[derive(Debug, Default)]
struct TimerState {
    count: AtomicU64,
    total_nanos: AtomicU64,
    max_nanos: AtomicU64,
}

struct Meter {
    name: String,
    description: Option<String>,
    tags: Tags,
    kind: Kind,
}

/// A counter, incremented by whoever holds it.
#[derive(Clone, Debug)]
pub struct Counter(Arc<AtomicU64>);

impl Counter {
    pub fn increment(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A timer: how many, how long in all, and the longest.
#[derive(Clone, Debug)]
pub struct Timer(Arc<TimerState>);

impl Timer {
    pub fn record(&self, elapsed: Duration) {
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        self.0.count.fetch_add(1, Ordering::Relaxed);
        self.0.total_nanos.fetch_add(nanos, Ordering::Relaxed);
        self.0.max_nanos.fetch_max(nanos, Ordering::Relaxed);
    }
}

/// The registry.
pub struct Metrics {
    common: Tags,
    meters: Mutex<Vec<Meter>>,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Metrics").field("common", &self.common).finish_non_exhaustive()
    }
}

impl Metrics {
    /// A registry whose every series carries `application=<name>`.
    pub fn new(application: &str) -> Metrics {
        Metrics { common: vec![("application".to_owned(), application.to_owned())], meters: Mutex::new(Vec::new()) }
    }

    fn add(&self, name: &str, description: &str, tags: &[(&str, &str)], kind: Kind) {
        let mut all = self.common.clone();
        all.extend(tags.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())));
        all.sort();
        if let Ok(mut meters) = self.meters.lock() {
            meters.push(Meter {
                name: name.to_owned(),
                description: Some(description.to_owned()).filter(|d| !d.is_empty()),
                tags: all,
                kind,
            });
        }
    }

    /// A value read when asked: the number of scans waiting, say.
    pub fn gauge(&self, name: &str, description: &str, read: impl Fn() -> f64 + Send + Sync + 'static) {
        self.add(name, description, &[], Kind::Gauge(Arc::new(read), None));
    }

    /// A gauge with its tags, and its base unit where it has one — Micrometer's `Gauge` with tags, or its `TimeGauge`
    /// (`Some("seconds")`), which `/actuator/metrics` reports with `"baseUnit":"seconds"`.
    pub fn gauge_with(
        &self,
        name: &str,
        description: &str,
        tags: &[(&str, &str)],
        base_unit: Option<&'static str>,
        read: impl Fn() -> f64 + Send + Sync + 'static,
    ) {
        self.add(name, description, tags, Kind::Gauge(Arc::new(read), base_unit));
    }

    pub fn counter(&self, name: &str, description: &str, tags: &[(&str, &str)]) -> Counter {
        let state = Arc::new(AtomicU64::new(0));
        self.add(name, description, tags, Kind::Counter(state.clone()));
        Counter(state)
    }

    pub fn timer(&self, name: &str, description: &str, tags: &[(&str, &str)]) -> Timer {
        let state = Arc::new(TimerState::default());
        self.add(name, description, tags, Kind::Timer(state.clone()));
        Timer(state)
    }

    /// `GET /actuator/metrics`: `{"names":[…]}`, sorted.
    pub fn names_document(&self) -> String {
        let meters = self
            .meters
            .lock()
            .map(|m| m.iter().map(|meter| meter.name.clone()).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut names: Vec<String> = meters;
        names.sort();
        names.dedup();
        json::object(&[("names", json::array(&names.iter().map(|name| json::string(name)).collect::<Vec<_>>()))])
    }

    /// `GET /actuator/metrics/{name}?tag=key:value…`, or `None` for a name no meter has under those tags
    /// (a 404).
    pub fn metric_document(&self, name: &str, filters: &[(String, String)]) -> Option<String> {
        let meters = self.meters.lock().ok()?;
        let matching: Vec<&Meter> = meters
            .iter()
            .filter(|meter| meter.name == name)
            .filter(|meter| filters.iter().all(|(key, value)| meter.tags.iter().any(|(k, v)| k == key && v == value)))
            .collect();
        if matching.is_empty() {
            return None;
        }

        // The statistics of every matching meter, merged: summed, except the maximum, which is the greatest.
        let mut statistics: BTreeMap<usize, (&'static str, f64)> = BTreeMap::new();
        let mut base_unit: Option<&str> = None;
        for meter in &matching {
            let measured: Vec<(usize, &'static str, f64)> = match &meter.kind {
                Kind::Gauge(read, unit) => {
                    if unit.is_some() {
                        base_unit = *unit;
                    }
                    vec![(0, "VALUE", read())]
                }
                Kind::Counter(count) => vec![(0, "COUNT", count.load(Ordering::Relaxed) as f64)],
                Kind::Timer(timer) => {
                    base_unit = Some("seconds");
                    vec![
                        (0, "COUNT", timer.count.load(Ordering::Relaxed) as f64),
                        (1, "TOTAL_TIME", timer.total_nanos.load(Ordering::Relaxed) as f64 / 1e9),
                        (2, "MAX", timer.max_nanos.load(Ordering::Relaxed) as f64 / 1e9),
                    ]
                }
            };
            for (order, statistic, value) in measured {
                let entry = statistics.entry(order).or_insert((statistic, 0.0));
                entry.1 = if statistic == "MAX" { entry.1.max(value) } else { entry.1 + value };
            }
        }

        let mut tags: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for meter in &matching {
            for (key, value) in &meter.tags {
                if filters.iter().any(|(filtered, _)| filtered == key) {
                    continue;
                }
                let values = tags.entry(key).or_default();
                if !values.contains(&value.as_str()) {
                    values.push(value);
                }
            }
        }
        let available: Vec<String> = tags
            .into_iter()
            .map(|(key, mut values)| {
                values.sort_unstable();
                json::object(&[
                    ("tag", json::string(key)),
                    ("values", json::array(&values.iter().map(|value| json::string(value)).collect::<Vec<_>>())),
                ])
            })
            .collect();

        // Keys in alphabetical order, as the Java instance writes the document.
        let mut document = vec![("availableTags", json::array(&available))];
        if let Some(unit) = base_unit {
            document.push(("baseUnit", json::string(unit)));
        }
        if let Some(description) = matching[0].description.as_deref() {
            document.push(("description", json::string(description)));
        }
        let measurements: Vec<String> = statistics
            .values()
            .map(|(statistic, value)| {
                json::object(&[("statistic", json::string(statistic)), ("value", json::double(*value))])
            })
            .collect();
        document.push(("measurements", json::array(&measurements)));
        document.push(("name", json::string(name)));
        Some(json::object(&document))
    }

    /// `GET /actuator/prometheus`: every meter in the Prometheus text format 0.0.4, as Micrometer's
    /// `PrometheusMeterRegistry` writes it through the Prometheus client — checked against the page Java 1.0 answered
    /// (`PrometheusScrapeTest`'s recording):
    ///
    /// - the name in snake case (`vectispire.scans.queued` → `vectispire_scans_queued`), with the base unit appended
    ///   where the meter has one (`_seconds` for a `TimeGauge` and a timer), and `_total` for a counter;
    /// - one family per name, `# HELP` (the description; none without one) and `# TYPE` before its series, the
    ///   families sorted by name and the series by their labels;
    /// - a timer as a `summary` (`_count` as an integer, `_sum` in seconds) beside a `_max` gauge;
    /// - the values as Java's `Double.toString` writes them (`3.0`, `2.5E11`), `NaN` for a gauge not measured yet.
    pub fn prometheus(&self) -> String {
        let Ok(meters) = self.meters.lock() else { return String::new() };
        // name → (type, written name, help, series as (labels, sample lines))
        let mut families: BTreeMap<String, Family> = BTreeMap::new();
        let mut add = |name: String, kind: &'static str, help: &Option<String>, labels: &Tags, lines: Vec<String>| {
            let family = families.entry(name.clone()).or_insert_with(|| Family {
                kind,
                written: if kind == "counter" { format!("{name}_total") } else { name },
                help: help.clone(),
                series: Vec::new(),
            });
            if family.kind == kind {
                family.series.push((labels.clone(), lines));
            }
        };
        for meter in meters.iter() {
            let base = prometheus_name(&meter.name);
            let labels = rendered_labels(&meter.tags);
            match &meter.kind {
                Kind::Gauge(read, unit) => {
                    let name = with_unit(base, *unit);
                    let line = format!("{name}{labels} {}", prometheus_double(read()));
                    add(name, "gauge", &meter.description, &meter.tags, vec![line]);
                }
                Kind::Counter(count) => {
                    let name = base.strip_suffix("_total").map(str::to_owned).unwrap_or(base);
                    let line =
                        format!("{name}_total{labels} {}", prometheus_double(count.load(Ordering::Relaxed) as f64));
                    add(name, "counter", &meter.description, &meter.tags, vec![line]);
                }
                Kind::Timer(timer) => {
                    let name = with_unit(base, Some("seconds"));
                    let count = timer.count.load(Ordering::Relaxed);
                    let sum = timer.total_nanos.load(Ordering::Relaxed) as f64 / 1e9;
                    let max = timer.max_nanos.load(Ordering::Relaxed) as f64 / 1e9;
                    add(
                        name.clone(),
                        "summary",
                        &meter.description,
                        &meter.tags,
                        vec![
                            format!("{name}_count{labels} {count}"),
                            format!("{name}_sum{labels} {}", prometheus_double(sum)),
                        ],
                    );
                    let max_name = format!("{name}_max");
                    let line = format!("{max_name}{labels} {}", prometheus_double(max));
                    add(max_name, "gauge", &meter.description, &meter.tags, vec![line]);
                }
            }
        }
        let mut page = String::new();
        // Sorted by name as `String.compareTo` sorts them: the names are ASCII once sanitised, so the map's byte order
        // is Java's UTF-16 order.
        for family in families.values() {
            if let Some(help) = &family.help {
                page.push_str(&format!("# HELP {} {}\n", family.written, escape_help(help)));
            }
            page.push_str(&format!("# TYPE {} {}\n", family.written, family.kind));
            let mut series: Vec<&(Tags, Vec<String>)> = family.series.iter().collect();
            series.sort_by(|a, b| a.0.cmp(&b.0));
            for (_, lines) in series {
                for line in lines {
                    page.push_str(line);
                    page.push('\n');
                }
            }
        }
        page
    }
}

/// The content type of `/actuator/prometheus`: the text format 0.0.4, as Java 1.0 answered it.
pub const PROMETHEUS_CONTENT_TYPE: &str = "text/plain;version=0.0.4;charset=utf-8";

struct Family {
    kind: &'static str,
    written: String,
    help: Option<String>,
    series: Vec<(Tags, Vec<String>)>,
}

/// `PrometheusNamingConvention`: snake case, then what the exposition format admits — `[a-zA-Z_:][a-zA-Z0-9_:]*`,
/// anything else an underscore.
fn prometheus_name(name: &str) -> String {
    let mut out: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == ':' { c } else { '_' }).collect();
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// The base unit appended, unless the name already ends with it: `vectispire.agents.last.seen.age` in seconds is
/// `vectispire_agents_last_seen_age_seconds`.
fn with_unit(name: String, unit: Option<&str>) -> String {
    match unit {
        Some(unit) if !name.ends_with(&format!("_{unit}")) => format!("{name}_{unit}"),
        _ => name,
    }
}

/// `{application="vectispire",kind="container"}`, the labels sorted by name (the tags already are).
fn rendered_labels(tags: &Tags) -> String {
    let labels: Vec<String> =
        tags.iter().map(|(key, value)| format!("{}=\"{}\"", prometheus_name(key), escape_label(value))).collect();
    format!("{{{}}}", labels.join(","))
}

fn escape_help(text: &str) -> String {
    text.replace('\\', "\\\\").replace('\n', "\\n")
}

fn escape_label(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// The Prometheus client's `writeDouble`: `+Inf` and `-Inf` where Java's `Double.toString` says `Infinity`; that one
/// writes `NaN` and every finite value as the client does.
fn prometheus_double(value: f64) -> String {
    if value.is_infinite() {
        if value > 0.0 { "+Inf".to_owned() } else { "-Inf".to_owned() }
    } else {
        vectispire_domain::wire::java_double_to_string(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_names_are_sorted_and_the_series_say_which_instance() {
        let metrics = Metrics::new("vectispire");
        metrics.gauge("vectispire.scans.queued", "Scans waiting for a worker or an agent to claim them", || 3.0);
        let _ = metrics.counter("vectispire.agents.polls", "Long polls answered", &[("outcome", "idle")]);
        assert_eq!(metrics.names_document(), "{\"names\":[\"vectispire.agents.polls\",\"vectispire.scans.queued\"]}");
        assert_eq!(
            metrics.metric_document("vectispire.scans.queued", &[]).unwrap(),
            "{\"availableTags\":[{\"tag\":\"application\",\"values\":[\"vectispire\"]}],\
             \"description\":\"Scans waiting for a worker or an agent to claim them\",\
             \"measurements\":[{\"statistic\":\"VALUE\",\"value\":3.0}],\"name\":\"vectispire.scans.queued\"}"
        );
    }

    #[test]
    fn a_counter_is_split_by_its_tags_and_summed_without_a_filter() {
        let metrics = Metrics::new("vectispire");
        let job = metrics.counter("vectispire.agents.polls", "Long polls answered", &[("outcome", "job")]);
        let idle = metrics.counter("vectispire.agents.polls", "Long polls answered", &[("outcome", "idle")]);
        job.increment();
        idle.increment();
        idle.increment();
        let all = metrics.metric_document("vectispire.agents.polls", &[]).unwrap();
        assert!(all.contains("\"statistic\":\"COUNT\",\"value\":3.0"), "{all}");
        assert!(all.contains("{\"tag\":\"outcome\",\"values\":[\"idle\",\"job\"]}"), "{all}");
        let only_idle =
            metrics.metric_document("vectispire.agents.polls", &[("outcome".to_owned(), "idle".to_owned())]).unwrap();
        assert!(only_idle.contains("\"value\":2.0"), "{only_idle}");
        assert!(!only_idle.contains("\"tag\":\"outcome\""), "a filtered tag is not offered again: {only_idle}");
        assert_eq!(
            metrics.metric_document("vectispire.agents.polls", &[("outcome".to_owned(), "none".to_owned())]),
            None
        );
    }

    #[test]
    fn a_timer_reports_its_count_its_time_in_seconds_and_its_maximum() {
        let metrics = Metrics::new("vectispire");
        let timer = metrics.timer("vectispire.scans.duration", "Wall-clock time from claim to result", &[]);
        timer.record(Duration::from_millis(1500));
        timer.record(Duration::from_millis(500));
        let document = metrics.metric_document("vectispire.scans.duration", &[]).unwrap();
        assert!(document.contains("\"baseUnit\":\"seconds\""), "{document}");
        assert!(
            document.contains("\"measurements\":[{\"statistic\":\"COUNT\",\"value\":2.0},{\"statistic\":\"TOTAL_TIME\",\"value\":2.0},{\"statistic\":\"MAX\",\"value\":1.5}]"),
            "{document}"
        );
    }

    #[test]
    fn timers_of_one_name_are_merged_the_count_summed_and_the_maximum_the_greatest() {
        let metrics = Metrics::new("vectispire");
        let slow = metrics.timer("vectispire.scans.duration", "d", &[("kind", "slow")]);
        let fast = metrics.timer("vectispire.scans.duration", "d", &[("kind", "fast")]);
        slow.record(Duration::from_secs(2));
        fast.record(Duration::from_secs(1));
        fast.record(Duration::from_secs(1));
        let document = metrics.metric_document("vectispire.scans.duration", &[]).unwrap();
        assert!(
            document.contains("[{\"statistic\":\"COUNT\",\"value\":3.0},{\"statistic\":\"TOTAL_TIME\",\"value\":4.0},{\"statistic\":\"MAX\",\"value\":2.0}]"),
            "{document}"
        );
    }

    /// The lines below are Java 1.0's own, from the page `PrometheusScrapeTest` recorded (values aside): the names,
    /// the unit suffixes, the help texts, the family order and the series order are the format's, not a reading of it.
    #[test]
    fn the_prometheus_page_is_written_as_micrometer_writes_it() {
        let metrics = Metrics::new("vectispire");
        // Registered out of order: the page sorts the families by name and the series by their labels.
        metrics.gauge_with(
            "vectispire.scans.queued",
            "Scans waiting for a worker or an agent to claim them, retry delays included",
            &[("kind", "repository")],
            None,
            || 3.0,
        );
        metrics.gauge_with(
            "vectispire.scans.queued",
            "Scans waiting for a worker or an agent to claim them, retry delays included",
            &[("kind", "container")],
            None,
            || 1.0,
        );
        metrics.gauge_with(
            "vectispire.agents.last.seen.age",
            "How long the least recently seen enabled agent has been silent — since its creation if it never polled; \
             zero when none is enabled",
            &[],
            Some("seconds"),
            || 52.055,
        );
        let delivered = metrics.counter(
            "vectispire.agents.claims",
            "Scans claimed for an agent, by what became of the claim",
            &[("outcome", "delivered")],
        );
        for _ in 0..56 {
            delivered.increment();
        }
        let _ = metrics.counter(
            "vectispire.agents.claims",
            "Scans claimed for an agent, by what became of the claim",
            &[("outcome", "undelivered")],
        );
        let timer = metrics.timer(
            "vectispire.scans.duration",
            "Wall-clock time from claim to result",
            &[("executor", "agent"), ("kind", "container"), ("outcome", "completed")],
        );
        timer.record(Duration::from_micros(53_557));
        metrics.gauge("vectispire.scans.running", "Scans claimed and not yet reported", || f64::NAN);

        assert_eq!(
            metrics.prometheus(),
            "# HELP vectispire_agents_claims_total Scans claimed for an agent, by what became of the claim\n\
             # TYPE vectispire_agents_claims_total counter\n\
             vectispire_agents_claims_total{application=\"vectispire\",outcome=\"delivered\"} 56.0\n\
             vectispire_agents_claims_total{application=\"vectispire\",outcome=\"undelivered\"} 0.0\n\
             # HELP vectispire_agents_last_seen_age_seconds How long the least recently seen enabled agent has been silent \
             — since its creation if it never polled; zero when none is enabled\n\
             # TYPE vectispire_agents_last_seen_age_seconds gauge\n\
             vectispire_agents_last_seen_age_seconds{application=\"vectispire\"} 52.055\n\
             # HELP vectispire_scans_duration_seconds Wall-clock time from claim to result\n\
             # TYPE vectispire_scans_duration_seconds summary\n\
             vectispire_scans_duration_seconds_count{application=\"vectispire\",executor=\"agent\",kind=\"container\",outcome=\"completed\"} 1\n\
             vectispire_scans_duration_seconds_sum{application=\"vectispire\",executor=\"agent\",kind=\"container\",outcome=\"completed\"} 0.053557\n\
             # HELP vectispire_scans_duration_seconds_max Wall-clock time from claim to result\n\
             # TYPE vectispire_scans_duration_seconds_max gauge\n\
             vectispire_scans_duration_seconds_max{application=\"vectispire\",executor=\"agent\",kind=\"container\",outcome=\"completed\"} 0.053557\n\
             # HELP vectispire_scans_queued Scans waiting for a worker or an agent to claim them, retry delays included\n\
             # TYPE vectispire_scans_queued gauge\n\
             vectispire_scans_queued{application=\"vectispire\",kind=\"container\"} 1.0\n\
             vectispire_scans_queued{application=\"vectispire\",kind=\"repository\"} 3.0\n\
             # HELP vectispire_scans_running Scans claimed and not yet reported\n\
             # TYPE vectispire_scans_running gauge\n\
             vectispire_scans_running{application=\"vectispire\"} NaN\n"
        );
    }

    #[test]
    fn a_meter_without_a_description_has_no_help_line_and_labels_are_escaped() {
        let metrics = Metrics::new("vec\"tis\\pire");
        metrics.gauge("a.b", "", || 1.5E11);
        metrics.gauge("a.c", "", || f64::NEG_INFINITY);
        assert_eq!(
            metrics.prometheus(),
            "# TYPE a_b gauge\na_b{application=\"vec\\\"tis\\\\pire\"} 1.5E11\n\
             # TYPE a_c gauge\na_c{application=\"vec\\\"tis\\\\pire\"} -Inf\n"
        );
    }

    #[test]
    fn an_unknown_name_has_no_document() {
        assert_eq!(Metrics::new("v").metric_document("nope", &[]), None);
    }
}
