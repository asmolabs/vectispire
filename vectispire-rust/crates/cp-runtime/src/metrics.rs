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
//! the agents — are the ones an operator asks about, and they are the same. `prometheus` was never
//! exposed (`management.endpoints.web.exposure.include: health,info,metrics`), so it is not offered.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::json;

type Tags = Vec<(String, String)>;

enum Kind {
    Gauge(Arc<dyn Fn() -> f64 + Send + Sync>),
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
        self.add(name, description, &[], Kind::Gauge(Arc::new(read)));
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
                Kind::Gauge(read) => vec![(0, "VALUE", read())],
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

    #[test]
    fn an_unknown_name_has_no_document() {
        assert_eq!(Metrics::new("v").metric_document("nope", &[]), None);
    }
}
