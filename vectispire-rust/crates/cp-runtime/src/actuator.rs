//! What `/actuator/**` answers, and to whom — as a document and a status, for the HTTP stack to serve.
//!
//! **No framework here**: the answers are produced from the health state and the meters, and the stack
//! (`cp-http`) mounts them and enforces [`Access`]. Exposure is the Java configuration's —
//! `management.endpoints.web.exposure.include: health,info,metrics`, with the probes on — and so is who
//! may read what: `health` and its probe groups stay **anonymous** because a container probe has no
//! session; everything else needs an **administrator's session**, not an agent or integration key and
//! not a session that still owes a password change. A metrics endpoint names internal structure and
//! volumes, which is not something to publish to whoever can reach the port.

use std::sync::{Arc, Mutex};

use crate::json;
use crate::metrics::Metrics;

/// The content type Spring Boot gives actuator documents.
pub const CONTENT_TYPE: &str = "application/vnd.spring-boot.actuator.v3+json";

/// Who may read an actuator path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Anyone: `/actuator/health` and below.
    Anonymous,
    /// A session of an administrative role that owes no password change.
    AdministratorSession,
}

/// `GET /actuator/**` is served under this prefix.
pub const PREFIX: &str = "/actuator";

/// Who may read `path`: `permitAll()` for `/actuator/health/**` and the health document itself, an
/// administrator's session for the rest of `/actuator/**`.
pub fn access(path: &str) -> Access {
    if path == "/actuator/health" || path.starts_with("/actuator/health/") {
        Access::Anonymous
    } else {
        Access::AdministratorSession
    }
}

/// A health status, ordered the way Spring aggregates them: the worst wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Down,
    OutOfService,
    Up,
    Unknown,
}

impl Status {
    pub fn code(self) -> &'static str {
        match self {
            Status::Down => "DOWN",
            Status::OutOfService => "OUT_OF_SERVICE",
            Status::Up => "UP",
            Status::Unknown => "UNKNOWN",
        }
    }

    /// 503 for a service that is down or out of service, 200 for the rest.
    pub fn http_status(self) -> u16 {
        match self {
            Status::Down | Status::OutOfService => 503,
            Status::Up | Status::Unknown => 200,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Status::Down => 0,
            Status::OutOfService => 1,
            Status::Up => 2,
            Status::Unknown => 3,
        }
    }
}

/// An indicator the overall status depends on, asked at each request.
type Indicator = Arc<dyn Fn() -> Status + Send + Sync>;

/// The two availability states a container platform probes: alive, and ready for traffic.
pub struct Health {
    live: Mutex<Status>,
    ready: Mutex<Status>,
    contributors: Mutex<Vec<(String, Indicator)>>,
}

impl Default for Health {
    fn default() -> Self {
        Health { live: Mutex::new(Status::Up), ready: Mutex::new(Status::Up), contributors: Mutex::new(Vec::new()) }
    }
}

impl std::fmt::Debug for Health {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Health")
            .field("liveness", &self.liveness())
            .field("readiness", &self.readiness())
            .finish_non_exhaustive()
    }
}

impl Health {
    /// An indicator the overall status also depends on — the database, say. It is asked at each request.
    pub fn contribute(&self, name: &str, indicator: impl Fn() -> Status + Send + Sync + 'static) {
        if let Ok(mut contributors) = self.contributors.lock() {
            contributors.push((name.to_owned(), Arc::new(indicator)));
        }
    }

    /// Readiness goes `OUT_OF_SERVICE` when shutdown starts, so a load balancer stops sending before the
    /// requests in flight are done.
    pub fn refuse_traffic(&self) {
        if let Ok(mut ready) = self.ready.lock() {
            *ready = Status::OutOfService;
        }
    }

    /// Liveness goes `DOWN` when the process cannot recover by itself, and a platform restarts it.
    pub fn break_liveness(&self) {
        if let Ok(mut live) = self.live.lock() {
            *live = Status::Down;
        }
    }

    fn liveness(&self) -> Status {
        self.live.lock().map(|status| *status).unwrap_or(Status::Down)
    }

    fn readiness(&self) -> Status {
        self.ready.lock().map(|status| *status).unwrap_or(Status::Down)
    }

    fn overall(&self) -> Status {
        let mut worst = Status::Up;
        let mut consider = |status: Status| {
            if status.rank() < worst.rank() {
                worst = status;
            }
        };
        consider(self.liveness());
        consider(self.readiness());
        if let Ok(contributors) = self.contributors.lock() {
            for (_, indicator) in contributors.iter() {
                consider(indicator());
            }
        }
        worst
    }
}

/// What the stack serves: a status, a content type (none for an empty answer), and the document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub content_type: Option<&'static str>,
    pub body: String,
}

impl Answer {
    fn ok(body: String) -> Answer {
        Answer { status: 200, content_type: Some(CONTENT_TYPE), body }
    }

    /// What Spring answers for an endpoint it exposes and has nothing under: a bare 404 with no body. A path
    /// that is not exposed at all is not this — it is the stack's own "nothing is served here".
    fn nothing_here() -> Answer {
        Answer { status: 404, content_type: None, body: String::new() }
    }
}

/// The build the instance runs, for `/actuator/info` — what `build-info` gives the Java one.
#[derive(Clone, Debug)]
pub struct BuildInfo {
    pub group: String,
    pub artifact: String,
    pub name: String,
    pub version: String,
    /// ISO-8601 instant of the build, when known.
    pub time: Option<String>,
}

/// The actuator.
#[derive(Debug)]
pub struct Actuator {
    pub health: Arc<Health>,
    pub metrics: Arc<Metrics>,
    pub build: BuildInfo,
}

impl Actuator {
    /// The answer for `path` (`/actuator`, `/actuator/health`, `/actuator/health/liveness`,
    /// `/actuator/info`, `/actuator/metrics`, `/actuator/metrics/{name}`) and its query string, or `None`
    /// for a path that is not exposed — which the stack answers as it answers any path with nothing under it.
    /// An exposed endpoint with nothing at that name (a health group, a meter) is a bare 404 from here.
    /// `base_url` is where the instance is reached, for the links.
    pub fn answer(&self, path: &str, query: &str, base_url: &str) -> Option<Answer> {
        let rest = path.strip_prefix(PREFIX)?;
        match rest.trim_end_matches('/') {
            "" => Some(Answer::ok(self.links(base_url))),
            "/health" => {
                let overall = self.health.overall();
                // `groups` first: the answer is written with its keys in alphabetical order, as every
                // actuator document but the index's links is.
                let body = json::object(&[
                    ("groups", json::array(&[json::string("liveness"), json::string("readiness")])),
                    ("status", json::string(overall.code())),
                ]);
                Some(Answer { status: overall.http_status(), content_type: Some(CONTENT_TYPE), body })
            }
            "/health/liveness" => Some(self.group(self.health.liveness())),
            "/health/readiness" => Some(self.group(self.health.readiness())),
            "/info" => Some(Answer::ok(self.info())),
            "/metrics" => Some(Answer::ok(self.metrics.names_document())),
            other if other.starts_with("/health/") => Some(Answer::nothing_here()),
            other => {
                let name = other.strip_prefix("/metrics/")?;
                let filters: Vec<(String, String)> = query
                    .split('&')
                    .filter_map(|pair| pair.strip_prefix("tag="))
                    .filter_map(|tag| tag.split_once(':'))
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
                    .collect();
                Some(self.metrics.metric_document(name, &filters).map_or_else(Answer::nothing_here, Answer::ok))
            }
        }
    }

    fn group(&self, status: Status) -> Answer {
        Answer {
            status: status.http_status(),
            content_type: Some(CONTENT_TYPE),
            body: json::object(&[("status", json::string(status.code()))]),
        }
    }

    /// `build` as the Java instance answers it: `artifact`, `name`, `version`, then `group` — the order its
    /// `build-info` yields them in, which is not alphabetical. A build with no time says none: the Java
    /// builds are reproducible and carry none.
    fn info(&self) -> String {
        let mut build = vec![
            ("artifact", json::string(&self.build.artifact)),
            ("name", json::string(&self.build.name)),
            ("version", json::string(&self.build.version)),
        ];
        if let Some(time) = &self.build.time {
            build.push(("time", json::string(time)));
        }
        build.push(("group", json::string(&self.build.group)));
        json::object(&[("build", json::object(&build))])
    }

    fn links(&self, base: &str) -> String {
        let base = base.trim_end_matches('/');
        let link = |href: String, templated: bool| {
            json::object(&[("href", json::string(&href)), ("templated", templated.to_string())])
        };
        json::object(&[(
            "_links",
            json::object(&[
                ("self", link(format!("{base}/actuator"), false)),
                ("info", link(format!("{base}/actuator/info"), false)),
                ("health-path", link(format!("{base}/actuator/health/{{*path}}"), true)),
                ("health", link(format!("{base}/actuator/health"), false)),
                ("metrics", link(format!("{base}/actuator/metrics"), false)),
                ("metrics-requiredMetricName", link(format!("{base}/actuator/metrics/{{requiredMetricName}}"), true)),
            ]),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actuator() -> Actuator {
        let metrics = Arc::new(Metrics::new("vectispire"));
        metrics.gauge("vectispire.scans.queued", "Scans waiting", || 2.0);
        Actuator {
            health: Arc::new(Health::default()),
            metrics,
            build: BuildInfo {
                group: "com.asmolabs.vectispire".to_owned(),
                artifact: "vectispire-core".to_owned(),
                name: "vectispire-core".to_owned(),
                version: "0.12.0-dev".to_owned(),
                time: Some("2026-10-16T21:00:00.000Z".to_owned()),
            },
        }
    }

    #[test]
    fn health_and_its_probes_are_anonymous_and_the_rest_needs_an_administrator() {
        for path in
            ["/actuator/health", "/actuator/health/liveness", "/actuator/health/readiness", "/actuator/health/x/y"]
        {
            assert_eq!(access(path), Access::Anonymous, "{path}");
        }
        for path in [
            "/actuator",
            "/actuator/info",
            "/actuator/metrics",
            "/actuator/metrics/x",
            "/actuator/healthz",
            "/actuator/prometheus",
            "/actuator/env",
        ] {
            assert_eq!(access(path), Access::AdministratorSession, "{path}");
        }
    }

    #[test]
    fn health_says_up_and_names_its_probe_groups() {
        let answer = actuator().answer("/actuator/health", "", "http://h").unwrap();
        assert_eq!(
            (answer.status, answer.body.as_str()),
            (200, "{\"groups\":[\"liveness\",\"readiness\"],\"status\":\"UP\"}")
        );
        assert_eq!(actuator().answer("/actuator/health/liveness", "", "http://h").unwrap().body, "{\"status\":\"UP\"}");
        assert_eq!(
            actuator().answer("/actuator/health/readiness/", "", "http://h").unwrap().body,
            "{\"status\":\"UP\"}"
        );
    }

    #[test]
    fn refusing_traffic_takes_readiness_and_the_whole_out_of_service_and_not_liveness() {
        let actuator = actuator();
        actuator.health.refuse_traffic();
        let ready = actuator.answer("/actuator/health/readiness", "", "http://h").unwrap();
        assert_eq!((ready.status, ready.body.as_str()), (503, "{\"status\":\"OUT_OF_SERVICE\"}"));
        assert_eq!(actuator.answer("/actuator/health/liveness", "", "http://h").unwrap().status, 200);
        let overall = actuator.answer("/actuator/health", "", "http://h").unwrap();
        assert_eq!(
            (overall.status, overall.body.as_str()),
            (503, "{\"groups\":[\"liveness\",\"readiness\"],\"status\":\"OUT_OF_SERVICE\"}")
        );
    }

    #[test]
    fn a_contributor_that_is_down_takes_the_overall_status_down_and_not_the_probes() {
        let actuator = actuator();
        actuator.health.contribute("db", || Status::Down);
        assert_eq!(actuator.answer("/actuator/health", "", "http://h").unwrap().status, 503);
        assert_eq!(actuator.answer("/actuator/health/liveness", "", "http://h").unwrap().status, 200);
    }

    #[test]
    fn info_names_the_build_and_metrics_are_listed_and_read() {
        let actuator = actuator();
        assert_eq!(
            actuator.answer("/actuator/info", "", "http://h").unwrap().body,
            "{\"build\":{\"artifact\":\"vectispire-core\",\"name\":\"vectispire-core\",\"version\":\"0.12.0-dev\",\"time\":\"2026-10-16T21:00:00.000Z\",\"group\":\"com.asmolabs.vectispire\"}}"
        );
        assert_eq!(
            actuator.answer("/actuator/metrics", "", "http://h").unwrap().body,
            "{\"names\":[\"vectispire.scans.queued\"]}"
        );
        assert!(
            actuator
                .answer("/actuator/metrics/vectispire.scans.queued", "", "http://h")
                .unwrap()
                .body
                .contains("\"value\":2.0")
        );
        let absent = actuator.answer("/actuator/metrics/nope", "", "http://h").unwrap();
        assert_eq!(
            (absent.status, absent.content_type, absent.body.as_str()),
            (404, None, ""),
            "exposed, and nothing at that name"
        );
        let group = actuator.answer("/actuator/health/nope", "", "http://h").unwrap();
        assert_eq!((group.status, group.content_type, group.body.as_str()), (404, None, ""));
        assert_eq!(actuator.answer("/actuator/env", "", "http://h"), None, "what is not exposed is not there");
        assert_eq!(actuator.answer("/actuator/prometheus", "", "http://h"), None);
    }

    #[test]
    fn the_index_links_what_is_exposed() {
        let body = actuator().answer("/actuator", "", "http://h:3180/").unwrap().body;
        assert!(body.contains("\"self\":{\"href\":\"http://h:3180/actuator\",\"templated\":false}"), "{body}");
        assert!(body.contains("\"metrics-requiredMetricName\":{\"href\":\"http://h:3180/actuator/metrics/{requiredMetricName}\",\"templated\":true}"), "{body}");
        assert!(!body.contains("prometheus"), "{body}");
    }
}
